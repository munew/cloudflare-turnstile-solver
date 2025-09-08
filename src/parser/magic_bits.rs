use oxc_allocator::Vec as Vec2;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, Expression,
    Function, Statement,
};
use oxc_ast_visit::{
    walk::{
        walk_assignment_expression, walk_expression, walk_function,
        walk_statement, walk_statements,
    },
    Visit,
};
use oxc_semantic::ScopeFlags;
use rustc_hash::FxHashMap;

use strum::{EnumIter, IntoEnumIterator, ToString};

use super::utils::{AssigmentExtractor, BinaryBitExtractor, BitExtractor, TestExtractor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultOpcode {
    pub bits: Vec<u16>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct WithTestOpcode {
    pub test_bits: Vec<u16>,
    pub bits: Vec<u16>,
}

#[derive(Debug, EnumIter, Clone, PartialEq, Eq)]
pub enum LiteralType {
    Null,
    NaN,
    Infinity,
    True,
    False,
    Float,
    Integer,
    String,
    NextValue,
    CopyState,
    Array,
    Regexp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLiteralTest {
    pub bits: Vec<u16>,
    pub type_: LiteralType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLiteralOpcode {
    pub bits: Vec<u16>,
    pub tests: FxHashMap<u16, NewLiteralTest>,
}

#[derive(Debug, EnumIter, Clone, Hash, PartialEq, Eq)]
pub enum UnaryOperator {
    TypeOf,
    Minus,
    Plus,
    LogicalNot,
    BitwiseNot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnaryOpcode {
    pub bits: Vec<u16>,
    pub operator: UnaryOperator,
}

impl UnaryOperator {
    pub fn get_operator(&self) -> &'static str {
        match self {
            UnaryOperator::BitwiseNot => "~",
            UnaryOperator::LogicalNot => "!",
            UnaryOperator::Minus => "-",
            UnaryOperator::Plus => "+",
            UnaryOperator::TypeOf => "typeof",
        }
    }
}

#[derive(Debug, EnumIter, Clone, Hash, PartialEq, Eq)]
pub enum BinaryOperator {
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Modulo,
    LogicalAnd,
    LogicalOr,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
    UnsignedRightShift,
    Equals,
    EqualsStrict,
    GreaterThan,
    GreaterThanOrEqual,
    InstanceOf,
}

impl BinaryOperator {
    pub fn get_operator(&self) -> &'static str {
        match self {
            BinaryOperator::Addition => "+",
            BinaryOperator::Subtraction => "-",
            BinaryOperator::Multiplication => "*",
            BinaryOperator::Division => "/",
            BinaryOperator::Modulo => "%",
            BinaryOperator::LogicalAnd => "&&",
            BinaryOperator::LogicalOr => "||",
            BinaryOperator::BitwiseAnd => "&",
            BinaryOperator::BitwiseOr => "|",
            BinaryOperator::BitwiseXor => "^",
            BinaryOperator::LeftShift => "<<",
            BinaryOperator::RightShift => ">>",
            BinaryOperator::UnsignedRightShift => ">>>",
            BinaryOperator::Equals => "==",
            BinaryOperator::EqualsStrict => "===",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
            BinaryOperator::InstanceOf => "instanceof",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryOpcode {
    pub bits: Vec<u16>,
    pub operator: BinaryOperator,
    pub swap: bool,
}

#[derive(Debug, EnumIter, Clone, PartialEq, Eq)]
pub enum HeapType {
    Set,
    Get,
    Init,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureTest {
    pub bits: Vec<u16>,
    pub closure_type: HeapType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureOpcode {
    pub bits: Vec<u16>,
    pub closures: FxHashMap<u16, ClosureTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToString)]
pub enum Opcode {
    ArrayPush(DefaultOpcode),
    Throw(DefaultOpcode),
    Bind(DefaultOpcode),
    RegisterVMFunction(DefaultOpcode),
    Binary(BinaryOpcode),
    Unary(UnaryOpcode),
    NewLiteral(NewLiteralOpcode),
    NewObject(DefaultOpcode),
    Pop(DefaultOpcode),
    SetProperty(DefaultOpcode),
    GetProperty(DefaultOpcode),
    SplicePop(DefaultOpcode),
    CallFuncNoContext(DefaultOpcode),
    SwapRegister(DefaultOpcode),
    NewArray(DefaultOpcode),
    Jump(DefaultOpcode),
    JumpIf(DefaultOpcode),
    Move(DefaultOpcode),
    Call(DefaultOpcode),
    Heap(ClosureOpcode),
}

pub struct OpcodeParser<'a> {
    constants: u16,
    functions: FxHashMap<&'a str, u16>,

    pub opcodes: FxHashMap<u16, Opcode>,
    pub create_function_ident: &'a str,
    pub window_register: u16,
}

impl<'a> OpcodeParser<'a> {
    pub fn new(constants: u16, functions: FxHashMap<&'a str, u16>) -> Self {
        OpcodeParser {
            constants,
            functions,
            opcodes: FxHashMap::default(),
            create_function_ident: "",
            window_register: 0,
        }
    }

    fn extract_bits_for_default_opcode(&self, statements: &Vec2<Statement<'a>>) -> DefaultOpcode {
        let mut bit_extractor = BitExtractor::new(self.constants);
        walk_statements(&mut bit_extractor, statements);
        DefaultOpcode {
            bits: bit_extractor.bits,
        }
    }

    fn handle_unary_opcodes(
        &mut self,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
    ) {
        for operator in UnaryOperator::iter() {
            let test = tests_visitor.tests.remove(0);
            let bits = bits_extractor.bits.drain(0..2).as_slice().to_vec();
            self.opcodes
                .insert(test, Opcode::Unary(UnaryOpcode { bits, operator }));
        }
    }

    fn handle_literal_opcodes(
        &mut self,
        opcode_register: u16,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
    ) {
        let bits = bits_extractor.bits.drain(0..2).as_slice().to_vec();
        let mut tests = FxHashMap::default();

        for type_ in LiteralType::iter() {
            let test = tests_visitor.tests.remove(0);
            let bits = match type_ {
                LiteralType::Integer
                | LiteralType::String
                | LiteralType::CopyState
                | LiteralType::Array => {
                    vec![bits_extractor.bits.remove(0)]
                }
                LiteralType::Regexp => bits_extractor.bits.clone(),
                _ => vec![],
            };

            tests.insert(test, NewLiteralTest { bits, type_ });
        }

        self.opcodes.insert(
            opcode_register,
            Opcode::NewLiteral(NewLiteralOpcode { bits, tests }),
        );
    }

    fn handle_binary_opcodes(
        &mut self,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BinaryBitExtractor,
    ) {
        for operator in BinaryOperator::iter() {
            let test = tests_visitor.tests.remove(0);
            let bits = bits_extractor.bits.drain(0..3).as_slice().to_vec();

            self.opcodes.insert(
                test,
                Opcode::Binary(BinaryOpcode {
                    bits,
                    operator,
                    swap: bits_extractor.swaps.remove(0),
                }),
            );
        }
    }

    fn handle_heap_opcodes(
        &mut self,
        opcode_register: u16,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
    ) {
        let bits = bits_extractor.bits.remove(0);
        let mut closures = FxHashMap::default();

        for closure in HeapType::iter() {
            let test = tests_visitor.tests.remove(0);
            let closure_bits = match closure {
                HeapType::Init => vec![],
                _ => vec![bits_extractor.bits.remove(0)],
            };

            closures.insert(
                test,
                ClosureTest {
                    bits: closure_bits,
                    closure_type: closure,
                },
            );
        }

        self.opcodes.insert(
            opcode_register,
            Opcode::Heap(ClosureOpcode {
                bits: vec![bits],
                closures,
            }),
        );
    }

    fn process_by_test_count(
        &mut self,
        opcode_register: u16,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
        binary_bits_extractor: &mut BinaryBitExtractor,
    ) {
        match tests_visitor.tests.len() {
            5 => self.handle_unary_opcodes(tests_visitor, bits_extractor),
            12 => self.handle_literal_opcodes(opcode_register, tests_visitor, bits_extractor),
            18 => self.handle_binary_opcodes(tests_visitor, binary_bits_extractor),
            _ => {
                if !tests_visitor.tests.is_empty()
                    && tests_visitor.tests.len() == HeapType::iter().count()
                {
                    self.handle_heap_opcodes(opcode_register, tests_visitor, bits_extractor);
                } else {
                    panic!("Invalid opcode: {}", opcode_register);
                }
            }
        }
    }
}

impl<'a> Visit<'a> for OpcodeParser<'a> {
    fn visit_assignment_expression(&mut self, assign_expr: &AssignmentExpression<'a>) {
        if let (
            AssignmentTarget::AssignmentTargetIdentifier(ident),
            Expression::CallExpression(_),
        ) = (&assign_expr.left, &assign_expr.right)
        {
            if let Some(opcode_register) = self.functions.remove(ident.name.as_str()) {
                self.window_register = opcode_register;
            }
        }

        walk_assignment_expression(self, assign_expr);
    }

    fn visit_function(&mut self, node: &Function<'a>, flags: ScopeFlags) {
        let (name, body) = match (&node.id, &node.body) {
            (Some(ident), Some(body)) => (ident.name.as_str(), body),
            _ => {
                walk_function(self, node, flags);
                return;
            }
        };

        if body.statements.is_empty() {
            walk_function(self, node, flags);
            return;
        }

        if let Statement::ReturnStatement(stmt) = &body.statements.last().unwrap() {
            if let Some(Expression::ComputedMemberExpression(member_expr)) = &stmt.argument {
                if let Statement::ExpressionStatement(expr) =
                    &body.statements[body.statements.len() - 2]
                {
                    if matches!(member_expr.object, Expression::StaticMemberExpression(_))
                        && matches!(member_expr.expression, Expression::BinaryExpression(_))
                        && matches!(expr.expression, Expression::AssignmentExpression(_))
                    {
                        self.create_function_ident = name;
                    }
                }
            }
        }

        if let Some(opcode_register) = self.functions.remove(name) {
            if body.statements.len() >= 2 {
                match &body.statements[body.statements.len() - 2] {
                    Statement::ExpressionStatement(expr) => {
                        if let Expression::ConditionalExpression(_) = &expr.expression {
                            let mut assigments_visitor = AssigmentExtractor::new();
                            assigments_visitor.visit_function_body(node.body.as_ref().unwrap());

                            let mut tests_visitor = TestExtractor::default();
                            walk_expression(&mut tests_visitor, &expr.expression);

                            let mut bits_extractor = BitExtractor::new(self.constants);
                            walk_expression(&mut bits_extractor, &expr.expression);

                            let mut binary_bits_extractor = BinaryBitExtractor::new(
                                self.constants,
                                assigments_visitor.identifiers,
                            );
                            walk_expression(&mut binary_bits_extractor, &expr.expression);

                            self.process_by_test_count(
                                opcode_register,
                                &mut tests_visitor,
                                &mut bits_extractor,
                                &mut binary_bits_extractor,
                            );
                        } else if let Expression::AssignmentExpression(assign_expr) =
                            &expr.expression
                        {
                            if let (
                                AssignmentTarget::ComputedMemberExpression(_),
                                Expression::ComputedMemberExpression(_),
                            ) = (&assign_expr.left, &assign_expr.right)
                            {
                                let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                self.opcodes
                                    .insert(opcode_register, Opcode::SwapRegister(opcode));
                            }
                        }
                    }
                    Statement::IfStatement(_) => {
                        let mut assigments_visitor = AssigmentExtractor::new();
                        assigments_visitor.visit_function_body(node.body.as_ref().unwrap());

                        let mut tests_visitor = TestExtractor::default();
                        walk_statement(
                            &mut tests_visitor,
                            &body.statements[body.statements.len() - 2],
                        );

                        let mut bits_extractor = BitExtractor::new(self.constants);
                        walk_statements(&mut bits_extractor, &body.statements);

                        let mut binary_bits_extractor =
                            BinaryBitExtractor::new(self.constants, assigments_visitor.identifiers);
                        walk_statements(&mut binary_bits_extractor, &body.statements);

                        self.process_by_test_count(
                            opcode_register,
                            &mut tests_visitor,
                            &mut bits_extractor,
                            &mut binary_bits_extractor,
                        );
                    }
                    _ => {}
                }
            }

            match body.statements.last().unwrap() {
                Statement::ExpressionStatement(expr) => match &expr.expression {
                    Expression::AssignmentExpression(assign_expr) => match &assign_expr.left {
                        AssignmentTarget::ComputedMemberExpression(member_expr) => {
                            match &assign_expr.right {
                                Expression::CallExpression(call_expr) => {
                                    if let Expression::ComputedMemberExpression(computed_expr) =
                                        &call_expr.callee
                                    {
                                        if let (
                                            Expression::Identifier(ident),
                                            Expression::StringLiteral(str_lit),
                                        ) = (&computed_expr.object, &computed_expr.expression)
                                        {
                                            let opcode = self
                                                .extract_bits_for_default_opcode(&body.statements);

                                            match str_lit.value.as_str() {
                                                "bind" => {
                                                    match ident.name.len() {
                                                        1 => self.opcodes.insert(
                                                            opcode_register,
                                                            Opcode::Bind(opcode),
                                                        ),
                                                        2 => self.opcodes.insert(
                                                            opcode_register,
                                                            Opcode::RegisterVMFunction(opcode),
                                                        ),
                                                        _ => None,
                                                    };
                                                }
                                                "pop" => {
                                                    self.opcodes.insert(
                                                        opcode_register,
                                                        Opcode::Pop(opcode),
                                                    );
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                Expression::ObjectExpression(_) => {
                                    let opcode =
                                        self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes
                                        .insert(opcode_register, Opcode::NewObject(opcode));
                                }
                                Expression::ComputedMemberExpression(member_expr) => {
                                    let opcode =
                                        self.extract_bits_for_default_opcode(&body.statements);

                                    match member_expr.object {
                                        Expression::Identifier(_) => {
                                            self.opcodes.insert(
                                                opcode_register,
                                                Opcode::GetProperty(opcode),
                                            );
                                        }
                                        Expression::StaticMemberExpression(_) => {
                                            self.opcodes.insert(
                                                opcode_register,
                                                Opcode::SetProperty(opcode),
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                Expression::NewExpression(_) => {
                                    let opcode =
                                        self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes
                                        .insert(opcode_register, Opcode::CallFuncNoContext(opcode));
                                }
                                Expression::ArrayExpression(_) => {
                                    let opcode =
                                        self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes
                                        .insert(opcode_register, Opcode::NewArray(opcode));
                                }
                                Expression::Identifier(_) => {
                                    if let Expression::NumericLiteral(_) = &member_expr.expression {
                                        let opcode =
                                            self.extract_bits_for_default_opcode(&body.statements);
                                        self.opcodes.insert(opcode_register, Opcode::Jump(opcode));
                                    } else {
                                        if let Statement::ExpressionStatement(expr_stmt) =
                                            &body.statements[body.statements.len() - 2]
                                        {
                                            if let Expression::AssignmentExpression(assign_expr) =
                                                &expr_stmt.expression
                                            {
                                                if let AssignmentTarget::AssignmentTargetIdentifier(_) = &assign_expr.left {
                                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                                    self.opcodes.insert(opcode_register, Opcode::Move(opcode));
                                                }
                                            }
                                        }
                                    }
                                }
                                Expression::ConditionalExpression(_) => {
                                    let opcode =
                                        self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes.insert(opcode_register, Opcode::Call(opcode));
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    },
                    Expression::CallExpression(call_expr) => {
                        if !call_expr.arguments[0].is_member_expression() {
                            let opcode = self.extract_bits_for_default_opcode(&body.statements);
                            self.opcodes
                                .insert(opcode_register, Opcode::SplicePop(opcode));
                        }

                        if let Expression::ComputedMemberExpression(computed_expr) =
                            &call_expr.callee
                        {
                            if let Expression::StringLiteral(str_lit) = &computed_expr.expression {
                                if str_lit.value == "push" {
                                    let opcode =
                                        self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes
                                        .insert(opcode_register, Opcode::ArrayPush(opcode));
                                }
                            }
                        }
                    }
                    Expression::LogicalExpression(_) => {
                        let opcode = self.extract_bits_for_default_opcode(&body.statements);
                        self.opcodes.insert(opcode_register, Opcode::JumpIf(opcode));
                    }
                    _ => {}
                },
                Statement::IfStatement(_) => {
                    let mut assigments_visitor = AssigmentExtractor::new();
                    assigments_visitor.visit_function_body(node.body.as_ref().unwrap());

                    let mut bits_extractor = BitExtractor::new(self.constants);
                    walk_statements(&mut bits_extractor, &body.statements);

                    let mut tests_visitor = TestExtractor::default();
                    walk_statements(&mut tests_visitor, &body.statements);

                    let mut binary_bits_extractor =
                        BinaryBitExtractor::new(self.constants, assigments_visitor.identifiers);
                    walk_statements(&mut binary_bits_extractor, &body.statements);

                    self.process_by_test_count(
                        opcode_register,
                        &mut tests_visitor,
                        &mut bits_extractor,
                        &mut binary_bits_extractor,
                    );
                }
                Statement::ThrowStatement(_) => {
                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                    self.opcodes.insert(opcode_register, Opcode::Throw(opcode));
                }
                _ => {}
            }
        }

        walk_function(self, node, flags);
    }
}
