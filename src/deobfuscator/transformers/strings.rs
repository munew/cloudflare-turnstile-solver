use oxc_allocator::Allocator;
use oxc_ast::{ast::*, AstBuilder};
use oxc_ast_visit::walk_mut::{
    walk_call_expression, walk_computed_member_expression, walk_expression,
    walk_function_body, walk_program, walk_return_statement,
    walk_string_literal,
};
use oxc_ast_visit::VisitMut;
use oxc_span::SPAN;

struct StringVisitor<'a> {
    ast: AstBuilder<'a>,
    string: Vec<&'a str>,

    main_script: bool,
}

impl<'a> StringVisitor<'a> {
    pub fn new(allocator: &'a Allocator, main_script: bool) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            string: Vec::new(),
            main_script,
        }
    }
}

impl<'a> VisitMut<'a> for StringVisitor<'a> {
    fn visit_string_literal(&mut self, node: &mut StringLiteral<'a>) {
        if node.value.as_str().len() > 500 && self.main_script {
            self.string = node.value.as_str().split("~").collect();

            *node = StringLiteral {
                value: self.ast.atom(""),
                raw: None,
                span: node.span,
                lone_surrogates: false,
            };

            return;
        }

        walk_string_literal(self, node);
    }

    fn visit_call_expression(&mut self, call_expr: &mut CallExpression<'a>) {
        if !self.main_script
            && let Expression::StaticMemberExpression(member) = &call_expr.callee
            && let Expression::StringLiteral(lit) = &member.object
            && member.property.name == "split"
            && let Some(Argument::StringLiteral(lit_2)) = &call_expr.arguments.first()
        {
            self.string = lit.value.as_str().split(lit_2.value.as_str()).collect();

            return;
        }

        walk_call_expression(self, call_expr);
    }
}

#[derive(Debug, Default)]
struct Decoder<'a> {
    string: Vec<&'a str>,
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub fn decode_string(&self, index: usize) -> Option<String> {
        if index < self.offset {
            return None;
        }

        let adjusted_index = index - self.offset;
        if self.string.len() <= adjusted_index {
            return None;
        }

        Some(self.string[adjusted_index].to_string())
    }
}

#[derive(Default)]
struct DecoderVisitor<'a> {
    sub: usize,
    main_script: bool,

    pub decoder: Decoder<'a>,
}

impl<'a> DecoderVisitor<'a> {
    pub fn new(string: Vec<&'a str>, main_script: bool) -> Self {
        Self {
            sub: 0,
            main_script,
            decoder: Decoder { string, offset: 0 },
        }
    }

    fn extract_decoder(&mut self, assign_expr: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(ident) = &assign_expr.left
            && let Expression::BinaryExpression(bin) = &assign_expr.right
            && let (
            BinaryOperator::Subtraction,
            Expression::Identifier(ident_2),
            Expression::NumericLiteral(lit),
        ) = (&bin.operator, &bin.left, &bin.right)
            && ident.name == ident_2.name
        {
            self.decoder.offset = lit.value as usize;
            loop {
                self.decoder.string.rotate_left(1);
                let string = self.decoder.string[self.sub - self.decoder.offset];
                if string == "stringify" || (!self.main_script && string == "Ninjas > pirates") {
                    break;
                }
            }
        }
    }
}

impl<'a> VisitMut<'a> for DecoderVisitor<'a> {
    fn visit_computed_member_expression(&mut self, node: &mut ComputedMemberExpression<'a>) {
        if let (Expression::Identifier(ident), Expression::CallExpression(call_expr)) =
            (&node.object, &node.expression)
            && matches!(call_expr.callee, Expression::Identifier(_))
            && ident.name.as_str() == "JSON"
            && let Some(Argument::NumericLiteral(lit)) = &call_expr.arguments.first()
            && self.sub == 0
            && self.main_script
        {
            self.sub = lit.value as usize;
        }

        walk_computed_member_expression(self, node);
    }

    fn visit_call_expression(&mut self, call_expr: &mut CallExpression<'a>) {
        if let Expression::Identifier(ident) = &call_expr.callee
            && ident.name == "Error"
            && let Some(Argument::CallExpression(call_expr_2)) = &call_expr.arguments.first()
            && let Some(Argument::NumericLiteral(lit)) = &call_expr_2.arguments.first()
            && self.sub == 0
            && !self.main_script
        {
            self.sub = lit.value as usize;
        }

        walk_call_expression(self, call_expr);
    }

    fn visit_function_body(&mut self, body: &mut FunctionBody<'a>) {
        if !body.is_empty()
            && let Statement::ExpressionStatement(expr) = &body.statements[0]
            && let Expression::AssignmentExpression(assign_expr) = &expr.expression
        {
            self.extract_decoder(assign_expr);
        }

        walk_function_body(self, body);
    }

    fn visit_return_statement(&mut self, node: &mut ReturnStatement<'a>) {
        if let Some(Expression::SequenceExpression(sequ_expr)) = &node.argument
            && sequ_expr.expressions.len() == 3
        {
            let inner_expr = match &sequ_expr.expressions[0] {
                Expression::ParenthesizedExpression(parenth_expr) => &parenth_expr.expression,
                _ => &sequ_expr.expressions[0],
            };

            if let Expression::AssignmentExpression(assign_expr) = inner_expr {
                self.extract_decoder(assign_expr);
            }
        }

        walk_return_statement(self, node);
    }
}

pub struct Strings<'a> {
    ast: AstBuilder<'a>,
    decoder: Decoder<'a>,

    main_script: bool,
}

impl<'a> Strings<'a> {
    pub fn new(allocator: &'a Allocator, main_script: bool) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            decoder: Decoder::default(),

            main_script,
        }
    }
}

const BLACKLISTED_IDENTIFIERS: [&str; 1] = ["BigInt"];
impl<'a> VisitMut<'a> for Strings<'a> {
    fn visit_program(&mut self, node: &mut Program<'a>) {
        let mut string_visitor = StringVisitor::new(self.ast.allocator, self.main_script);
        string_visitor.visit_program(node);

        let mut decoder_visitor = DecoderVisitor::new(string_visitor.string, self.main_script);
        decoder_visitor.visit_program(node);

        self.decoder = decoder_visitor.decoder;
        walk_program(self, node);
    }

    fn visit_expression(&mut self, node: &mut Expression<'a>) {
        if let Expression::CallExpression(call_expr) = node
            && matches!(call_expr.callee, Expression::Identifier(_))
            && !BLACKLISTED_IDENTIFIERS.contains(&call_expr.callee.get_identifier_reference().unwrap().name.as_str())
            && call_expr.arguments.len() == 1
            && let Argument::NumericLiteral(lit) = &call_expr.arguments[0]
            && let Some(decoded_str) = self.decoder.decode_string(lit.value as usize)
        {
            *node = Expression::StringLiteral(self.ast.alloc(StringLiteral {
                value: self.ast.atom(decoded_str.as_str()),
                raw: None,
                span: SPAN,
                lone_surrogates: false,
            }));

            return;
        }

        walk_expression(self, node);
    }
}
