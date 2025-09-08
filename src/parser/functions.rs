use oxc_ast::ast::{
    ArrayExpressionElement, AssignmentExpression, AssignmentTarget, Expression, Function,
};
use oxc_ast_visit::{
    walk::{walk_assignment_expression, walk_function},
    Visit,
};
use oxc_semantic::ScopeFlags;
use rustc_hash::FxHashMap;

#[derive(Default)]
pub struct FindFunctions<'a> {
    last_function_name: &'a str,
    is_in_vm_function: bool,

    pub key: u16,
    pub constants: u16,
    pub function_with_opcodes: &'a str,
    pub functions: FxHashMap<&'a str, u16>,
}

impl<'a> Visit<'a> for FindFunctions<'a> {
    fn visit_function(&mut self, node: &Function<'a>, flags: ScopeFlags) {
        if let Some(name) = node.id.as_ref().map(|id| id.name.as_str()) {
            self.last_function_name = name;
        }

        self.is_in_vm_function = false;
        walk_function(self, node, flags);
    }

    fn visit_assignment_expression(&mut self, node: &AssignmentExpression<'a>) {
        if let (AssignmentTarget::StaticMemberExpression(left), Expression::BinaryExpression(_)) =
            (&node.left, &node.right)
        {
            if let Expression::ThisExpression(_) = &left.object {
                if &left.property.name == "g" {
                    self.is_in_vm_function = true;
                    self.function_with_opcodes = self.last_function_name;
                }
            }
        }

        if self.is_in_vm_function {
            if let AssignmentTarget::ComputedMemberExpression(member_expr) = &node.left {
                if let Expression::BinaryExpression(bin_expr) = &member_expr.expression {
                    let value = match (&bin_expr.left, &bin_expr.right) {
                        (Expression::NumericLiteral(n_lit1), _) => n_lit1.value as u16,
                        (_, Expression::NumericLiteral(n_lit2)) => n_lit2.value as u16,
                        _ => 0,
                    };

                    match &node.right {
                        Expression::Identifier(ident) => {
                            self.functions.insert(ident.name.into(), value);
                        }
                        Expression::ArrayExpression(array_expr) => {
                            self.constants = value;

                            if let ArrayExpressionElement::NumericLiteral(num_lit) =
                                &array_expr.elements[3]
                            {
                                self.key = num_lit.value as u16;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        walk_assignment_expression(self, node);
    }
}
