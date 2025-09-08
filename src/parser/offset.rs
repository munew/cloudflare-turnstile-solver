use oxc_allocator::Allocator;
use oxc_ast::{
    ast::{AssignmentExpression, AssignmentTarget, BinaryExpression, Expression, ForStatement},
    AstBuilder,
};
use oxc_ast_visit::{
    walk_mut::{
        walk_assignment_expression, walk_binary_expression, walk_expression, walk_for_statement,
    },
    VisitMut,
};

pub struct GetKeyOperations<'a> {
    ast: AstBuilder<'a>,

    pub key_expr: Option<Expression<'a>>,
}

impl<'a> GetKeyOperations<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            key_expr: None,
        }
    }
}

impl<'a> VisitMut<'a> for GetKeyOperations<'a> {
    fn visit_expression(&mut self, node: &mut Expression<'a>) {
        if let Expression::BinaryExpression(bin_expr) = node {
            if bin_expr.operator.as_str() == "&" {
                println!("Found & operation: {:?}", bin_expr.right);
                if let Expression::NumericLiteral(num) = &bin_expr.right {
                    if num.value == 255.0 {
                        self.key_expr = Some(self.ast.move_expression(node));
                    }
                }
            }
        }
        walk_expression(self, node);
    }
}

#[derive(Default, Debug)]
pub struct KeyOperations {
    pub add: u32,
    pub multiply: u32,
}

pub struct FindOffset<'a> {
    ast: AstBuilder<'a>,
    in_for: bool,

    pub key_expr: Option<Expression<'a>>,

    pub offset: i16,
}

impl<'a> FindOffset<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            in_for: false,
            key_expr: None,
            offset: 0,
        }
    }
}

impl<'a> VisitMut<'a> for FindOffset<'a> {
    fn visit_for_statement(&mut self, node: &mut ForStatement<'a>) {
        self.in_for = true;
        walk_for_statement(self, node);
        self.in_for = false;
    }

    fn visit_assignment_expression(&mut self, node: &mut AssignmentExpression<'a>) {
        if self.in_for {
            if node.operator.as_str() == "=" {
                if let (
                    AssignmentTarget::ComputedMemberExpression(member_expr),
                    Expression::BinaryExpression(_),
                ) = (&node.left, &node.right)
                {
                    if let Expression::NumericLiteral(num_lit) = &member_expr.expression {
                        if num_lit.value == 3.0 {
                            self.key_expr = Some(self.ast.move_expression(&mut node.right));
                        }
                    }
                }
            }
        }

        walk_assignment_expression(self, node);
    }

    fn visit_binary_expression(&mut self, node: &mut BinaryExpression<'a>) {
        if node.operator.as_str() == "+" {
            let (lit, call_expr) = match (&node.left, &node.right) {
                (Expression::NumericLiteral(num_lit), Expression::CallExpression(call_expr)) => {
                    (num_lit.value as u16, Some(call_expr))
                }
                (Expression::CallExpression(call_expr), Expression::NumericLiteral(num_lit)) => {
                    (num_lit.value as u16, Some(call_expr))
                }
                _ => (0, None),
            };

            if let Some(_) = call_expr {
                self.offset = lit as i16;

                return;
            }
        }

        walk_binary_expression(self, node);
    }
}
