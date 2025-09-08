use oxc_allocator::Allocator;
use oxc_ast::{ast::*, AstBuilder};
use oxc_ast_visit::walk_mut::{walk_expression, walk_statement};
use oxc_ast_visit::VisitMut;

pub struct UselessIf<'a> {
    ast: AstBuilder<'a>,
}

impl<'a> UselessIf<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
        }
    }

    fn evaluate_binary_expression(&self, expr: &BinaryExpression) -> Option<bool> {
        match (&expr.left, &expr.right) {
            (Expression::StringLiteral(left), Expression::StringLiteral(right)) => {
                match expr.operator {
                    BinaryOperator::StrictEquality => {
                        Some(left.value.as_str() == right.value.as_str())
                    }
                    BinaryOperator::StrictInequality => {
                        Some(left.value.as_str() != right.value.as_str())
                    }
                    BinaryOperator::Equality => Some(left.value.as_str() == right.value.as_str()),
                    BinaryOperator::Inequality => Some(left.value.as_str() != right.value.as_str()),
                    _ => None,
                }
            }
            (Expression::NumericLiteral(left), Expression::NumericLiteral(right)) => {
                match expr.operator {
                    BinaryOperator::StrictEquality => Some(left.value == right.value),
                    BinaryOperator::StrictInequality => Some(left.value != right.value),
                    BinaryOperator::Equality => Some(left.value == right.value),
                    BinaryOperator::Inequality => Some(left.value != right.value),
                    BinaryOperator::LessThan => Some(left.value < right.value),
                    BinaryOperator::LessEqualThan => Some(left.value <= right.value),
                    BinaryOperator::GreaterThan => Some(left.value > right.value),
                    BinaryOperator::GreaterEqualThan => Some(left.value >= right.value),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl<'a> VisitMut<'a> for UselessIf<'a> {
    fn visit_statement(&mut self, node: &mut Statement<'a>) {
        match node {
            Statement::IfStatement(if_stmt) => {
                if let Expression::BinaryExpression(bin_expr) = &if_stmt.test {
                    if let Some(result) = self.evaluate_binary_expression(bin_expr) {
                        if result {
                            *node = self.ast.move_statement(&mut if_stmt.consequent);
                        } else if let Some(alternate) = &mut if_stmt.alternate {
                            *node = self.ast.move_statement(alternate);
                        } else {
                            *node = Statement::EmptyStatement(
                                self.ast.alloc(EmptyStatement { span: if_stmt.span }),
                            );
                        }
                    }
                }
            }
            _ => {}
        }

        walk_statement(self, node);
    }

    fn visit_expression(&mut self, node: &mut Expression<'a>) {
        match node {
            Expression::ConditionalExpression(cond_expr) => {
                if let Expression::BinaryExpression(bin_expr) = &cond_expr.test {
                    if let Some(result) = self.evaluate_binary_expression(bin_expr) {
                        if result {
                            *node = self.ast.move_expression(&mut cond_expr.consequent);
                        } else {
                            *node = self.ast.move_expression(&mut cond_expr.alternate);
                        }
                    }
                }
            }
            _ => {}
        }

        walk_expression(self, node);
    }
}
