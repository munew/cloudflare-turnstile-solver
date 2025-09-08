use oxc_allocator::Allocator;
use oxc_ast::{ast::*, AstBuilder};
use oxc_ast_visit::walk_mut::{walk_conditional_expression, walk_if_statement};
use oxc_ast_visit::VisitMut;
use oxc_span::SPAN;
use std::cell::Cell;

pub struct NormalizeConditionals<'a> {
    ast: AstBuilder<'a>,
}

impl<'a> NormalizeConditionals<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
        }
    }

    fn should_convert_operator(&self, operator: &BinaryOperator) -> Option<BinaryOperator> {
        match operator {
            BinaryOperator::StrictInequality => Some(BinaryOperator::StrictEquality),
            BinaryOperator::Inequality => Some(BinaryOperator::Equality),
            _ => None,
        }
    }

    // fn normalize(&mut self, node: &mut ConditionalExpression<'a>, bin_expr: &mut BinaryExpression) {
    //     if let Some(new_op) = self.should_convert_operator(&bin_expr.operator) {
    //         bin_expr.operator = new_op;
    //         node.test = self.ast.move_expression(&mut node.test);
    // 
    //         let orig_consequent = self.ast.move_expression(&mut node.consequent);
    //         let orig_alternate = self.ast.move_expression(&mut node.alternate);
    //         node.consequent = orig_alternate;
    //         node.alternate = orig_consequent;
    //     }
    // }
}

impl<'a> VisitMut<'a> for NormalizeConditionals<'a> {
    fn visit_conditional_expression(&mut self, node: &mut ConditionalExpression<'a>) {
        walk_conditional_expression(self, node);

        match &mut node.test.get_inner_expression_mut() {
            Expression::BinaryExpression(bin_expr) => {
                if let Some(new_operator) = self.should_convert_operator(&bin_expr.operator) {
                    bin_expr.operator = new_operator;

                    node.test = self.ast.move_expression(&mut node.test);

                    let original_consequent = self.ast.move_expression(&mut node.consequent);
                    let original_alternate = self.ast.move_expression(&mut node.alternate);
                    node.consequent = original_alternate;
                    node.alternate = original_consequent;
                }
            }

            Expression::SequenceExpression(seq_expr) => {
                if let Some(test) = seq_expr.expressions.last_mut()
                    && let Expression::BinaryExpression(bin_expr) =
                    &mut test.get_inner_expression_mut()
                    && let Some(new_operator) = self.should_convert_operator(&bin_expr.operator)
                {
                    bin_expr.operator = new_operator;

                    node.test = self.ast.move_expression(&mut node.test);

                    let original_consequent = self.ast.move_expression(&mut node.consequent);
                    let original_alternate = self.ast.move_expression(&mut node.alternate);
                    node.consequent = original_alternate;
                    node.alternate = original_consequent;
                }
            }

            _ => {}
        }
    }

    fn visit_if_statement(&mut self, node: &mut IfStatement<'a>) {
        walk_if_statement(self, node);

        if let Expression::BinaryExpression(bin_expr) = &mut node.test
            && let Some(new_operator) = self.should_convert_operator(&bin_expr.operator)
        {
            bin_expr.operator = new_operator;

            let original_consequent = self.ast.move_statement(&mut node.consequent);
            node.test = self.ast.move_expression(&mut node.test);
            if let Some(alternate) = &mut node.alternate {
                let original_alternate = self.ast.move_statement(alternate);
                node.alternate = Some(original_consequent);
                node.consequent = original_alternate;
            } else {
                let empty_block = Statement::BlockStatement(self.ast.alloc(BlockStatement {
                    span: SPAN,
                    body: self.ast.vec(),
                    scope_id: Cell::new(None),
                }));

                node.alternate = Some(original_consequent);
                node.consequent = empty_block;
            }
        }
    }
}
