use oxc_allocator::{Allocator, Vec};
use oxc_ast::{ast::*, AstBuilder};
use oxc_ast_visit::walk_mut::walk_statements;
use oxc_ast_visit::VisitMut;
use oxc_span::SPAN;

use std::cell::Cell;

pub struct SequenceExpressions<'a> {
    ast: AstBuilder<'a>,
}

impl<'a> SequenceExpressions<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
        }
    }
}

impl<'a> VisitMut<'a> for SequenceExpressions<'a> {
    fn visit_statements(&mut self, node: &mut Vec<'a, Statement<'a>>) {
        let mut new_stmts: Vec<'_, Statement<'a>> = self.ast.vec();

        for stmt in node.iter_mut() {
            match stmt {
                Statement::ExpressionStatement(expr_stmt) => {
                    match expr_stmt.expression.get_inner_expression_mut() {
                        Expression::AssignmentExpression(assign_expr) => {
                            let name = match &mut assign_expr.left {
                                AssignmentTarget::AssignmentTargetIdentifier(ident) => ident.name,
                                _ => {
                                    new_stmts.push(self.ast.move_statement(stmt));
                                    continue;
                                }
                            };
                            match &mut assign_expr.right.get_inner_expression_mut() {
                                Expression::SequenceExpression(seq_expr) => {
                                    let len = seq_expr.expressions.len();
                                    for (i, expr) in seq_expr.expressions.iter_mut().enumerate() {
                                        if i == len - 1 {
                                            new_stmts.push(Statement::ExpressionStatement(
                                                self.ast.alloc(ExpressionStatement {
                                                    span: SPAN,
                                                    expression: Expression::AssignmentExpression(
                                                        self.ast.alloc(AssignmentExpression {
                                                            span: SPAN,
                                                            left: AssignmentTarget::AssignmentTargetIdentifier(
                                                                self.ast.alloc(IdentifierReference {
                                                                    span: SPAN,
                                                                    name,
                                                                    reference_id: Cell::new(None),
                                                                })
                                                            ),
                                                            operator: AssignmentOperator::Assign,
                                                            right: self.ast.move_expression(expr),
                                                        }),
                                                    ),
                                                }),
                                            ));
                                        } else {
                                            new_stmts.push(Statement::ExpressionStatement(
                                                self.ast.alloc(ExpressionStatement {
                                                    span: SPAN,
                                                    expression: self.ast.move_expression(expr),
                                                }),
                                            ));
                                        }
                                    }
                                }
                                _ => new_stmts.push(self.ast.move_statement(stmt)),
                            }
                        }

                        Expression::SequenceExpression(seq_expr) => {
                            for expr in seq_expr.expressions.iter_mut() {
                                new_stmts.push(Statement::ExpressionStatement(self.ast.alloc(
                                    ExpressionStatement {
                                        span: SPAN,
                                        expression: self.ast.move_expression(expr),
                                    },
                                )));
                            }
                        }

                        _ => new_stmts.push(self.ast.move_statement(stmt)),
                    }
                }

                Statement::ReturnStatement(return_stmt) => match &mut return_stmt.argument {
                    Some(expr) => match expr.get_inner_expression_mut() {
                        Expression::SequenceExpression(seq_expr) => {
                            let len = seq_expr.expressions.len();
                            for (i, expr) in seq_expr.expressions.iter_mut().enumerate() {
                                if i == len - 1 {
                                    new_stmts.push(Statement::ReturnStatement(self.ast.alloc(
                                        ReturnStatement {
                                            span: SPAN,
                                            argument: Some(self.ast.move_expression(expr)),
                                        },
                                    )));
                                } else {
                                    new_stmts.push(Statement::ExpressionStatement(self.ast.alloc(
                                        ExpressionStatement {
                                            span: SPAN,
                                            expression: self.ast.move_expression(expr),
                                        },
                                    )));
                                }
                            }
                        }

                        _ => new_stmts.push(self.ast.move_statement(stmt)),
                    },

                    _ => new_stmts.push(self.ast.move_statement(stmt)),
                },

                //Statement::ForStatement(for_stmt) => {
                //    if let Some(ForStatementInit::SequenceExpression(seq_expr)) = &mut for_stmt.init
                //    {
                //        let len = seq_expr.expressions.len();

                //        let mut last = None;
                //        for (i, expr) in seq_expr.expressions.iter_mut().enumerate() {
                //            if i == len - 1 {
                //                last = Some(self.ast.move_expression(expr));
                //            } else {
                //                new_stmts.push(Statement::ExpressionStatement(self.ast.alloc(
                //                    ExpressionStatement {
                //                        span: SPAN,
                //                        expression: self.ast.move_expression(expr),
                //                    },
                //                )));
                //            }
                //        }

                //        if let Some(mut last) = last {
                //            new_stmts.push(Statement::ForStatement(
                //                self.ast.alloc(ForStatement {
                //                    span: SPAN,
                //                    init: Some(self.ast.move_expression(&mut last).into()),

                //                    test: for_stmt
                //                        .test
                //                        .as_mut()
                //                        .map(|test| self.ast.move_expression(test)),

                //                    update: for_stmt
                //                        .update
                //                        .as_mut()
                //                        .map(|update| self.ast.move_expression(update)),

                //                    body: self.ast.move_statement(&mut for_stmt.body),
                //                    scope_id: Cell::new(None),
                //                }),
                //            ));
                //        }
                //    }
                //}
                Statement::IfStatement(if_stmt) => match if_stmt.test.get_inner_expression_mut() {
                    Expression::SequenceExpression(seq_expr) => {
                        let len = seq_expr.expressions.len();

                        let mut last = None;
                        for (i, expr) in seq_expr.expressions.iter_mut().enumerate() {
                            if i == len - 1 {
                                last = Some(self.ast.move_expression(expr));
                            } else {
                                new_stmts.push(Statement::ExpressionStatement(self.ast.alloc(
                                    ExpressionStatement {
                                        span: SPAN,
                                        expression: self.ast.move_expression(expr),
                                    },
                                )));
                            }
                        }

                        if let Some(mut last) = last {
                            new_stmts.push(Statement::IfStatement(
                                self.ast.alloc(IfStatement {
                                    span: SPAN,
                                    test: self.ast.move_expression(&mut last),
                                    consequent: self.ast.move_statement(&mut if_stmt.consequent),
                                    alternate: if_stmt
                                        .alternate
                                        .as_mut()
                                        .map(|alt| self.ast.move_statement(alt)),
                                }),
                            ));
                        }
                    }

                    _ => new_stmts.push(self.ast.move_statement(stmt)),
                },

                _ => new_stmts.push(self.ast.move_statement(stmt)),
            }
        }

        *node = new_stmts;
        walk_statements(self, node);
    }
}
