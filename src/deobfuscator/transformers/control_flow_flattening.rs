use oxc_allocator::{Allocator, Vec as Vec2};
use oxc_ast::{ast::*, AstBuilder};
use oxc_ast_visit::walk_mut::{walk_statement, walk_statements};
use oxc_ast_visit::VisitMut;

use oxc_span::SPAN;
use rustc_hash::FxHashMap;

pub struct ControlFlowFlattening<'a> {
    ast: AstBuilder<'a>,
}

impl<'a> ControlFlowFlattening<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
        }
    }

    pub fn patch_statement(&mut self, node: &mut Statement<'a>) -> Option<Vec2<'a, Statement<'a>>> {
        if let Statement::ForStatement(for_stmt) = node {
            let flow_str = if let Some(ForStatementInit::SequenceExpression(seq_expr)) =
                &for_stmt.init
            {
                let mut result = None;

                for expr in &seq_expr.expressions {
                    if let Expression::AssignmentExpression(assign_expr) = expr
                        && let Expression::CallExpression(call_expr) = &assign_expr.right
                        && let Expression::ComputedMemberExpression(member_expr) = &call_expr.callee
                        && let Expression::StringLiteral(str_lit) = &member_expr.object
                    {
                        result = Some(str_lit.value.as_str());
                    }
                }

                result?
            } else {
                return None;
            }
                .split("|")
                .collect::<Vec<&str>>();

            if flow_str[0].len() > 2 {
                return None;
            }

            let mut cases: FxHashMap<&str, oxc_allocator::Vec<'_, Statement<'_>>> =
                FxHashMap::default();
            if let Statement::BlockStatement(block_stmt) = &mut for_stmt.body
                && let Statement::SwitchStatement(switch_stmt) = &mut block_stmt.body[0]
            {
                for case in switch_stmt.cases.iter_mut() {
                    if let Some(Expression::StringLiteral(str_lit)) = &case.test {
                        if case.consequent.len() != 1 {
                            case.consequent.pop();
                        }
                        cases.insert(
                            str_lit.value.as_str(),
                            self.ast.move_vec(&mut case.consequent),
                        );
                    }
                }
            }

            let mut blocks = self.ast.vec();
            for flow in flow_str.iter() {
                if let Some(stmts) = cases.remove(flow) {
                    blocks.extend(stmts);
                }
            }

            return Some(blocks);
        }

        None
    }
}

impl<'a> VisitMut<'a> for ControlFlowFlattening<'a> {
    fn visit_statement(&mut self, stmt: &mut Statement<'a>) {
        if let Some(patched) = self.patch_statement(stmt)
            && !patched.is_empty()
        {
            *stmt = Statement::BlockStatement(self.ast.alloc_block_statement(SPAN, patched));
        }

        walk_statement(self, stmt);
    }

    fn visit_statements(&mut self, stmts: &mut Vec2<'a, Statement<'a>>) {
        let mut new_stmts: oxc_allocator::Vec<'_, Statement<'a>> = self.ast.vec();

        for stmt in stmts.iter_mut() {
            if let Some(patched) = self.patch_statement(stmt) {
                new_stmts.extend(patched);
            }
        }

        if !new_stmts.is_empty() {
            *stmts = new_stmts;
        }

        walk_statements(self, stmts);
    }
}
