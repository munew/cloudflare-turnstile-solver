use crate::deobfuscator::deobfuscate;
use crate::solver::entries::FingerprintEntryBase;
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, AssignmentExpression, CallExpression, Expression, MemberExpression};
use oxc_ast_visit::{walk, Visit};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct EvalErrorEntry {
    pub error_key: String,
    pub error_length: usize,
}

#[async_trait]
impl FingerprintEntryBase for EvalErrorEntry {
    fn parse(
        _: &FxHashMap<String, usize>,
        strings: &[String],
        _: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let script = strings
            .iter()
            .find(|s| s.contains("){"))
            .context("could not find eval script")?;
        let (key, error_length) =
            get_eval_error_output_key(script).context("could not find eval error key")?;

        Ok(Self {
            error_key: key,
            error_length,
        })
    }

    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        let call_function_name = task.opcode_to_function_name.get("Call").unwrap();
        let base = format!(
            "Ninjas>pirates,Error:Ninjas>piratesatevalevalat{call_function_name}https://challenges.cloudflare.com"
        );
        let result: String = base.chars().take(self.error_length).collect();
        map.insert(self.error_key.clone(), result.into());

        task.query_selector_calls.push("script".to_string());
        Ok(3)
    }
}

#[derive(Default)]
struct EvalErrorKeyFinderVisitor {
    key: Option<String>,
    error_length: Option<usize>,
}

impl<'a> Visit<'a> for EvalErrorKeyFinderVisitor {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(id) = &it.callee
            && id.name == "substring"
            && it.arguments.len() == 2
            && let Argument::NumericLiteral(lit) = &it.arguments[2]
        {
            self.error_length = Some(lit.value as usize);
        }

        if let Expression::ComputedMemberExpression(member) = &it.callee
            && let Expression::StringLiteral(lit) = &member.expression
            && lit.value == "substring"
            && it.arguments.len() == 2
            && let Argument::NumericLiteral(lit) = &it.arguments[1]
        {
            self.error_length = Some(lit.value as usize);
        }

        walk::walk_call_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if !it.left.is_member_expression() || !it.right.is_member_expression() {
            walk::walk_assignment_expression(self, it);
            return;
        }

        let left = match it.left.as_member_expression().unwrap() {
            MemberExpression::ComputedMemberExpression(it) => it,
            _ => panic!(),
        };

        let right = match &it.right {
            Expression::ComputedMemberExpression(it) => it,
            _ => panic!(),
        };

        if let Expression::NumericLiteral(num) = &right.expression
            && num.value == 2.0
            && let Expression::StringLiteral(lit) = &left.expression
        {
            self.key = Some(lit.value.to_string());
        }

        walk::walk_assignment_expression(self, it);
    }
}

fn get_eval_error_output_key(js_code: &str) -> Option<(String, usize)> {
    let allocator = Allocator::default();
    let program = deobfuscate(js_code, &allocator, false);

    let mut visitor = EvalErrorKeyFinderVisitor::default();
    walk::walk_program(&mut visitor, program);

    if visitor.key.is_none() || visitor.error_length.is_none() {
        return None;
    }

    Some((visitor.key.unwrap(), visitor.error_length.unwrap()))
}
