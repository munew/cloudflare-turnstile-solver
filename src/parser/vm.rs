use oxc_ast::ast::{CallExpression, Expression, StringLiteral};
use oxc_ast_visit::walk::walk_call_expression;
use oxc_ast_visit::Visit;

#[derive(Default, Debug)]
pub struct ScriptVisitor {
    pub initial_vm: Option<String>,
    pub main_vm: Option<String>,
    pub compressor_charset: Option<String>,
    pub init_argument: Option<String>,
}

impl<'a> Visit<'a> for ScriptVisitor {
    // fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
    //     if let Expression::StringLiteral(literal) = &it.object
    //         && let Expression::StringLiteral(literal2) = &it.expression
    //         && literal.value.len() == 65
    //         && literal2.value == "charAt"
    //     {
    //         self.compressor_charset = Some(literal.value.to_string());
    //     }
    // 
    //     walk_computed_member_expression(self, it);
    // }
    
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if !it.callee.is_identifier_reference() {
            walk_call_expression(self, it);
            return;
        }

        if it.arguments.len() != 1 {
            walk_call_expression(self, it);
            return;
        }

        let callee = it.callee_name().unwrap();
        let first_arg = it.arguments.get(0).unwrap();

        if !first_arg.is_expression() || !first_arg.as_expression().unwrap().is_string_literal() {
            walk_call_expression(self, it);
            return;
        }

        let first_arg_str = match first_arg.as_expression().unwrap() {
            Expression::StringLiteral(str) => str,
            _ => panic!("expected a string literal"),
        }
            .value
            .as_str();

        if first_arg_str.len() < 300 {
            walk_call_expression(self, it);
            return;
        }

        match callee {
            "atob" => self.initial_vm = Some(first_arg_str.to_string()),
            _ => {
                if first_arg_str.len() >= 1000 {
                    self.main_vm = Some(first_arg_str.to_string())
                }
            }
        }

        walk_call_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        if it.value.len() == 65 && it.value.contains("$") && it.value.contains("-") && it.value.contains("+") {
            self.compressor_charset = Some(it.value.to_string());
        }
        
        if it.value.len() > 20
            && it.value.starts_with("/")
            && it.value.ends_with("/")
            && it.value.split(":").count() == 3
            && !it.value.contains("/b/")
        {
            self.init_argument = Some(it.value.to_string());
        }
    }
}
