use std::collections::HashMap;

use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, CallExpression, Expression,
    ObjectPropertyKind, StringLiteral,
};
use oxc_ast_visit::{
    walk::{walk_assignment_expression, walk_call_expression, walk_string_literal},
    Visit,
};

#[derive(Default, Debug)]
pub struct PayloadKeyExtractor {
    check_for_writing: bool,
    start_writing: bool,
    write_to: Option<String>,

    pub browser_keys_key: String,
    pub initial_keys: Vec<String>,
    pub initial_keys_values: HashMap<String, String>,
    pub initial_obj_keys: Vec<String>,
}

impl<'a> Visit<'a> for PayloadKeyExtractor {
    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        if lit.value.starts_with("_cf_chl_opt;") {
            self.browser_keys_key = lit.value.split(";").collect::<Vec<&str>>()[16].to_string();
        }

        walk_string_literal(self, lit);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.write_to.is_some() {
            self.write_to = None;
        }

        if call.arguments.len() == 4
            && let Expression::Identifier(ident) = &call.callee
            && ident.name.as_str() == "setTimeout"
            && let Argument::NumericLiteral(num) = &call.arguments[1]
            && num.value == 100.0
            && let Argument::ObjectExpression(obj) = &call.arguments[3]
        {
            obj.properties.iter().for_each(|prop| {
                if let ObjectPropertyKind::ObjectProperty(obj_p) = prop {
                    if let Expression::StringLiteral(lit) = &obj_p.value {
                        Some(lit.value.to_string())
                    } else {
                        None
                    }
                        .and_then(|v| {
                            self.initial_keys_values
                                .insert(obj_p.key.name().unwrap().to_string(), v)
                        });

                    self.initial_keys
                        .push(obj_p.key.name().unwrap().to_string());
                }
            })
        }

        walk_call_expression(self, call);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if let (AssignmentTarget::ComputedMemberExpression(_), Expression::CallExpression(call)) =
            (&assign.left, &assign.right)
            && let Expression::ComputedMemberExpression(comp) = &call.callee
            && let Expression::Identifier(str) = &comp.object
            && str.name.as_str() == "performance"
        {
            self.check_for_writing = true;
        }

        if let (AssignmentTarget::AssignmentTargetIdentifier(_), Expression::ObjectExpression(_)) =
            (&assign.left, &assign.right)
            && self.check_for_writing
        {
            self.start_writing = true;
            self.check_for_writing = false;
        }

        if let AssignmentTarget::ComputedMemberExpression(comp) = &assign.left
            && let (Expression::Identifier(_), Expression::StringLiteral(str)) =
            (&comp.object, &comp.expression)
        {
            if self.start_writing {
                if let Expression::NumericLiteral(num) = &assign.right
                    && num.value == 0.0
                {
                    self.write_to = Some("obj".to_string());
                } else if let Expression::ComputedMemberExpression(comp) = &assign.right
                    && let Expression::StringLiteral(str) = &comp.expression
                    && str.value.as_str() == "cType"
                {
                    self.write_to = Some("normal".to_string());
                }

                self.start_writing = false;
            }

            match self.write_to.clone().unwrap_or("".to_string()).as_str() {
                "obj" => {
                    if let Expression::NumericLiteral(num) = &assign.right
                        && num.value == 0.0
                    {
                        self.initial_obj_keys.push(str.value.to_string());
                    } else {
                        self.write_to = None;
                    }
                }
                "normal" => {
                    if let Expression::StringLiteral(lit) = &assign.right {
                        Some(lit.value.to_string())
                    } else {
                        None
                    }
                        .and_then(|v| self.initial_keys_values.insert(str.value.to_string(), v));

                    self.initial_keys.push(str.value.to_string());
                }
                _ => {}
            }
        }

        walk_assignment_expression(self, assign);
    }
}
