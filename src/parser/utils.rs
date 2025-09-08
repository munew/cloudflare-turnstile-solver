use oxc_ast::ast::{
    AssignmentExpression, AssignmentOperator, AssignmentTarget, BinaryExpression,
    ConditionalExpression, Expression, IdentifierReference, StaticMemberExpression,
};
use oxc_ast_visit::{
    Visit,
    walk::{walk_assignment_expression, walk_binary_expression, walk_static_member_expression},
};
use rustc_hash::FxHashMap;

#[derive(Debug, Default)]
pub struct TestExtractor {
    pub tests: Vec<u16>,
}

impl<'a> Visit<'a> for TestExtractor {
    fn visit_binary_expression(&mut self, node: &BinaryExpression<'a>) {
        if node.operator.as_str() == "==" || node.operator.as_str() == "===" {
            let value = match (
                node.left.get_inner_expression(),
                node.right.get_inner_expression(),
            ) {
                (Expression::NumericLiteral(lit), _) => lit.value as u16,
                (_, Expression::NumericLiteral(lit)) => lit.value as u16,
                _ => {
                    walk_binary_expression(self, node);

                    return;
                }
            };

            self.tests.push(value);
        }

        walk_binary_expression(self, node);
    }
}

#[derive(Debug, Default)]
pub struct ExtractIdentifiers {
    pub identifiers: FxHashMap<String, Vec<String>>,
    found: Vec<String>,
}

impl<'a> Visit<'a> for ExtractIdentifiers {
    fn visit_assignment_expression(&mut self, node: &AssignmentExpression<'a>) {
        walk_assignment_expression(self, node);

        let ident = match &node.left {
            AssignmentTarget::AssignmentTargetIdentifier(ident) => ident.name.into_string(),
            _ => {
                return;
            }
        };

        self.identifiers.insert(
            ident.clone(),
            self.found
                .to_owned()
                .iter()
                .filter_map(|x| if x != &ident { Some(x.clone()) } else { None })
                .collect(),
        );
        self.found.clear();
    }

    fn visit_static_member_expression(&mut self, node: &StaticMemberExpression<'a>) {
        if let Expression::ThisExpression(_) = &node.object {
            return;
        }

        walk_static_member_expression(self, node);
    }

    fn visit_identifier_reference(&mut self, node: &IdentifierReference<'a>) {
        self.found.push(node.name.into_string());
    }
}

pub struct BinaryBitExtractor<'a> {
    blacklist: Vec<u16>,
    assigment_identifiers: Vec<&'a str>,

    pub identifiers: FxHashMap<String, Vec<String>>,

    pub bits: Vec<u16>,
    pub swaps: Vec<bool>,
}

impl<'a> BinaryBitExtractor<'a> {
    pub fn new(constants: u16, mut assigment_identifiers: Vec<&'a str>) -> BinaryBitExtractor<'a> {
        let blacklist = vec![constants]; // maybe 255 too?
        if assigment_identifiers.len() > 6 {
            assigment_identifiers.drain(..assigment_identifiers.len() - 6);
        }

        BinaryBitExtractor {
            blacklist,
            assigment_identifiers,
            identifiers: FxHashMap::default(),
            bits: Vec::new(),
            swaps: Vec::new(),
        }
    }

    fn get_o(&mut self) -> Option<Vec<String>> {
        let copy = self.identifiers.clone();
        let o_list = self
            .identifiers
            .get_mut(*self.assigment_identifiers.get(4).unwrap_or(&"o"))?;

        Some(
            o_list
                .iter()
                .filter_map(|s| {
                    if s == self.assigment_identifiers.get(5).unwrap_or(&"h") {
                        copy.get(*self.assigment_identifiers.get(5).unwrap_or(&"h"))?
                            .get(0)
                            .cloned()
                    } else {
                        Some(s.to_string())
                    }
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl<'a> Visit<'a> for BinaryBitExtractor<'a> {
    fn visit_assignment_expression(&mut self, node: &AssignmentExpression<'a>) {
        let mut extractor = ExtractIdentifiers::default();
        extractor.visit_assignment_expression(node);

        self.identifiers.extend(extractor.identifiers);

        walk_assignment_expression(self, node);
    }

    fn visit_binary_expression(&mut self, node: &BinaryExpression<'a>) {
        if node.operator.as_str() == "^" {
            let (value, _) = match (
                node.left.get_inner_expression(),
                node.right.get_inner_expression(),
            ) {
                (Expression::NumericLiteral(lit), Expression::Identifier(ident)) => {
                    (lit.value as u16, ident.name.to_string())
                }
                (Expression::Identifier(ident), Expression::NumericLiteral(lit)) => {
                    (lit.value as u16, ident.name.to_string())
                }
                _ => {
                    walk_binary_expression(self, node);

                    return;
                }
            };

            if (!node.right.is_member_expression() && !node.left.is_member_expression())
                || !self.blacklist.contains(&value)
            {
                self.bits.push(value);
            }

            if self.bits.len() % 3 == 0 {
                if self
                    .get_o()
                    .unwrap_or(vec!["".to_string()])
                    .get(0)
                    .unwrap_or(&"".to_string())
                    == *self.assigment_identifiers.get(2).unwrap_or(&"m")
                {
                    self.swaps.push(true);
                } else {
                    self.swaps.push(false);
                }

                self.identifiers.clear();
            }

            return;
        }

        walk_binary_expression(self, node);
    }
}

#[derive(Debug)]
pub struct BitExtractor {
    blacklist: Vec<u16>,

    pub bits: Vec<u16>,
}

impl BitExtractor {
    pub fn new(constants: u16) -> BitExtractor {
        let blacklist = vec![constants]; // maybe 255 too?

        BitExtractor {
            blacklist,
            bits: Vec::new(),
        }
    }
}

impl<'a> Visit<'a> for BitExtractor {
    fn visit_binary_expression(&mut self, node: &BinaryExpression<'a>) {
        if node.operator.as_str() == "^" {
            let value = match (
                node.left.get_inner_expression(),
                node.right.get_inner_expression(),
            ) {
                (Expression::NumericLiteral(lit), _) => lit.value as u16,
                (_, Expression::NumericLiteral(lit)) => lit.value as u16,
                _ => {
                    walk_binary_expression(self, node);

                    return;
                }
            };

            if (!node.right.is_member_expression() && !node.left.is_member_expression())
                || !self.blacklist.contains(&value)
            {
                self.bits.push(value);
            }

            return;
        }

        walk_binary_expression(self, node);
    }
}

pub fn eval_key_expr(expr: &Expression, key: i64, op: i64) -> Option<i64> {
    match expr {
        Expression::ParenthesizedExpression(expr) => eval_key_expr(&expr.expression, key, op),
        Expression::ComputedMemberExpression(_) => Some(key),
        Expression::StaticMemberExpression(_) => Some(op),
        Expression::Identifier(_) => Some(key + op),
        Expression::BinaryExpression(bin_expr) => {
            let left_value = eval_key_expr(&bin_expr.left, key, op)?;
            let right_value = eval_key_expr(&bin_expr.right, key, op)?;
            match bin_expr.operator.as_str() {
                "*" => Some(left_value * right_value),
                "/" => Some(left_value / right_value),
                "%" => Some(left_value % right_value),
                "+" => Some(left_value + right_value),
                "-" => Some(left_value - right_value),
                "&" => Some(left_value & right_value),
                _ => None,
            }
        }
        Expression::NumericLiteral(literal) => Some(literal.value as i64),
        _ => None,
    }
}

pub struct AssigmentExtractor<'a> {
    pub identifiers: Vec<&'a str>,
}

impl<'a> AssigmentExtractor<'a> {
    pub fn new() -> Self {
        AssigmentExtractor {
            identifiers: Vec::new(),
        }
    }
}

impl<'a> Visit<'a> for AssigmentExtractor<'a> {
    fn visit_conditional_expression(&mut self, node: &ConditionalExpression<'a>) {
        if let Expression::BinaryExpression(binary_expr) = &node.test
            && let Expression::Identifier(ident) = &binary_expr.left
        {
            self.identifiers.push(ident.name.as_str());
        }

        if let Expression::BinaryExpression(binary_expr) = &node.test
            && let Expression::Identifier(ident) = &binary_expr.right
        {
            self.identifiers.push(ident.name.as_str());
        }

        return;
    }

    fn visit_if_statement(&mut self, _: &oxc_ast::ast::IfStatement<'a>) {
        return;
    }

    fn visit_assignment_expression(&mut self, assign_expr: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(ident) = &assign_expr.left
            && (matches!(
                &assign_expr.right.get_inner_expression(),
                Expression::BinaryExpression(_)
            ) || matches!(
                &assign_expr.right.get_inner_expression(),
                Expression::NumericLiteral(_)
            ) || matches!(
                &assign_expr.right.get_inner_expression(),
                Expression::UnaryExpression(_)
            ))
            && assign_expr.operator == AssignmentOperator::Assign
        {
            self.identifiers.push(ident.name.as_str());

            return;
        }

        walk_assignment_expression(self, assign_expr);
    }
}
