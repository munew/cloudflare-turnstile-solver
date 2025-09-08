use oxc_allocator::Allocator;
use oxc_ast::{
    AstBuilder,
    ast::{AssignmentExpression, AssignmentTarget, Expression, NumberBase, ObjectPropertyKind},
};
use oxc_ast_visit::{
    VisitMut,
    walk_mut::{walk_assignment_expression, walk_expression},
};
use oxc_span::SPAN;
use rustc_hash::FxHashMap;

pub struct NumbersVisitor<'a> {
    ast: AstBuilder<'a>,

    objects: FxHashMap<String, FxHashMap<String, u16>>,
}

impl<'a> NumbersVisitor<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),

            objects: FxHashMap::default(),
        }
    }
}

impl<'a> VisitMut<'a> for NumbersVisitor<'a> {
    fn visit_assignment_expression(&mut self, assign: &mut AssignmentExpression<'a>) {
        if let (
            AssignmentTarget::AssignmentTargetIdentifier(ident),
            Expression::ObjectExpression(obj),
        ) = (&assign.left, &assign.right)
        {
            let props: FxHashMap<String, u16> = obj
                .properties
                .iter()
                .filter_map(|prop| {
                    if let ObjectPropertyKind::ObjectProperty(obj) = prop {
                        if let (Some(name), Expression::NumericLiteral(num)) =
                            (obj.key.name(), &obj.value)
                        {
                            Some((name.to_string(), num.value as u16))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            self.objects.insert(ident.name.to_string(), props);
        }

        walk_assignment_expression(self, assign);
    }

    fn visit_expression(&mut self, expr: &mut Expression<'a>) {
        if let Expression::StaticMemberExpression(memb) = &expr
            && let Expression::Identifier(ident) = &memb.object
            && let Some(props) = self.objects.get(&ident.name.to_string())
            && let Some(value) = props.get(&memb.property.name.to_string())
        {
            *expr = Expression::NumericLiteral(self.ast.alloc_numeric_literal(
                SPAN,
                *value as f64,
                None,
                NumberBase::Decimal,
            ));
        }

        walk_expression(self, expr);
    }
}