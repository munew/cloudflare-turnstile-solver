use oxc_allocator::Allocator;
use oxc_ast::{AstBuilder, ast::*};
use oxc_ast_visit::VisitMut;
use oxc_ast_visit::walk_mut::{walk_expression, walk_program};
use oxc_span::SPAN;
use rustc_hash::FxHashMap;

static KEYS_BLACKLIST: &[&str] = &[
    "event",
    "source",
    "widgetId",
    "parent",
    "addEventListener",
    "setTimeout",
    "_cf_chl_opt",
    "prototype",
    "type",
];

fn extract_proxy<'a>(
    proxy_expr: &Expression<'a>,
    proxies: &FxHashMap<&'a str, Proxy<'a>>,
) -> (Option<Proxy<'a>>, Option<Expression<'a>>) {
    match &proxy_expr {
        Expression::StringLiteral(str_lit) => {
            return (
                Some(Proxy::String {
                    raw: str_lit.value.as_str(),
                }),
                None,
            );
        }

        Expression::FunctionExpression(func_expr) => {
            if let Some(body) = &func_expr.body {
                if body.statements.len() >= 1 {
                    let func_arguments: FxHashMap<&'a str, usize> = func_expr
                        .params
                        .items
                        .iter()
                        .enumerate()
                        .map(|(i, arg)| match &arg.pattern.kind {
                            BindingPatternKind::BindingIdentifier(ident) => {
                                (ident.name.as_str(), i)
                            }
                            _ => ("", 0),
                        })
                        .collect();

                    match &body.statements.last().unwrap() {
                        Statement::ReturnStatement(return_stmt) => {
                            if let Some(arg) = &return_stmt.argument {
                                let expr = match arg {
                                    Expression::SequenceExpression(seq_expr) => {
                                        if let Some(last_expr) = seq_expr.expressions.last() {
                                            last_expr.get_inner_expression()
                                        } else {
                                            arg.get_inner_expression()
                                        }
                                    }
                                    _ => arg.get_inner_expression(),
                                };

                                match expr {
                                    Expression::CallExpression(call_expr) => {
                                        let callee: usize = match &call_expr.callee {
                                            Expression::Identifier(ident) => {
                                                if let Some(index) =
                                                    func_arguments.get(ident.name.as_str())
                                                {
                                                    *index
                                                } else {
                                                    return (None, None);
                                                }
                                            }
                                            Expression::ComputedMemberExpression(member_expr) => {
                                                if let Expression::StringLiteral(str_lit) =
                                                    &member_expr.expression
                                                {
                                                    if let Some(proxy) =
                                                        proxies.get(str_lit.value.as_str())
                                                    {
                                                        return (Some(proxy.clone()), None);
                                                    } else {
                                                        unsafe {
                                                            return (
                                                                None,
                                                                Some(std::mem::transmute_copy(
                                                                    proxy_expr,
                                                                )),
                                                            );
                                                        }
                                                    }
                                                }
                                                return (None, None);
                                            }
                                            _ => return (None, None),
                                        };

                                        let arguments: Vec<usize> = call_expr
                                            .arguments
                                            .iter()
                                            .map(|arg| match arg {
                                                Argument::Identifier(ident) => {
                                                    if let Some(index) =
                                                        func_arguments.get(ident.name.as_str())
                                                    {
                                                        *index
                                                    } else {
                                                        0
                                                    }
                                                }
                                                _ => 0,
                                            })
                                            .collect();

                                        return (
                                            Some(Proxy::CallExpression { callee, arguments }),
                                            None,
                                        );
                                    }

                                    Expression::BinaryExpression(bin_expr) => {
                                        let arguments: Vec<usize> = vec![
                                            match &bin_expr.left {
                                                Expression::Identifier(ident) => {
                                                    if let Some(index) =
                                                        func_arguments.get(ident.name.as_str())
                                                    {
                                                        *index
                                                    } else {
                                                        return (None, None);
                                                    }
                                                }
                                                _ => 0,
                                            },
                                            match &bin_expr.right {
                                                Expression::Identifier(ident) => {
                                                    if let Some(index) =
                                                        func_arguments.get(ident.name.as_str())
                                                    {
                                                        *index
                                                    } else {
                                                        return (None, None);
                                                    }
                                                }
                                                _ => 0,
                                            },
                                        ];

                                        return (
                                            Some(Proxy::BinaryExpression {
                                                operator: bin_expr.operator,
                                                arguments,
                                            }),
                                            None,
                                        );
                                    }

                                    Expression::ComputedMemberExpression(member_expr) => {
                                        if let Expression::StringLiteral(str_lit) =
                                            &member_expr.expression
                                        {
                                            if let Some(proxy) = proxies.get(str_lit.value.as_str())
                                            {
                                                return (Some(proxy.clone()), None);
                                            } else {
                                                unsafe {
                                                    return (
                                                        None,
                                                        Some(std::mem::transmute_copy(proxy_expr)),
                                                    );
                                                }
                                            }
                                        }
                                        return (None, None);
                                    }

                                    _ => {}
                                }
                            }
                        }

                        _ => {}
                    }
                }
            }
        }

        Expression::ComputedMemberExpression(member_expr) => {
            if let Expression::StringLiteral(str_lit) = &member_expr.expression {
                if let Some(proxy) = proxies.get(str_lit.value.as_str()) {
                    return (Some(proxy.clone()), None);
                } else {
                    unsafe {
                        return (None, Some(std::mem::transmute_copy(proxy_expr)));
                    }
                }
            }
            return (None, None);
        }

        _ => {}
    }

    (None, None)
}

#[derive(Debug, Clone)]
pub enum Proxy<'a> {
    String {
        raw: &'a str,
    },

    CallExpression {
        callee: usize,
        arguments: Vec<usize>,
    },

    BinaryExpression {
        operator: BinaryOperator,
        arguments: Vec<usize>,
    },
}

pub struct FindProxies<'a> {
    pub proxies: FxHashMap<&'a str, Proxy<'a>>,
    pub waiting_proxies: FxHashMap<&'a str, Expression<'a>>,
}

impl<'a> FindProxies<'a> {
    pub fn new() -> Self {
        Self {
            proxies: FxHashMap::default(),
            waiting_proxies: FxHashMap::default(),
        }
    }
}

impl<'a> VisitMut<'a> for FindProxies<'a> {
    fn visit_expression(&mut self, node: &mut Expression<'a>) {
        if let Expression::AssignmentExpression(assign_expr) = node {
            if let AssignmentTarget::AssignmentTargetIdentifier(_) = &assign_expr.left {
                if let Expression::ObjectExpression(obj) = &mut assign_expr.right {
                    for prop in obj.properties.iter_mut() {
                        if let ObjectPropertyKind::ObjectProperty(obj_prop) = prop {
                            let name = match &obj_prop.key {
                                PropertyKey::StringLiteral(prop_key) => prop_key.value.as_str(),
                                PropertyKey::StaticIdentifier(ident) => ident.name.as_str(),
                                PropertyKey::Identifier(ident) => ident.name.as_str(),
                                _ => continue,
                            };

                            if !KEYS_BLACKLIST.contains(&name) && name.len() == 5 {
                                let (proxy, expr) = extract_proxy(&obj_prop.value, &self.proxies);

                                if let Some(proxy) = proxy {
                                    self.proxies.insert(name, proxy);
                                }

                                if let Some(expr) = expr {
                                    self.waiting_proxies.insert(name, expr);
                                }
                            }
                        }
                    }
                }
            }

            if let AssignmentTarget::ComputedMemberExpression(member_expr) = &assign_expr.left {
                if let Expression::StringLiteral(str_lit) = &member_expr.expression
                    && !KEYS_BLACKLIST.contains(&str_lit.value.as_str())
                    && str_lit.value.len() == 5
                {
                    let (proxy, expr) = extract_proxy(&assign_expr.right, &self.proxies);

                    if let Some(proxy) = proxy {
                        self.proxies.insert(str_lit.value.as_str(), proxy);
                    }

                    if let Some(expr) = expr {
                        self.waiting_proxies.insert(str_lit.value.as_str(), expr);
                    }
                }
            }
        }

        walk_expression(self, node);
    }
}

pub struct ReplaceProxyFunctions<'a> {
    ast: AstBuilder<'a>,
    proxies: FxHashMap<&'a str, Proxy<'a>>,
}

impl<'a> ReplaceProxyFunctions<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            proxies: FxHashMap::default(),
        }
    }
}

impl<'a> VisitMut<'a> for ReplaceProxyFunctions<'a> {
    fn visit_program(&mut self, node: &mut Program<'a>) {
        let mut find_proxies = FindProxies::new();
        find_proxies.visit_program(node);

        let mut iters = 0;
        while iters < 3 {
            let mut to_rem = Vec::new();
            for (name, expr) in &find_proxies.waiting_proxies {
                if let (Some(new), _) = extract_proxy(expr, &find_proxies.proxies) {
                    find_proxies.proxies.insert(name, new);

                    to_rem.push(name);
                }
            }

            iters += 1;
        }

        self.proxies = find_proxies.proxies;
        walk_program(self, node);
    }

    fn visit_expression(&mut self, node: &mut Expression<'a>) {
        match node {
            Expression::CallExpression(call_expr) => {
                if let Expression::ComputedMemberExpression(member_expr) = &mut call_expr.callee {
                    if let Expression::StringLiteral(str_lit) = &mut member_expr.expression {
                        if let Some(proxy) = self.proxies.get(str_lit.value.as_str()) {
                            match proxy {
                                Proxy::CallExpression { callee, arguments } => {
                                    let e_callee = if let Some(mut expr) =
                                        call_expr.arguments[*callee].as_expression_mut()
                                    {
                                        self.ast.move_expression(&mut expr)
                                    } else {
                                        return;
                                    };

                                    let mut n_arguments = self.ast.vec();
                                    n_arguments.extend(arguments.iter().filter_map(|index| {
                                        call_expr.arguments.get_mut(*index).and_then(|arg| {
                                            arg.as_expression_mut()
                                                .map(|expr| self.ast.move_expression(expr).into())
                                        })
                                    }));

                                    *node =
                                        Expression::CallExpression(self.ast.alloc(CallExpression {
                                            span: SPAN,
                                            callee: e_callee,
                                            arguments: n_arguments,
                                            type_arguments: None,
                                            pure: false,
                                            optional: false,
                                        }))
                                }

                                Proxy::BinaryExpression {
                                    operator,
                                    arguments,
                                } => {
                                    if arguments.len() < 2 {
                                        return;
                                    }

                                    let e_left = if let Some(mut expr) =
                                        call_expr.arguments[arguments[0]].as_expression_mut()
                                    {
                                        self.ast.move_expression(&mut expr)
                                    } else {
                                        return;
                                    };

                                    let e_right = if let Some(mut expr) =
                                        call_expr.arguments[arguments[1]].as_expression_mut()
                                    {
                                        self.ast.move_expression(&mut expr)
                                    } else {
                                        return;
                                    };

                                    *node = Expression::BinaryExpression(self.ast.alloc(
                                        BinaryExpression {
                                            span: SPAN,
                                            operator: operator.clone(),
                                            left: e_left,
                                            right: e_right,
                                        },
                                    ))
                                }

                                _ => {}
                            }
                        }
                    }
                }
            }

            Expression::ComputedMemberExpression(member_expr) => {
                if let Expression::StringLiteral(str_lit) = &mut member_expr.expression {
                    if let Some(proxy) = self.proxies.get(str_lit.value.as_str()) {
                        match proxy {
                            Proxy::String { raw } => {
                                *node = Expression::StringLiteral(self.ast.alloc(StringLiteral {
                                    value: self.ast.atom(raw),
                                    raw: None,
                                    span: SPAN,
                                    lone_surrogates: false,
                                }))
                            }

                            _ => {}
                        }
                    }
                }
            }

            _ => {}
        }

        walk_expression(self, node);
    }
}