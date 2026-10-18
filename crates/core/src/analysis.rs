use crate::model::Comment;
use crate::*;
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_codegen::Codegen;
use oxc_parser::Parser;
use oxc_semantic::{Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use regex::Regex;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::LazyLock,
};

#[derive(Default)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub endpoints: Vec<Endpoint>,
    pub comments: Vec<Comment>,
    pub modules: Vec<ModuleReference>,
    pub diagnostics: Vec<Diagnostic>,
    pub formatted: Option<String>,
}

pub fn evidence(
    artifact: &Artifact,
    text: &str,
    start: usize,
    end: usize,
    method: &str,
) -> Evidence {
    let mut start = start.min(text.len());
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let prefix = &text[..start];
    Evidence {
        artifact_id: artifact.id.clone(),
        location: artifact.location.clone(),
        start,
        end: end.min(text.len()),
        line: prefix.bytes().filter(|c| *c == b'\n').count() + 1,
        column: prefix
            .rsplit('\n')
            .next()
            .unwrap_or("")
            .encode_utf16()
            .count()
            + 1,
        method: method.into(),
        mapped_locations: vec![],
    }
}

fn source_type(location: &str) -> SourceType {
    let path = location.split(['?', '#']).next().unwrap_or(location);
    SourceType::from_path(path).unwrap_or_else(|_| SourceType::mjs())
}

pub fn beautify(text: &str, location: &str) -> Result<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, text, source_type(location)).parse();
    if !parsed.diagnostics.is_empty() {
        return Err(Error::Invalid(format!(
            "cannot format {location}: {:?}",
            parsed.diagnostics
        )));
    }
    Ok(Codegen::new().build(&parsed.program).code)
}

pub fn analyze(artifact: &Artifact, options: &ScanOptions) -> Analysis {
    let mut out = Analysis::default();
    let Ok(text) = std::str::from_utf8(&artifact.content) else {
        out.diagnostics.push(Diagnostic {
            code: "encoding".into(),
            location: artifact.location.clone(),
            message: "non UTF-8 artifact preserved; analysis skipped".into(),
            partial: true,
        });
        return out;
    };
    if options.enabled("secrets") {
        scan_patterns(text, artifact, "text", &mut out.findings);
    }
    if options.enabled("urls") {
        scan_urls(text, artifact, "text", &mut out.findings);
    }
    if artifact.kind != ArtifactKind::Script {
        if options.enabled("secrets")
            && artifact.kind == ArtifactKind::Json
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(text)
        {
            json_secrets(&json, "", artifact, text, &mut out.findings);
        }
        return out;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, text, source_type(&artifact.location)).parse();
    if !parsed.diagnostics.is_empty() {
        for d in parsed.diagnostics {
            out.diagnostics.push(Diagnostic {
                code: "parse_fallback".into(),
                location: artifact.location.clone(),
                message: format!("{d:?}"),
                partial: true,
            });
        }
        for finding in &mut out.findings {
            for e in &mut finding.evidence {
                e.method = "text_fallback".into();
            }
        }
        return out;
    }
    let built = SemanticBuilder::new_compiler()
        .with_build_nodes(true)
        .build(&parsed.program);
    for d in &built.diagnostics {
        out.diagnostics.push(Diagnostic {
            code: "semantic".into(),
            location: artifact.location.clone(),
            message: format!("{d:?}"),
            partial: true,
        });
    }
    if options.enabled("comments") {
        for c in &parsed.program.comments {
            let span = c.content_span();
            let value = span.source_text(text).to_string();
            let lower = value.to_lowercase();
            let tags = [
                "todo", "fixme", "secret", "token", "password", "admin", "internal", "feature",
            ]
            .iter()
            .filter(|x| lower.contains(**x))
            .map(|s| s.to_string())
            .collect();
            out.comments.push(Comment {
                text: value,
                tags,
                evidence: evidence(
                    artifact,
                    text,
                    span.start as usize,
                    span.end as usize,
                    "ast_comment",
                ),
            });
        }
    }
    let mut visitor = Analyzer {
        artifact,
        text,
        options,
        semantic: &built.semantic,
        values: HashMap::new(),
        invalid: HashSet::new(),
        xhr_endpoints: HashMap::new(),
        out: &mut out,
    };
    // Conservatively invalidate bindings written anywhere, including mutations of object members.
    let mut mutations = Mutations {
        semantic: &built.semantic,
        invalid: HashSet::new(),
    };
    mutations.visit_program(&parsed.program);
    visitor.invalid = mutations.invalid;
    visitor.visit_program(&parsed.program);
    out.formatted = Some(Codegen::new().build(&parsed.program).code);
    out
}

#[derive(Clone, Debug)]
enum Value {
    Text(String, bool),
    Number(f64),
    Object(BTreeMap<String, Value>),
    Client(String, BTreeMap<String, Value>),
    Xhr(String),
    Builtin(String),
    Method(Box<Value>, String),
    Request(Box<Value>, Box<Value>),
    Unknown(String),
}
impl Value {
    fn text(&self) -> (String, bool) {
        match self {
            Self::Text(s, known) => (s.clone(), *known),
            Self::Number(n) => (n.to_string(), true),
            Self::Unknown(s) => (format!("${{{s}}}"), false),
            _ => ("${unknown}".into(), false),
        }
    }
    fn prop(&self, key: &str) -> Value {
        match self {
            Self::Object(map) => map.get(key).cloned().unwrap_or(Value::Unknown(key.into())),
            Self::Client(..) if key == "default" => self.clone(),
            Self::Builtin(name) if ["window", "globalThis", "self"].contains(&name.as_str()) => {
                match key {
                    "fetch" | "Request" | "XMLHttpRequest" | "URL" => Self::Builtin(key.into()),
                    "axios" => Self::Client(String::new(), BTreeMap::new()),
                    _ => Self::Unknown(key.into()),
                }
            }
            Self::Client(..) | Self::Builtin(_) | Self::Xhr(_) => {
                Value::Method(Box::new(self.clone()), key.into())
            }
            _ => Value::Unknown(key.into()),
        }
    }
    fn keys(&self) -> Vec<String> {
        if let Self::Object(map) = self {
            map.keys().cloned().collect()
        } else {
            vec![]
        }
    }
}

fn merge_config(mut defaults: BTreeMap<String, Value>, config: Value) -> Value {
    let Value::Object(config) = config else {
        return config;
    };
    for (key, value) in config {
        let value = if ["headers", "params"].contains(&key.as_str()) {
            if let (Some(Value::Object(previous)), Value::Object(current)) =
                (defaults.get(&key), &value)
            {
                let mut combined = previous.clone();
                combined.extend(current.clone());
                Value::Object(combined)
            } else {
                value
            }
        } else {
            value
        };
        defaults.insert(key, value);
    }
    Value::Object(defaults)
}
fn http_method(config: &Value) -> String {
    match config {
        Value::Object(map) => map
            .get("method")
            .map(|v| v.text().0.to_uppercase())
            .unwrap_or("GET".into()),
        _ => "${method}".into(),
    }
}

fn symbol(semantic: &Semantic<'_>, id: &IdentifierReference<'_>) -> Option<String> {
    id.reference_id
        .get()
        .and_then(|r| semantic.scoping().get_reference(r).symbol_id())
        .map(|s| format!("{s:?}"))
}
fn normalized_binding(id: &BindingIdentifier<'_>) -> Option<String> {
    id.symbol_id.get().map(|s| format!("{s:?}"))
}

struct Mutations<'s, 'a> {
    semantic: &'s Semantic<'a>,
    invalid: HashSet<String>,
}
impl Mutations<'_, '_> {
    fn root(&mut self, expr: &Expression<'_>) {
        match expr {
            Expression::Identifier(id) => {
                if let Some(key) = symbol(self.semantic, id) {
                    self.invalid.insert(key);
                }
            }
            Expression::StaticMemberExpression(m) => self.root(&m.object),
            Expression::ComputedMemberExpression(m) => self.root(&m.object),
            _ => {}
        }
    }
}
impl<'a> Visit<'a> for Mutations<'_, 'a> {
    fn visit_assignment_expression(&mut self, node: &AssignmentExpression<'a>) {
        match &node.left {
            AssignmentTarget::StaticMemberExpression(m) => self.root(&m.object),
            AssignmentTarget::ComputedMemberExpression(m) => self.root(&m.object),
            _ => {}
        }
        walk::walk_assignment_expression(self, node);
    }
    fn visit_identifier_reference(&mut self, node: &IdentifierReference<'a>) {
        if let Some(r) = node.reference_id.get() {
            let reference = self.semantic.scoping().get_reference(r);
            if reference.is_write()
                && let Some(s) = reference.symbol_id()
            {
                self.invalid.insert(format!("{s:?}"));
            }
        }
    }
}

struct Analyzer<'s, 'a> {
    artifact: &'s Artifact,
    text: &'s str,
    options: &'s ScanOptions,
    semantic: &'s Semantic<'a>,
    values: HashMap<String, Value>,
    invalid: HashSet<String>,
    xhr_endpoints: HashMap<String, usize>,
    out: &'s mut Analysis,
}

impl Analyzer<'_, '_> {
    fn ev(&self, span: Span) -> Evidence {
        evidence(
            self.artifact,
            self.text,
            span.start as usize,
            span.end as usize,
            "ast_semantic",
        )
    }
    fn key(&self, key: &PropertyKey<'_>) -> Option<String> {
        match key {
            PropertyKey::StaticIdentifier(i) => Some(i.name.to_string()),
            PropertyKey::StringLiteral(s) => Some(s.value.to_string()),
            _ => key
                .as_expression()
                .map(|e| self.eval(e, 0).text())
                .filter(|(_, k)| *k)
                .map(|(s, _)| s),
        }
    }
    fn eval(&self, expr: &Expression<'_>, depth: usize) -> Value {
        if depth > 24 {
            return Value::Unknown("depth_limit".into());
        }
        let next = depth + 1;
        match expr {
            Expression::StringLiteral(s) => Value::Text(s.value.to_string(), true),
            Expression::NumericLiteral(s) => Value::Number(s.value),
            Expression::BooleanLiteral(s) => Value::Text(s.value.to_string(), true),
            Expression::ImportMeta(_) => Value::Object(BTreeMap::from([(
                "url".into(),
                Value::Text(self.artifact.location.clone(), true),
            )])),
            Expression::Identifier(id) => {
                if let Some(key) = symbol(self.semantic, id) {
                    if self.invalid.contains(&key) {
                        return Value::Unknown(id.name.to_string());
                    }
                    self.values
                        .get(&key)
                        .cloned()
                        .unwrap_or(Value::Unknown(id.name.to_string()))
                } else {
                    match id.name.as_str() {
                        "axios" => Value::Client(String::new(), BTreeMap::new()),
                        "fetch" | "Request" | "XMLHttpRequest" | "URL" | "URLSearchParams"
                        | "window" | "globalThis" | "self" => Value::Builtin(id.name.to_string()),
                        _ => Value::Unknown(id.name.to_string()),
                    }
                }
            }
            Expression::TemplateLiteral(t) => {
                let mut text = String::new();
                let mut known = true;
                for (i, q) in t.quasis.iter().enumerate() {
                    text.push_str(
                        q.value
                            .cooked
                            .as_ref()
                            .map_or(q.value.raw.as_str(), |s| s.as_str()),
                    );
                    if let Some(e) = t.expressions.get(i) {
                        let (v, k) = self.eval(e, next).text();
                        text.push_str(&v);
                        known &= k;
                    }
                }
                Value::Text(text, known)
            }
            Expression::BinaryExpression(b) if b.operator.as_str() == "+" => {
                let left = self.eval(&b.left, next);
                let right = self.eval(&b.right, next);
                if let (Value::Number(l), Value::Number(r)) = (&left, &right) {
                    return Value::Number(l + r);
                }
                let (l, lk) = left.text();
                let (r, rk) = right.text();
                Value::Text(format!("{l}{r}"), lk && rk)
            }
            Expression::ObjectExpression(o) => {
                let mut map = BTreeMap::new();
                for p in &o.properties {
                    match p {
                        ObjectPropertyKind::ObjectProperty(p) if !p.method => {
                            if let Some(k) = self.key(&p.key) {
                                map.insert(k, self.eval(&p.value, next));
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(s) => {
                            if let Value::Object(other) = self.eval(&s.argument, next) {
                                map.extend(other);
                            }
                        }
                        _ => {}
                    }
                }
                Value::Object(map)
            }
            Expression::StaticMemberExpression(m) => {
                self.eval(&m.object, next).prop(m.property.name.as_str())
            }
            Expression::ComputedMemberExpression(m) => {
                let (key, known) = self.eval(&m.expression, next).text();
                if known {
                    self.eval(&m.object, next).prop(&key)
                } else {
                    Value::Unknown(key)
                }
            }
            Expression::ParenthesizedExpression(p) => self.eval(&p.expression, next),
            Expression::TSAsExpression(p) => self.eval(&p.expression, next),
            Expression::TSSatisfiesExpression(p) => self.eval(&p.expression, next),
            Expression::TSNonNullExpression(p) => self.eval(&p.expression, next),
            Expression::ConditionalExpression(c) => {
                let (l, _) = self.eval(&c.consequent, next).text();
                let (r, _) = self.eval(&c.alternate, next).text();
                if l == r {
                    self.eval(&c.consequent, next)
                } else {
                    Value::Text(format!("${{{l}|{r}}}"), false)
                }
            }
            Expression::CallExpression(c) => match self.eval(&c.callee, next) {
                Value::Method(object, name)
                    if name == "create" && matches!(*object, Value::Client(..)) =>
                {
                    let Value::Client(_, defaults) = *object else {
                        unreachable!()
                    };
                    let cfg = merge_config(defaults, self.arg(&c.arguments, 0, next));
                    let base = match &cfg {
                        Value::Object(map) if !map.contains_key("baseURL") => String::new(),
                        _ => cfg.prop("baseURL").text().0,
                    };
                    let defaults = if let Value::Object(map) = cfg {
                        map
                    } else {
                        BTreeMap::new()
                    };
                    Value::Client(base, defaults)
                }
                Value::Builtin(name) if name == "require" => Value::Unknown("require".into()),
                _ if matches!(&c.callee, Expression::Identifier(i) if i.name == "require" && symbol(self.semantic,i).is_none()) =>
                {
                    let (module, known) = self.arg(&c.arguments, 0, next).text();
                    if known && module == "axios" {
                        Value::Client(String::new(), BTreeMap::new())
                    } else {
                        Value::Unknown(module)
                    }
                }
                _ => Value::Unknown("call".into()),
            },
            Expression::NewExpression(c) => match self.eval(&c.callee, next) {
                Value::Builtin(name) if name == "Request" => Value::Request(
                    Box::new(self.arg(&c.arguments, 0, next)),
                    Box::new(self.arg(&c.arguments, 1, next)),
                ),
                Value::Builtin(name) if name == "XMLHttpRequest" => {
                    Value::Xhr(format!("{}", c.span.start))
                }
                Value::Builtin(name) if name == "URLSearchParams" => {
                    self.arg(&c.arguments, 0, next)
                }
                Value::Builtin(name) if name == "URL" => {
                    let (path, pknown) = self.arg(&c.arguments, 0, next).text();
                    let (base, bknown) = self.arg(&c.arguments, 1, next).text();
                    if pknown && bknown {
                        url::Url::parse(&base)
                            .ok()
                            .and_then(|b| b.join(&path).ok())
                            .map(|u| Value::Text(u.to_string(), true))
                            .unwrap_or(Value::Unknown(path))
                    } else {
                        Value::Unknown(path)
                    }
                }
                _ => Value::Unknown("new".into()),
            },
            _ => Value::Unknown("expression".into()),
        }
    }
    fn arg(&self, args: &oxc_allocator::Vec<'_, Argument<'_>>, i: usize, depth: usize) -> Value {
        args.get(i)
            .and_then(|a| a.as_expression())
            .map_or(Value::Object(BTreeMap::new()), |e| self.eval(e, depth))
    }
    fn bind(&mut self, pattern: &BindingPattern<'_>, value: Value) {
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                if let Some(key) = normalized_binding(id) {
                    self.values.insert(key, value);
                }
            }
            BindingPattern::ObjectPattern(o) => {
                for p in &o.properties {
                    if let Some(key) = self.key(&p.key) {
                        self.bind(&p.value, value.prop(&key));
                    }
                }
            }
            BindingPattern::AssignmentPattern(a) => self.bind(&a.left, value),
            _ => {}
        }
    }
    fn endpoint(
        &mut self,
        client: &str,
        method: String,
        value: Value,
        cfg: Value,
        span: Span,
        base: &str,
    ) {
        if !self.options.enabled("endpoints") {
            return;
        }
        let (mut url, known) = value.text();
        let override_base = match &cfg {
            Value::Object(map) => map.get("baseURL").map(|v| v.text().0),
            _ => None,
        };
        let base = override_base.as_deref().unwrap_or(base);
        if !base.is_empty()
            && !url.starts_with("http://")
            && !url.starts_with("https://")
            && !url.starts_with("//")
        {
            url = format!(
                "{}/{}",
                base.trim_end_matches('/'),
                url.trim_start_matches('/')
            );
        }
        let query_params = match cfg.prop("params") {
            Value::Object(map) => map.keys().cloned().collect(),
            _ => vec![],
        };
        let method_known = !method.contains("${");
        self.out.endpoints.push(Endpoint {
            method,
            url,
            client: client.into(),
            confidence: if known && !base.contains("${") && method_known {
                "high"
            } else {
                "low"
            }
            .into(),
            query_params,
            headers: cfg.prop("headers").keys(),
            body_params: cfg.prop("body").keys(),
            observed: false,
            evidence: vec![self.ev(span)],
            request_ids: vec![],
        });
    }
}

impl<'a> Visit<'a> for Analyzer<'_, 'a> {
    fn visit_import_declaration(&mut self, node: &ImportDeclaration<'a>) {
        self.out.modules.push(ModuleReference {
            artifact_id: self.artifact.id.clone(),
            specifier: node.source.value.to_string(),
            kind: "import".into(),
        });
        if node.source.value == "axios"
            && let Some(specifiers) = &node.specifiers
        {
            for s in specifiers {
                let id = match s {
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => Some(&s.local),
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => Some(&s.local),
                    ImportDeclarationSpecifier::ImportSpecifier(s)
                        if s.imported.name() == "default" =>
                    {
                        Some(&s.local)
                    }
                    _ => None,
                };
                if let Some(id) = id
                    && let Some(key) = normalized_binding(id)
                {
                    self.values
                        .insert(key, Value::Client(String::new(), BTreeMap::new()));
                }
            }
        }
        walk::walk_import_declaration(self, node);
    }
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        if let Some(init) = &node.init {
            let value = self.eval(init, 0);
            if self.options.enabled("secrets")
                && let BindingPattern::BindingIdentifier(id) = &node.id
                && let Value::Text(s, true) = &value
            {
                contextual_secret(
                    id.name.as_str(),
                    s,
                    self.ev(init.span()),
                    &mut self.out.findings,
                );
            }
            self.bind(&node.id, value);
        }
        walk::walk_variable_declarator(self, node);
    }
    fn visit_object_property(&mut self, node: &ObjectProperty<'a>) {
        if self.options.enabled("secrets")
            && let Some(key) = self.key(&node.key)
            && let Value::Text(s, true) = self.eval(&node.value, 0)
        {
            contextual_secret(&key, &s, self.ev(node.value.span()), &mut self.out.findings);
        }
        walk::walk_object_property(self, node);
    }
    fn visit_call_expression(&mut self, node: &CallExpression<'a>) {
        let callee = self.eval(&node.callee, 0);
        let first = self.arg(&node.arguments, 0, 0);
        let second = self.arg(&node.arguments, 1, 0);
        match callee {
            Value::Builtin(name) if name == "fetch" => {
                let (url, cfg) = if let Value::Request(u, c) = first {
                    let cfg = if let Value::Object(defaults) = *c {
                        merge_config(defaults, second)
                    } else {
                        second
                    };
                    (*u, cfg)
                } else {
                    (first, second)
                };
                let method = http_method(&cfg);
                self.endpoint("fetch", method, url, cfg, node.span, "");
            }
            Value::Client(base, defaults) => {
                let (url, cfg) = if matches!(first, Value::Object(_)) {
                    (first.prop("url"), first)
                } else {
                    (first, second)
                };
                let cfg = merge_config(defaults, cfg);
                let method = http_method(&cfg);
                self.endpoint("axios", method, url, cfg, node.span, &base);
            }
            Value::Method(client, method) => match *client {
                Value::Client(base, defaults)
                    if [
                        "get", "delete", "head", "options", "post", "put", "patch", "request",
                    ]
                    .contains(&method.as_str()) =>
                {
                    let (url, cfg) = if method == "request" {
                        (first.prop("url"), first)
                    } else {
                        (
                            first,
                            if ["post", "put", "patch"].contains(&method.as_str()) {
                                self.arg(&node.arguments, 2, 0)
                            } else {
                                second.clone()
                            },
                        )
                    };
                    let mut cfg = merge_config(defaults, cfg);
                    if ["post", "put", "patch"].contains(&method.as_str())
                        && let Value::Object(ref mut map) = cfg
                    {
                        map.insert("body".into(), second);
                    }
                    let m = if method == "request" {
                        http_method(&cfg)
                    } else {
                        method
                    };
                    self.endpoint("axios", m.to_uppercase(), url, cfg, node.span, &base);
                }
                Value::Xhr(id) if method == "open" => {
                    let index = self.out.endpoints.len();
                    self.endpoint(
                        "xhr",
                        first.text().0.to_uppercase(),
                        second,
                        Value::Object(BTreeMap::new()),
                        node.span,
                        "",
                    );
                    if self.out.endpoints.len() > index {
                        self.xhr_endpoints.insert(id, index);
                    }
                }
                Value::Xhr(id) if method == "setRequestHeader" => {
                    let (header, known) = first.text();
                    if known && let Some(index) = self.xhr_endpoints.get(&id) {
                        self.out.endpoints[*index].headers.push(header);
                    }
                }
                Value::Xhr(id) if method == "send" => {
                    if let Some(index) = self.xhr_endpoints.get(&id) {
                        self.out.endpoints[*index].body_params = first.keys();
                    }
                }
                _ => {}
            },
            _ => {}
        }
        if matches!(&node.callee, Expression::Identifier(i) if i.name == "require" && symbol(self.semantic,i).is_none())
        {
            let (s, k) = self.arg(&node.arguments, 0, 0).text();
            if k {
                self.out.modules.push(ModuleReference {
                    artifact_id: self.artifact.id.clone(),
                    specifier: s,
                    kind: "require".into(),
                });
            }
        }
        walk::walk_call_expression(self, node);
    }
    fn visit_import_expression(&mut self, node: &ImportExpression<'a>) {
        let (s, k) = self.eval(&node.source, 0).text();
        if k {
            self.out.modules.push(ModuleReference {
                artifact_id: self.artifact.id.clone(),
                specifier: s,
                kind: "dynamic_import".into(),
            });
        }
        walk::walk_import_expression(self, node);
    }
    fn visit_export_all_declaration(&mut self, node: &ExportAllDeclaration<'a>) {
        self.out.modules.push(ModuleReference {
            artifact_id: self.artifact.id.clone(),
            specifier: node.source.value.to_string(),
            kind: "export".into(),
        });
        walk::walk_export_all_declaration(self, node);
    }
    fn visit_export_from_declaration(&mut self, node: &ExportFromDeclaration<'a>) {
        self.out.modules.push(ModuleReference {
            artifact_id: self.artifact.id.clone(),
            specifier: node.source.value.to_string(),
            kind: "export".into(),
        });
        walk::walk_export_from_declaration(self, node);
    }
    fn visit_new_expression(&mut self, node: &NewExpression<'a>) {
        let specifier = match self.eval(&node.callee, 0) {
            Value::Builtin(name) if name == "URL" => {
                let (path, known) = self.arg(&node.arguments, 0, 0).text();
                if known
                    && path.split(['?', '#']).next().is_some_and(|p| {
                        [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]
                            .iter()
                            .any(|ext| p.ends_with(ext))
                    })
                {
                    Some((path, "asset_url"))
                } else {
                    None
                }
            }
            _ if matches!(&node.callee,Expression::Identifier(i) if ["Worker","SharedWorker"].contains(&i.name.as_str()) && symbol(self.semantic,i).is_none()) =>
            {
                let (path, known) = self.arg(&node.arguments, 0, 0).text();
                if known { Some((path, "worker")) } else { None }
            }
            _ => None,
        };
        if let Some((specifier, kind)) = specifier {
            self.out.modules.push(ModuleReference {
                artifact_id: self.artifact.id.clone(),
                specifier,
                kind: kind.into(),
            });
        }
        walk::walk_new_expression(self, node);
    }
}

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s\"'<>`\\)]+"#).unwrap());
static SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)").unwrap()
});
static RULES: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    [
    ("aws_access_key",r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("github_token",r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b"),
    ("google_api_key",r"\bAIza[A-Za-z0-9_-]{35}\b"),
    ("slack_token",r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b"),
    ("jwt",r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ("private_key",r"(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ("bearer_token",r"\bBearer [A-Za-z0-9._~+/-]{16,}=*"),
].into_iter().map(|(n,p)| (n,Regex::new(p).unwrap())).collect()
});

fn push_finding(
    rule: &str,
    category: &str,
    confidence: &str,
    severity: &str,
    value: &str,
    e: Evidence,
    out: &mut Vec<Finding>,
) {
    out.push(Finding {
        id: digest(format!("{rule}\0{value}")),
        rule: rule.into(),
        category: category.into(),
        confidence: confidence.into(),
        severity: severity.into(),
        value: value.into(),
        evidence: vec![e],
    });
}
pub fn scan_patterns(text: &str, artifact: &Artifact, method: &str, out: &mut Vec<Finding>) {
    for (rule, re) in RULES.iter() {
        for m in re.find_iter(text) {
            if !placeholder(m.as_str()) {
                push_finding(
                    rule,
                    "secret",
                    "high",
                    if *rule == "google_api_key" || *rule == "jwt" {
                        "info"
                    } else {
                        "high"
                    },
                    m.as_str(),
                    evidence(artifact, text, m.start(), m.end(), method),
                    out,
                );
            }
        }
    }
}
fn scan_urls(text: &str, artifact: &Artifact, method: &str, out: &mut Vec<Finding>) {
    for m in URL_RE.find_iter(text) {
        push_finding(
            "url_literal",
            "url",
            "high",
            "info",
            m.as_str(),
            evidence(artifact, text, m.start(), m.end(), method),
            out,
        );
    }
}
fn placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("your_")
        || lower.contains("your-")
        || value.chars().all(|c| c == 'x' || c == 'X' || c == '*')
}
fn entropy(value: &str) -> f64 {
    let mut counts = HashMap::new();
    for b in value.bytes() {
        *counts.entry(b).or_insert(0usize) += 1;
    }
    counts
        .values()
        .map(|n| {
            let p = *n as f64 / value.len().max(1) as f64;
            -p * p.log2()
        })
        .sum()
}
fn contextual_secret(key: &str, value: &str, e: Evidence, out: &mut Vec<Finding>) {
    if SECRET_KEY.is_match(key)
        && value.len() >= 8
        && !placeholder(value)
        && !value.contains("${")
        && !value.starts_with("http")
    {
        let confidence = if value.len() >= 16 && entropy(value) >= 3.2 {
            "medium"
        } else {
            "low"
        };
        push_finding(
            "contextual_secret",
            "secret",
            confidence,
            "medium",
            value,
            e,
            out,
        );
    }
}
fn json_secrets(
    value: &serde_json::Value,
    key: &str,
    artifact: &Artifact,
    text: &str,
    out: &mut Vec<Finding>,
) {
    match value {
        serde_json::Value::Object(o) => {
            for (k, v) in o {
                json_secrets(v, k, artifact, text, out);
            }
        }
        serde_json::Value::Array(a) => {
            for v in a {
                json_secrets(v, key, artifact, text, out);
            }
        }
        serde_json::Value::String(s) => {
            let start = text
                .find(&serde_json::to_string(s).unwrap_or_default())
                .unwrap_or(0);
            contextual_secret(
                key,
                s,
                evidence(artifact, text, start, start + s.len() + 2, "json_context"),
                out,
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(code: &str) -> Analysis {
        analyze(
            &Artifact::new(
                "test.ts".into(),
                ArtifactKind::Script,
                code.as_bytes().to_vec(),
                "test".into(),
            ),
            &ScanOptions::default(),
        )
    }
    #[test]
    fn correlates_clients_and_constants() {
        let a = run(
            r#"import http from 'axios'; const cfg = {baseURL:'https://api.test/v1'}; const api = http.create(cfg); const id = '42'; api.get(`/users/${id}`, {params:{page:1}, headers:{Authorization:'x'}}); fetch('/health'); const xhr = new XMLHttpRequest(); xhr.open('POST','/xhr');"#,
        );
        assert!(a.diagnostics.is_empty(), "{:?}", a.diagnostics);
        assert!(
            a.endpoints
                .iter()
                .any(|e| e.url == "https://api.test/v1/users/42" && e.query_params == ["page"])
        );
        assert!(
            a.endpoints
                .iter()
                .any(|e| e.url == "/xhr" && e.method == "POST")
        );
    }
    #[test]
    fn respects_shadowing_and_writes() {
        let a = run(
            "function f(fetch) { fetch('/fake'); } const thing = {}; thing.get('/fake'); let p='/old'; p='/new'; fetch(p);",
        );
        assert_eq!(a.endpoints.len(), 1);
        assert_eq!(a.endpoints[0].url, "${p}");
    }
    #[test]
    fn destructuring_and_request() {
        let a = run(
            "const {path:p} = {path:'/users'}; const r = new Request(p,{method:'POST',body:{name:'x'}}); fetch(r);",
        );
        assert_eq!(a.endpoints[0].url, "/users");
        assert_eq!(a.endpoints[0].method, "POST");
        assert_eq!(a.endpoints[0].body_params, ["name"]);
    }
    #[test]
    fn defaults_request_overrides_xhr_and_worker_references() {
        let a = run(
            "import a from 'axios';const c=a.create({baseURL:'https://api.test/v1',headers:{Authorization:'x'}});c.get('/users',{headers:{Accept:'json'},baseURL:'https://other.test'});const xhr=new XMLHttpRequest();xhr.open('POST','/x');xhr.setRequestHeader('X-Token','x');xhr.send({name:'x'});fetch(new Request('/req',{method:'POST'}),{method:'PUT'});new Worker(new URL('./worker.js',import.meta.url));window.fetch('/number/'+(1+2));",
        );
        assert!(a.diagnostics.is_empty(), "{:?}", a.diagnostics);
        assert!(a.endpoints.iter().any(
            |e| e.url == "https://other.test/users" && e.headers == ["Accept", "Authorization"]
        ));
        assert!(
            a.endpoints
                .iter()
                .any(|e| e.url == "/x" && e.headers == ["X-Token"] && e.body_params == ["name"])
        );
        assert!(
            a.endpoints
                .iter()
                .any(|e| e.url == "/req" && e.method == "PUT")
        );
        assert!(a.endpoints.iter().any(|e| e.url == "/number/3"));
        assert!(a.modules.iter().any(|m| m.specifier == "./worker.js"));
    }
    #[test]
    fn long_lines_comments_and_unicode() {
        let a = run(&format!(
            "const pad='{}'; /* 🔥 TODO admin */ const api_key='Abc9Xyz1234567890abcdef';",
            "x".repeat(1000)
        ));
        assert_eq!(a.comments.len(), 1);
        assert!(a.findings.iter().any(|f| f.rule == "contextual_secret"));
        let e = evidence(
            &Artifact::new("x".into(), ArtifactKind::Script, vec![], "test".into()),
            "🔥x",
            4,
            5,
            "test",
        );
        assert_eq!(e.column, 3);
    }
}
