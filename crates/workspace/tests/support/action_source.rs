//! Syntax inventory, never a substitute for runtime authorization or type checking.
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use syn::{
    parse::Parser,
    punctuated::Punctuated,
    visit::{self, Visit},
    Attribute, Item, Meta, Token,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub owner: String,
    pub name: String,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub file: String,
    pub callable: String,
    pub capability: String,
    pub expression: String,
    pub count: usize,
}

fn capability_name(ident: &syn::Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_owned()
}
fn configuration(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let values = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .ok()?;
            let values: Vec<_> = values.iter().map(configuration).collect();
            if list.path.is_ident("not") && values.len() == 1 {
                values[0].map(|v| !v)
            } else if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|v| *v == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|v| *v == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}
fn production(attrs: &[Attribute]) -> bool {
    !attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<Meta>()
                    .ok()
                    .as_ref()
                    .and_then(configuration)
                    == Some(false))
    })
}
fn conditional_path(meta: &Meta) -> bool {
    let Meta::List(list) = meta else {
        return false;
    };
    if !list.path.is_ident("cfg_attr") {
        return false;
    }
    let Ok(values) = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
    else {
        return true;
    };
    values
        .iter()
        .skip(1)
        .any(|meta| meta.path().is_ident("path") || conditional_path(meta))
}
fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(v) => &v.attrs,
        Item::Enum(v) => &v.attrs,
        Item::ExternCrate(v) => &v.attrs,
        Item::Fn(v) => &v.attrs,
        Item::ForeignMod(v) => &v.attrs,
        Item::Impl(v) => &v.attrs,
        Item::Macro(v) => &v.attrs,
        Item::Mod(v) => &v.attrs,
        Item::Static(v) => &v.attrs,
        Item::Struct(v) => &v.attrs,
        Item::Trait(v) => &v.attrs,
        Item::TraitAlias(v) => &v.attrs,
        Item::Type(v) => &v.attrs,
        Item::Union(v) => &v.attrs,
        Item::Use(v) => &v.attrs,
        _ => &[],
    }
}

pub struct Scanner {
    root: PathBuf,
    visited: BTreeSet<PathBuf>,
    pub api: BTreeSet<Api>,
    sites: BTreeMap<(String, String, String, String), usize>,
    capabilities: BTreeSet<String>,
}
impl Scanner {
    pub fn new(root: &Path, capabilities: BTreeSet<String>) -> Self {
        Self {
            root: root.canonicalize().expect("source root must exist"),
            visited: BTreeSet::new(),
            api: BTreeSet::new(),
            sites: BTreeMap::new(),
            capabilities,
        }
    }
    pub fn scan(&mut self, path: &Path) -> Result<(), String> {
        self.scan_file(path, true)
    }
    fn scan_file(&mut self, path: &Path, children_in_parent: bool) -> Result<(), String> {
        let path = path
            .canonicalize()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !path.starts_with(&self.root) {
            return Err(format!("module escaped source root: {}", path.display()));
        }
        if !self.visited.insert(path.clone()) {
            return Ok(());
        }
        let source = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let file = syn::parse_file(&source).map_err(|e| format!("{}: {e}", path.display()))?;
        if !production(&file.attrs) {
            return Ok(());
        }
        let parent = path.parent().unwrap();
        let stem = path.file_stem().unwrap().to_string_lossy();
        // Crate roots and explicit #[path] modules resolve children beside
        // their source, regardless of its filename. Ordinary foo.rs modules
        // resolve children under foo/, including ones named lib.rs or main.rs.
        let module_dir = if children_in_parent || stem == "mod" {
            parent.to_owned()
        } else {
            parent.join(stem.as_ref())
        };
        self.items(&path, &module_dir, parent, &[], &file.items)
    }
    fn items(
        &mut self,
        file: &Path,
        module_dir: &Path,
        attr_dir: &Path,
        scope: &[String],
        items: &[Item],
    ) -> Result<(), String> {
        for item in items {
            if !production(item_attrs(item)) {
                continue;
            }
            if let Item::Mod(module) = item {
                if module.attrs.iter().any(|attr| conditional_path(&attr.meta)) {
                    return Err(format!(
                        "conditional module path needs explicit source coverage: {}",
                        file.display()
                    ));
                }
                let mut nested = scope.to_vec();
                nested.push(module.ident.to_string());
                if let Some((_, items)) = &module.content {
                    let dir = module_dir.join(module.ident.to_string());
                    self.items(file, &dir, &dir, &nested, items)?;
                } else {
                    let explicit = module.attrs.iter().find(|a| a.path().is_ident("path"));
                    let target = if let Some(attr) = explicit {
                        let Meta::NameValue(value) = &attr.meta else {
                            return Err("unsupported module path".into());
                        };
                        let syn::Expr::Lit(literal) = &value.value else {
                            return Err("nonliteral module path".into());
                        };
                        let syn::Lit::Str(path) = &literal.lit else {
                            return Err("non-string module path".into());
                        };
                        attr_dir.join(path.value())
                    } else {
                        let flat = module_dir.join(format!("{}.rs", module.ident));
                        let nested = module_dir.join(module.ident.to_string()).join("mod.rs");
                        match (flat.is_file(), nested.is_file()) {
                            (true, false) => flat,
                            (false, true) => nested,
                            _ => {
                                return Err(format!(
                                    "missing or ambiguous module {} in {}",
                                    module.ident,
                                    file.display()
                                ))
                            }
                        }
                    };
                    self.scan_file(&target, explicit.is_some())?;
                }
            } else {
                if let Item::Trait(item) = item {
                    if file.ends_with("crates/workspace/src/lib.rs")
                        && ["Workspace", "ChatWorkspace", "WorkspaceProvider"]
                            .iter()
                            .any(|name| item.ident == *name)
                    {
                        for member in &item.items {
                            if let syn::TraitItem::Fn(method) = member {
                                if production(&method.attrs) {
                                    self.api.insert(Api {
                                        owner: item.ident.to_string(),
                                        name: capability_name(&method.sig.ident),
                                        signature: method.sig.to_token_stream().to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                let relative = file
                    .strip_prefix(&self.root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                Calls {
                    file: &relative,
                    scope: scope.to_vec(),
                    scanner: self,
                }
                .visit_item(item);
            }
        }
        Ok(())
    }
    pub fn sites(&self) -> Vec<Site> {
        self.sites
            .iter()
            .map(|((file, callable, capability, expression), count)| Site {
                file: file.clone(),
                callable: callable.clone(),
                capability: capability.clone(),
                expression: expression.clone(),
                count: *count,
            })
            .collect()
    }
}
struct Calls<'a> {
    file: &'a str,
    scope: Vec<String>,
    scanner: &'a mut Scanner,
}
impl Calls<'_> {
    fn record(&mut self, capability: &str, expression: impl ToTokens) {
        if self.scanner.capabilities.contains(capability) {
            *self
                .scanner
                .sites
                .entry((
                    self.file.into(),
                    self.scope.join("::"),
                    capability.into(),
                    expression.to_token_stream().to_string(),
                ))
                .or_default() += 1;
        }
    }
}
impl<'ast> Visit<'ast> for Calls<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if production(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.scope.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.scope.pop();
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let name = format!(
            "impl {} for {}",
            item.trait_
                .as_ref()
                .map(|(_, p, _)| p.to_token_stream().to_string())
                .unwrap_or_else(|| "inherent".into()),
            item.self_ty.to_token_stream()
        );
        self.scope.push(name);
        visit::visit_item_impl(self, item);
        self.scope.pop();
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !production(&item.attrs) {
            return;
        }
        self.scope.push(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.scope.pop();
    }
    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.scope.push(format!("trait {}", item.ident));
        visit::visit_item_trait(self, item);
        self.scope.pop();
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if !production(&item.attrs) {
            return;
        }
        self.scope.push(item.sig.ident.to_string());
        visit::visit_trait_item_fn(self, item);
        self.scope.pop();
    }
    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        if !production(&expr.attrs) {
            return;
        }
        self.record(&capability_name(&expr.method), expr);
        visit::visit_expr_method_call(self, expr);
    }
    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if !production(&expr.attrs) {
            return;
        }
        if let syn::Expr::Path(path) = expr.func.as_ref() {
            if let Some(last) = path.path.segments.last() {
                if self
                    .scanner
                    .capabilities
                    .contains(&capability_name(&last.ident))
                {
                    self.record(&capability_name(&last.ident), expr);
                    for argument in &expr.args {
                        self.visit_expr(argument);
                    }
                    return;
                }
            }
        }
        visit::visit_expr_call(self, expr);
    }
    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        if !production(&expr.attrs) {
            return;
        }
        // A bare local variable named `export` is not a function reference.
        // Unqualified aliases retain the inventory's explicit resolution gap.
        if expr.path.segments.len() > 1 || expr.qself.is_some() {
            if let Some(last) = expr.path.segments.last() {
                self.record(&capability_name(&last.ident), expr);
            }
        }
        visit::visit_expr_path(self, expr);
    }
    fn visit_expr_block(&mut self, expr: &'ast syn::ExprBlock) {
        if production(&expr.attrs) {
            visit::visit_expr_block(self, expr);
        }
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if production(&local.attrs) {
            visit::visit_local(self, local);
        }
    }
}
