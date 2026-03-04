use crate::contract::{CheckStatus, QueryMode};
use crate::verification::helpers::resolve_path;
use crate::verification::{AstCache, RawResult};
use tree_sitter::StreamingIterator;

pub(crate) async fn run_ast_query(
    path: &str,
    language_str: &str,
    query_str: &str,
    mode: &QueryMode,
    working_dir: Option<&str>,
    ast_cache: &mut AstCache,
) -> RawResult {
    // 1. Resolve Language
    let language =
        match language_str.to_lowercase().as_str() {
            "python" => tree_sitter_python::LANGUAGE.into(),
            "javascript" | "js" => tree_sitter_javascript::LANGUAGE.into(),
            "typescript" | "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
            "html" => tree_sitter_html::LANGUAGE.into(),
            "css" => tree_sitter_css::LANGUAGE.into(),
            _ => return RawResult {
                status: CheckStatus::Failed,
                message: format!("Unsupported language for AstQuery: {language_str}"),
                details: Some(
                    "Currently supported languages: python, javascript, typescript, tsx, html, css"
                        .into(),
                ),
            },
        };

    // 2. Expand Macros or use raw query
    let expanded_query = if query_str.starts_with("macro:") {
        expand_ast_macro(query_str, language_str)
    } else {
        Ok(query_str.to_string())
    };

    let expanded_query = match expanded_query {
        Ok(q) => q,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Failed to expand AST macro: {e}"),
                details: None,
            }
        }
    };

    // 3. Parse Query
    let query = match tree_sitter::Query::new(&language, &expanded_query) {
        Ok(q) => q,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Invalid tree-sitter query: {e}"),
                details: Some(expanded_query),
            }
        }
    };

    // 4. Get File Content & Syntax Tree
    let effective_path = resolve_path(path, working_dir);
    let content = match std::fs::read_to_string(&effective_path) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read file '{path}': {e}"),
                details: None,
            };
            crate::verification::helpers::add_working_dir_hint_if_needed(
                &mut result,
                path,
                working_dir,
            );
            return result;
        }
    };

    let tree = if let Some(t) = ast_cache.get(path) {
        t.clone()
    } else {
        let mut parser = tree_sitter::Parser::new();
        if let Err(e) = parser.set_language(&language) {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Failed to set language in parser: {e}"),
                details: None,
            };
        }
        let parsed_tree = match parser.parse(&content, None) {
            Some(t) => t,
            None => {
                return RawResult {
                    status: CheckStatus::Failed,
                    message: format!("Failed to parse file '{path}' into AST"),
                    details: None,
                }
            }
        };
        ast_cache.insert(path.to_string(), parsed_tree.clone());
        parsed_tree
    };

    // 5. Execute Query
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut match_count = 0;

    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while matches.next().is_some() {
        match_count += 1;
    }

    let has_matches = match_count > 0;

    // 6. Evaluate Result based on Mode
    let passed = match mode {
        QueryMode::Required => has_matches,
        QueryMode::Forbidden => !has_matches,
    };

    let mut details = format!("Query:\n{expanded_query}\n");
    if has_matches {
        details.push_str(&format!("\nFound {} match(es) in '{path}'", match_count));
    } else {
        details.push_str(&format!("\nNo matches found in '{path}'"));
    }

    RawResult {
        status: if passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        message: if passed {
            format!("AstQuery passed for {path} (mode: {:?})", mode)
        } else {
            format!("AstQuery failed for {path} (mode: {:?})", mode)
        },
        details: Some(details),
    }
}

pub(crate) fn expand_ast_macro(macro_str: &str, language: &str) -> Result<String, String> {
    let parts: Vec<&str> = macro_str.split(':').collect();
    if parts.len() < 2 {
        return Err("Invalid macro format. Expected macro:<name>[:<args>]".into());
    }

    let macro_name = parts[1];
    let args = &parts[2..];

    match (language.to_lowercase().as_str(), macro_name) {
        ("python", "function_exists") => {
            if args.is_empty() {
                return Err("function_exists requires a function name argument".into());
            }
            let fn_name = args[0];
            Ok(format!(
                "(function_definition name: (identifier) @name (#eq? @name \"{fn_name}\"))"
            ))
        }
        ("python", "class_exists") => {
            if args.is_empty() {
                return Err("class_exists requires a class name argument".into());
            }
            let class_name = args[0];
            Ok(format!(
                "(class_definition name: (identifier) @name (#eq? @name \"{class_name}\"))"
            ))
        }
        ("python", "imports_module") => {
            if args.is_empty() {
                return Err("imports_module requires a module name argument".into());
            }
            let module_name = args[0];
            Ok(format!(
                "(import_statement name: (dotted_name (identifier) @name (#eq? @name \"{module_name}\")))"
            ))
        }
        ("javascript" | "typescript" | "tsx", "export_exists") => {
            if args.is_empty() {
                return Err("export_exists requires a name argument".into());
            }
            let name = args[0];
            Ok(format!(
                "(export_statement [
                    (function_declaration name: (identifier) @name (#eq? @name \"{name}\"))
                    (lexical_declaration (variable_declarator name: (identifier) @name (#eq? @name \"{name}\")))
                    (class_declaration name: (identifier) @name (#eq? @name \"{name}\"))
                ])"
            ))
        }
        ("javascript" | "typescript" | "tsx", "react_component_exists") => {
            if args.is_empty() {
                return Err("react_component_exists requires a component name argument".into());
            }
            let name = args[0];
            Ok(format!(
                "[
                    (function_declaration name: (identifier) @name (#eq? @name \"{name}\"))
                    (lexical_declaration (variable_declarator name: (identifier) @name (#eq? @name \"{name}\")))
                ]"
            ))
        }
        ("html", "element_exists") => {
            if args.is_empty() {
                return Err(
                    "element_exists requires an element specifier (e.g., div.my-class)".into(),
                );
            }
            let spec = args[0];
            let mut tag = spec;
            let mut attr_query = String::new();

            if let Some(idx) = spec.find('.') {
                tag = &spec[..idx];
                let class_name = &spec[idx + 1..];
                attr_query = format!("(attribute (attribute_name) @attr_name (#eq? @attr_name \"class\") (quoted_attribute_value (attribute_value) @attr_val (#match? @attr_val \"(^|\\\\s){class_name}(\\\\s|$)\")))");
            } else if let Some(idx) = spec.find('#') {
                tag = &spec[..idx];
                let id_name = &spec[idx + 1..];
                attr_query = format!("(attribute (attribute_name) @attr_name (#eq? @attr_name \"id\") (quoted_attribute_value (attribute_value) @attr_val (#eq? @attr_val \"{id_name}\")))");
            }

            let tag_match = if tag.is_empty() || tag == "*" || tag == "_" {
                "(tag_name) @tag".to_string()
            } else {
                format!("(tag_name) @tag (#eq? @tag \"{tag}\")")
            };

            Ok(format!("(element (start_tag {tag_match} {attr_query}))"))
        }
        ("css", "selector_exists") => {
            if args.is_empty() {
                return Err("selector_exists requires a selector argument".into());
            }
            let selector = args[0];
            if let Some(class_name) = selector.strip_prefix('.') {
                Ok(format!(
                    "(class_selector (class_name) @name (#eq? @name \"{class_name}\"))"
                ))
            } else if let Some(id_name) = selector.strip_prefix('#') {
                Ok(format!(
                    "(id_selector (id_name) @name (#eq? @name \"{id_name}\"))"
                ))
            } else {
                Ok(format!("(tag_name) @name (#eq? @name \"{selector}\")"))
            }
        }
        _ => Err(format!(
            "Unknown macro '{macro_name}' for language '{language}'"
        )),
    }
}
