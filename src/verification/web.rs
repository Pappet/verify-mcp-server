use crate::contract::CheckStatus;
use crate::verification::command::execute_command;
use crate::verification::helpers::{add_working_dir_hint_if_needed, resolve_path, shell_escape, truncate};
use crate::verification::RawResult;
use tree_sitter::StreamingIterator;

pub(crate) async fn check_typescript_type_check(
    paths: &[String],
    working_dir: Option<&str>,
    timeout_secs: u64,
) -> RawResult {
    let mut cmd_str = String::from("npx tsc --noEmit");
    for p in paths {
        cmd_str.push(' ');
        cmd_str.push_str(&shell_escape(p));
    }
    
    match execute_command(&cmd_str, working_dir, timeout_secs, None, true).await {
        Ok((code, stdout, stderr)) => {
            let passed = code == 0;
            let err_count = stdout.matches("error TS").count();
            let warn_count = stdout.matches("warning TS").count();
            
            let message = if passed {
                format!("TypeScript types passed ({} warnings)", warn_count)
            } else {
                format!("TypeScript types failed with {} errors", err_count)
            };
            
            let combined = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
            RawResult {
                status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                message,
                details: Some(truncate(&combined, 4000)),
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("Command execution error: {e}"),
            details: None,
        }
    }
}

pub(crate) async fn check_jest_vitest_result(
    test_path: &str,
    min_passed: Option<usize>,
    max_failures: Option<usize>,
    max_skipped: Option<usize>,
    working_dir: Option<&str>,
    timeout_secs: u64,
) -> RawResult {
    let is_vitest = test_path.contains("vitest");
    let base_cmd = if is_vitest {
        "npx vitest --reporter=json --run"
    } else {
        "npx jest --json"
    };
    
    let cmd_str = format!("{base_cmd} {}", shell_escape(test_path));
    
    match execute_command(&cmd_str, working_dir, timeout_secs, None, true).await {
        Ok((code, stdout, _stderr)) => {
            let start_idx = stdout.find('{').unwrap_or(0);
            let end_idx = stdout.rfind('}').map(|i| i + 1).unwrap_or(stdout.len());
            let json_str = if start_idx < end_idx { &stdout[start_idx..end_idx] } else { "" };
            
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_str);
            if let Ok(json) = parsed {
                let num_passed = json["numPassedTests"].as_u64().unwrap_or(0) as usize;
                let num_failed = json["numFailedTests"].as_u64().unwrap_or(0) as usize;
                let num_pending = json["numPendingTests"].as_u64().unwrap_or(0) as usize;
                
                let min_p = min_passed.unwrap_or(0);
                let max_f = max_failures.unwrap_or(0);
                let max_s = max_skipped.unwrap_or(usize::MAX);
                
                let passed = num_passed >= min_p && num_failed <= max_f && num_pending <= max_s;
                
                let mut issues = Vec::new();
                if num_passed < min_p {
                    issues.push(format!("Passed: {num_passed} < min {min_p}"));
                }
                if num_failed > max_f {
                    issues.push(format!("Failed: {num_failed} > max {max_f}"));
                }
                if num_pending > max_s {
                    issues.push(format!("Skipped: {num_pending} > max {max_s}"));
                }
                
                let msg = if passed {
                    format!("JS Tests passed (pass: {num_passed}, fail: {num_failed}, skip: {num_pending})")
                } else {
                    format!("JS Tests failed: {}", issues.join(", "))
                };
                
                RawResult {
                    status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                    message: msg,
                    details: Some(truncate(&stdout, 4000)),
                }
            } else {
                let passed = code == 0;
                RawResult {
                    status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                    message: format!("JS Tests failed to parse JSON (exit code {code})"),
                    details: Some(truncate(&stdout, 4000)),
                }
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("Command execution error: {e}"),
            details: None,
        }
    }
}

pub(crate) fn check_css_html_consistency(
    html_path: &str,
    css_path: &str,
    working_dir: Option<&str>,
) -> RawResult {
    let effective_html = resolve_path(html_path, working_dir);
    let effective_css = resolve_path(css_path, working_dir);
    
    let html_content = match std::fs::read_to_string(&effective_html) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read HTML file '{html_path}': {e}"),
                details: None,
            };
            add_working_dir_hint_if_needed(&mut result, html_path, working_dir);
            return result;
        }
    };
    
    let css_content = match std::fs::read_to_string(&effective_css) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read CSS file '{css_path}': {e}"),
                details: None,
            };
            add_working_dir_hint_if_needed(&mut result, css_path, working_dir);
            return result;
        }
    };
    
    // Parse HTML
    let mut parser = tree_sitter::Parser::new();
    let _ = parser.set_language(&tree_sitter_html::LANGUAGE.into());
    let html_tree = match parser.parse(&html_content, None) {
        Some(t) => t,
        None => return RawResult {
            status: CheckStatus::Failed,
            message: "Failed to parse HTML into AST".into(),
            details: None,
        }
    };
    
    let class_query_str = "(attribute (attribute_name) @attr_name (#eq? @attr_name \"class\") (quoted_attribute_value (attribute_value) @attr_val))";
    let query = match tree_sitter::Query::new(&tree_sitter_html::LANGUAGE.into(), class_query_str) {
        Ok(q) => q,
        Err(e) => return RawResult {
            status: CheckStatus::Failed,
            message: format!("Invalid tree-sitter html query: {e}"),
            details: None,
        }
    };
    let mut cursor = tree_sitter::QueryCursor::new();
    
    let mut html_classes = std::collections::HashSet::new();
    let mut matches = cursor.matches(&query, html_tree.root_node(), html_content.as_bytes());
    while let Some(m) = matches.next() {
        // Find the @attr_val capture (index 1)
        for capture in m.captures {
            if capture.index == 1 {
                if let Ok(val) = capture.node.utf8_text(html_content.as_bytes()) {
                    for cls in val.split_whitespace() {
                        html_classes.insert(cls.to_string());
                    }
                }
            }
        }
    }
    
    // Parse CSS
    let _ = parser.set_language(&tree_sitter_css::LANGUAGE.into());
    let css_tree = match parser.parse(&css_content, None) {
        Some(t) => t,
        None => return RawResult {
            status: CheckStatus::Failed,
            message: "Failed to parse CSS into AST".into(),
            details: None,
        }
    };
    let css_query_str = "(class_selector (class_name) @name)";
    let query = match tree_sitter::Query::new(&tree_sitter_css::LANGUAGE.into(), css_query_str) {
        Ok(q) => q,
        Err(e) => return RawResult {
            status: CheckStatus::Failed,
            message: format!("Invalid tree-sitter css query: {e}"),
            details: None,
        }
    };
    let mut cursor = tree_sitter::QueryCursor::new();
    
    let mut css_classes = std::collections::HashSet::new();
    let mut matches = cursor.matches(&query, css_tree.root_node(), css_content.as_bytes());
    while let Some(m) = matches.next() {
        if let Some(capture) = m.captures.get(0) {
            if let Ok(name) = capture.node.utf8_text(css_content.as_bytes()) {
                css_classes.insert(name.to_string());
            }
        }
    }
    
    let mut missing = Vec::new();
    for cls in &html_classes {
        if !css_classes.contains(cls) {
             missing.push(cls.clone());
        }
    }
    
    if missing.is_empty() {
        RawResult {
            status: CheckStatus::Passed,
            message: format!("All {} HTML classes found in CSS", html_classes.len()),
            details: None,
        }
    } else {
        RawResult {
            status: CheckStatus::Failed,
            message: format!("{} of {} HTML classes NOT found in CSS", missing.len(), html_classes.len()),
            details: Some(format!("Missing classes:\n{}", missing.join("\n"))),
        }
    }
}
