//! Verification engine: executes contract checks and produces results.

use crate::contract::*;
use crate::sandbox::{self, CommandPolicy, SandboxConfig};
use regex::Regex;
use std::path::Path;
use std::time::Instant;
use tokio::process::Command;
use tracing::{debug, info, warn};
use tree_sitter::StreamingIterator;

pub type AstCache = std::collections::HashMap<String, tree_sitter::Tree>;

/// Execute all checks in a contract and return results.
pub async fn run_contract(contract: &Contract, input: Option<&str>) -> Vec<CheckResult> {
    let mut results = Vec::with_capacity(contract.checks.len());
    let mut ast_cache = AstCache::new();

    for check in &contract.checks {
        let start = Instant::now();
        let result = run_check(check, input, &mut ast_cache).await;
        let duration_ms = start.elapsed().as_millis() as u64;

        let check_result = CheckResult {
            check_name: check.name.clone(),
            status: result.status,
            severity: check.severity.clone(),
            message: result.message,
            details: result.details,
            duration_ms,
        };

        if check_result.status == CheckStatus::Passed {
            info!(check = %check.name, "✓ Check passed");
        } else {
            warn!(check = %check.name, severity = ?check.severity, "✗ Check failed or unverified");
        }

        results.push(check_result);
    }

    results
}

/// Determine overall contract status from check results.
pub fn determine_status(results: &[CheckResult]) -> ContractStatus {
    let has_error_failure = results
        .iter()
        .any(|r| r.status == CheckStatus::Failed && r.severity == Severity::Error);

    let has_unverified = results
        .iter()
        .any(|r| r.status == CheckStatus::Unverified);

    if has_error_failure {
        ContractStatus::Failed
    } else if has_unverified {
        ContractStatus::ReviewRequired
    } else {
        ContractStatus::Passed
    }
}

// ── Internal ────────────────────────────────────────────────────────

struct RawResult {
    status: CheckStatus,
    message: String,
    details: Option<String>,
}

async fn run_check(check: &Check, input: Option<&str>, ast_cache: &mut AstCache) -> RawResult {
    match &check.check_type {
        CheckType::CommandSucceeds {
            command,
            working_dir,
            timeout_secs,
            sandbox,
        } => {
            run_command_succeeds(command, working_dir.as_deref(), *timeout_secs, *sandbox).await
        }

        CheckType::CommandOutputMatches {
            command,
            pattern,
            working_dir,
            timeout_secs,
            sandbox,
        } => {
            run_command_output_matches(
                command,
                pattern,
                working_dir.as_deref(),
                *timeout_secs,
                *sandbox,
            )
            .await
        }

        CheckType::FileExists { path } => check_file_exists(path),

        CheckType::FileContainsPatterns {
            path,
            required_patterns,
        } => check_file_contains_patterns(path, required_patterns),

        CheckType::FileExcludesPatterns {
            path,
            forbidden_patterns,
        } => check_file_excludes_patterns(path, forbidden_patterns),

        CheckType::AstQuery {
            path,
            language,
            query,
            mode,
        } => run_ast_query(path, language, query, mode, ast_cache).await,

        CheckType::JsonSchemaValid { schema } => check_json_schema(input, schema),

        CheckType::ValueInRange { min, max } => check_value_in_range(input, *min, *max),

        CheckType::DiffSizeLimit {
            max_additions,
            max_deletions,
        } => check_diff_size(input, *max_additions, *max_deletions),

        CheckType::Assertion { claim } => handle_assertion(claim, input),

        // ── Python-Specific Checks ──────────────────────────────
        CheckType::PythonTypeCheck {
            paths,
            checker,
            extra_args,
            working_dir,
            timeout_secs,
        } => {
            check_python_types(paths, checker, extra_args, working_dir.as_deref(), *timeout_secs)
                .await
        }

        CheckType::PytestResult {
            test_path,
            min_passed,
            max_failures,
            max_skipped,
            working_dir,
            timeout_secs,
        } => {
            check_pytest_result(
                test_path,
                *min_passed,
                *max_failures,
                *max_skipped,
                working_dir.as_deref(),
                *timeout_secs,
            )
            .await
        }

        CheckType::PythonImportGraph {
            root_path,
            fail_on_circular,
            working_dir,
            enforced_architecture,
        } => check_python_import_graph(root_path, *fail_on_circular, working_dir.as_deref(), enforced_architecture.as_deref()).await,

        CheckType::JsonRegistryConsistency {
            json_path,
            id_field,
            source_path,
            reference_pattern,
        } => check_json_registry_consistency(json_path, id_field, source_path, reference_pattern.as_deref()),
    }
}

// ── Check Implementations ───────────────────────────────────────────

async fn run_command_succeeds(
    command: &str,
    working_dir: Option<&str>,
    timeout_secs: u64,
    sandbox_override: Option<bool>,
) -> RawResult {
    match execute_command(command, working_dir, timeout_secs, sandbox_override, false).await {
        Ok((code, stdout, stderr)) => {
            let passed = code == 0;
            let combined = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
            RawResult {
                status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                message: if passed {
                    format!("Command succeeded (exit code 0)")
                } else {
                    format!("Command failed with exit code {code}")
                },
                details: Some(truncate(&combined, 2000)),
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("Command execution error: {e}"),
            details: None,
        },
    }
}

async fn run_command_output_matches(
    command: &str,
    pattern: &str,
    working_dir: Option<&str>,
    timeout_secs: u64,
    sandbox_override: Option<bool>,
) -> RawResult {
    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Invalid regex pattern: {e}"),
                details: None,
            }
        }
    };

    match execute_command(command, working_dir, timeout_secs, sandbox_override, false).await {
        Ok((code, stdout, stderr)) => {
            let matches = re.is_match(&stdout);
            let combined = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
            RawResult {
                status: if code == 0 && matches { CheckStatus::Passed } else { CheckStatus::Failed },
                message: if code != 0 {
                    format!("Command failed with exit code {code}")
                } else if matches {
                    format!("Output matches pattern '{pattern}'")
                } else {
                    format!("Output does NOT match pattern '{pattern}'")
                },
                details: Some(truncate(&combined, 2000)),
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("Command execution error: {e}"),
            details: None,
        },
    }
}

fn check_file_exists(path: &str) -> RawResult {
    let exists = Path::new(path).exists();
    RawResult {
        status: if exists { CheckStatus::Passed } else { CheckStatus::Failed },
        message: if exists {
            format!("File exists: {path}")
        } else {
            format!("File NOT found: {path}")
        },
        details: None,
    }
}

fn check_file_contains_patterns(path: &str, patterns: &[String]) -> RawResult {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read file '{path}': {e}"),
                details: None,
            }
        }
    };

    let mut missing = Vec::new();
    for pattern in patterns {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(&content) {
                    missing.push(pattern.clone());
                }
            }
            Err(e) => {
                missing.push(format!("{pattern} (invalid regex: {e})"));
            }
        }
    }

    if missing.is_empty() {
        RawResult {
            status: CheckStatus::Passed,
            message: format!("All {} required patterns found in {path}", patterns.len()),
            details: None,
        }
    } else {
        RawResult {
            status: CheckStatus::Failed,
            message: format!(
                "{} of {} patterns missing in {path}",
                missing.len(),
                patterns.len()
            ),
            details: Some(format!("Missing patterns:\n{}", missing.join("\n"))),
        }
    }
}

fn check_file_excludes_patterns(path: &str, patterns: &[String]) -> RawResult {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read file '{path}': {e}"),
                details: None,
            }
        }
    };

    let mut found = Vec::new();
    for pattern in patterns {
        match Regex::new(pattern) {
            Ok(re) => {
                if let Some(m) = re.find(&content) {
                    found.push(format!("{pattern} (found at offset {})", m.start()));
                }
            }
            Err(e) => {
                found.push(format!("{pattern} (invalid regex: {e})"));
            }
        }
    }

    if found.is_empty() {
        RawResult {
            status: CheckStatus::Passed,
            message: format!("None of the {} forbidden patterns found in {path}", patterns.len()),
            details: None,
        }
    } else {
        RawResult {
            status: CheckStatus::Failed,
            message: format!(
                "{} forbidden pattern(s) found in {path}",
                found.len()
            ),
            details: Some(format!("Found:\n{}", found.join("\n"))),
        }
    }
}

fn check_json_schema(input: Option<&str>, schema_str: &str) -> RawResult {
    let input = match input {
        Some(i) => i,
        None => {
            return RawResult {
                status: CheckStatus::Failed,
                message: "No input provided for JSON schema validation".into(),
                details: Some("Pass the JSON to validate in the 'input' field".into()),
            }
        }
    };

    let instance: serde_json::Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Input is not valid JSON: {e}"),
                details: Some(truncate(input, 500)),
            }
        }
    };

    let schema: serde_json::Value = match serde_json::from_str(schema_str) {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Schema is not valid JSON: {e}"),
                details: None,
            }
        }
    };

    // Simple structural validation (full jsonschema crate can be added later)
    match validate_json_structure(&instance, &schema) {
        Ok(()) => RawResult {
            status: CheckStatus::Passed,
            message: "JSON validates against schema".into(),
            details: None,
        },
        Err(errors) => RawResult {
            status: CheckStatus::Failed,
            message: format!("JSON schema validation failed: {} error(s)", errors.len()),
            details: Some(errors.join("\n")),
        },
    }
}

/// Simple structural JSON validation (type checking + required fields).
fn validate_json_structure(
    instance: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Check type
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let actual_type = match instance {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    "integer"
                } else {
                    "number"
                }
            }
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };

        // "integer" is also a valid "number"
        let type_ok = actual_type == expected_type
            || (expected_type == "number" && actual_type == "integer");

        if !type_ok {
            errors.push(format!("Expected type '{expected_type}', got '{actual_type}'"));
        }
    }

    // Check required fields for objects
    if let (Some(required), Some(obj)) = (
        schema
            .get("required")
            .and_then(|r| r.as_array()),
        instance.as_object(),
    ) {
        for req in required {
            if let Some(field) = req.as_str() {
                if !obj.contains_key(field) {
                    errors.push(format!("Missing required field: '{field}'"));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_value_in_range(input: Option<&str>, min: Option<f64>, max: Option<f64>) -> RawResult {
    let input = match input {
        Some(i) => i,
        None => {
            return RawResult {
                status: CheckStatus::Failed,
                message: "No input provided for range check".into(),
                details: None,
            }
        }
    };

    let value: f64 = match input.trim().parse() {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot parse '{input}' as number: {e}"),
                details: None,
            }
        }
    };

    let above_min = min.map_or(true, |m| value >= m);
    let below_max = max.map_or(true, |m| value <= m);
    let passed = above_min && below_max;

    let range_str = match (min, max) {
        (Some(lo), Some(hi)) => format!("[{lo}, {hi}]"),
        (Some(lo), None) => format!("[{lo}, ∞)"),
        (None, Some(hi)) => format!("(-∞, {hi}]"),
        (None, None) => "(-∞, ∞)".into(),
    };

    RawResult {
        status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
        message: if passed {
            format!("Value {value} is within range {range_str}")
        } else {
            format!("Value {value} is OUTSIDE range {range_str}")
        },
        details: None,
    }
}

fn check_diff_size(
    input: Option<&str>,
    max_additions: Option<usize>,
    max_deletions: Option<usize>,
) -> RawResult {
    let input = match input {
        Some(i) => i,
        None => {
            return RawResult {
                status: CheckStatus::Failed,
                message: "No diff input provided. Pass a unified diff in the 'input' field.".into(),
                details: None,
            }
        }
    };

    let mut additions = 0usize;
    let mut deletions = 0usize;
    for line in input.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            additions += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            deletions += 1;
        }
    }

    let add_ok = max_additions.map_or(true, |m| additions <= m);
    let del_ok = max_deletions.map_or(true, |m| deletions <= m);
    let passed = add_ok && del_ok;

    let mut issues = Vec::new();
    if !add_ok {
        issues.push(format!(
            "additions: {additions} > max {}",
            max_additions.unwrap()
        ));
    }
    if !del_ok {
        issues.push(format!(
            "deletions: {deletions} > max {}",
            max_deletions.unwrap()
        ));
    }

    RawResult {
        status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
        message: if passed {
            format!("Diff size OK: +{additions} -{deletions} lines")
        } else {
            format!("Diff too large: {}", issues.join(", "))
        },
        details: Some(format!("+{additions} -{deletions} lines")),
    }
}

fn handle_assertion(claim: &str, input: Option<&str>) -> RawResult {
    // The agent asserts something is true and provides evidence.
    // We record it but flag that it's not independently verified.
    match input {
        Some(evidence) if !evidence.trim().is_empty() => RawResult {
            status: CheckStatus::Unverified,
            message: format!("Assertion recorded (UNVERIFIED): {claim}"),
            details: Some(format!(
                "⚠ Agent-provided evidence (not independently verified):\n{evidence}"
            )),
        },
        _ => RawResult {
            status: CheckStatus::Failed,
            message: format!("Assertion WITHOUT evidence: {claim}"),
            details: Some(
                "Agent made a claim but provided no evidence. This is exactly the blind-trust \
                 problem this server exists to prevent."
                    .into(),
            ),
        },
    }
}

async fn run_ast_query(
    path: &str,
    language_str: &str,
    query_str: &str,
    mode: &QueryMode,
    ast_cache: &mut AstCache,
) -> RawResult {
    // 1. Resolve Language
    let language = match language_str.to_lowercase().as_str() {
        "python" => tree_sitter_python::LANGUAGE.into(),
        _ => return RawResult {
            status: CheckStatus::Failed,
            message: format!("Unsupported language for AstQuery: {language_str}"),
            details: Some("Currently supported languages: python".into()),
        }
    };

    // 2. Expand Macros or use raw query
    let expanded_query = if query_str.starts_with("macro:") {
        expand_ast_macro(query_str, language_str)
    } else {
        Ok(query_str.to_string())
    };

    let expanded_query = match expanded_query {
        Ok(q) => q,
        Err(e) => return RawResult {
            status: CheckStatus::Failed,
            message: format!("Failed to expand AST macro: {e}"),
            details: None,
        }
    };

    // 3. Parse Query
    let query = match tree_sitter::Query::new(&language, &expanded_query) {
        Ok(q) => q,
        Err(e) => return RawResult {
            status: CheckStatus::Failed,
            message: format!("Invalid tree-sitter query: {e}"),
            details: Some(expanded_query),
        }
    };

    // 4. Get File Content & Syntax Tree
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return RawResult {
            status: CheckStatus::Failed,
            message: format!("Cannot read file '{path}': {e}"),
            details: None,
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
            None => return RawResult {
                status: CheckStatus::Failed,
                message: format!("Failed to parse file '{path}' into AST"),
                details: None,
            }
        };
        ast_cache.insert(path.to_string(), parsed_tree.clone());
        parsed_tree
    };

    // 5. Execute Query
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut match_count = 0;
    
    // In newer tree-sitter versions, QueryMatches might not implement Iterator directly
    // because it yields items referencing the cursor. We use its inherent .next() method.
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
        status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
        message: if passed {
            format!("AstQuery passed for {path} (mode: {:?})", mode)
        } else {
            format!("AstQuery failed for {path} (mode: {:?})", mode)
        },
        details: Some(details),
    }
}

fn expand_ast_macro(macro_str: &str, language: &str) -> Result<String, String> {
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
            Ok(format!("(function_definition name: (identifier) @name (#eq? @name \"{fn_name}\"))"))
        },
        ("python", "class_exists") => {
            if args.is_empty() {
                return Err("class_exists requires a class name argument".into());
            }
            let class_name = args[0];
            Ok(format!("(class_definition name: (identifier) @name (#eq? @name \"{class_name}\"))"))
        },
        ("python", "imports_module") => {
            if args.is_empty() {
                return Err("imports_module requires a module name argument".into());
            }
            let module_name = args[0];
            Ok(format!(
                "(import_statement name: (dotted_name (identifier) @name (#eq? @name \"{module_name}\")))"
            ))
        },
        _ => Err(format!("Unknown macro '{macro_name}' for language '{language}'")),
    }
}

// ── Python-Specific Check Implementations ───────────────────

async fn check_python_types(
    paths: &[String],
    checker: &str,
    extra_args: &[String],
    working_dir: Option<&str>,
    timeout_secs: u64,
) -> RawResult {
    let checker_cmd = match checker {
        "pyright" => "pyright",
        _ => "mypy",
    };

    // Build command: mypy/pyright <extra_args> <paths>
    let mut parts = vec![checker_cmd.to_string()];
    // For mypy, add --no-error-summary is not needed; we parse the output
    if checker_cmd == "mypy" {
        parts.push("--show-column-numbers".into());
        parts.push("--no-color-output".into());
    }
    parts.extend(extra_args.iter().cloned());
    parts.extend(paths.iter().cloned());
    let command = parts.join(" ");

    match execute_command(&command, working_dir, timeout_secs, None, true).await {
        Ok((code, stdout, stderr)) => {
            let combined = format!("{stdout}{stderr}");
            let lines: Vec<&str> = combined.lines().collect();

            // Parse error/warning counts
            let mut errors = 0usize;
            let mut warnings = 0usize;
            let mut error_details = Vec::new();

            for line in &lines {
                let lower = line.to_lowercase();
                if lower.contains(": error") || lower.contains(": error:") {
                    errors += 1;
                    error_details.push(line.to_string());
                } else if lower.contains(": warning") || lower.contains(": warn") {
                    warnings += 1;
                }
            }

            // mypy summary line: "Found X errors in Y files"
            if let Some(summary) = lines.iter().find(|l| l.contains("Found") && l.contains("error")) {
                // Try to extract count from summary if we didn't parse individual lines
                if errors == 0 {
                    if let Some(n) = extract_first_number(summary) {
                        errors = n;
                    }
                }
            }

            let passed = code == 0 && errors == 0;

            let details_text = if error_details.is_empty() {
                truncate(&combined, 3000)
            } else {
                let mut d = format!("Type errors ({errors}):\n");
                for (i, e) in error_details.iter().enumerate() {
                    if i >= 20 {
                        d.push_str(&format!("  ... and {} more\n", error_details.len() - 20));
                        break;
                    }
                    d.push_str(&format!("  {e}\n"));
                }
                if warnings > 0 {
                    d.push_str(&format!("\n{warnings} warning(s) (see full output)"));
                }
                d
            };

            RawResult {
                status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                message: if passed {
                    format!("{checker_cmd}: no type errors ({warnings} warnings)")
                } else {
                    format!("{checker_cmd}: {errors} error(s), {warnings} warning(s)")
                },
                details: Some(details_text),
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("{checker_cmd} execution failed: {e}. Is {checker_cmd} installed?"),
            details: Some(format!(
                "Hint: Install with `pip install {}`",
                if checker_cmd == "pyright" { "pyright" } else { "mypy" }
            )),
        },
    }
}

async fn check_pytest_result(
    test_path: &str,
    min_passed: Option<usize>,
    max_failures: Option<usize>,
    max_skipped: Option<usize>,
    working_dir: Option<&str>,
    timeout_secs: u64,
) -> RawResult {
    // Use --tb=short for concise tracebacks, -v for test names, --no-header to reduce noise
    let command = format!("python -m pytest {test_path} -v --tb=short --no-header");

    match execute_command(&command, working_dir, timeout_secs, None, true).await {
        Ok((code, stdout, stderr)) => {
            let combined = format!("{stdout}{stderr}");
            let lines: Vec<&str> = combined.lines().collect();

            // ── Parse summary counts ────────────────────────────
            let mut passed_count = 0usize;
            let mut failed_count = 0usize;
            let mut skipped_count = 0usize;
            let mut error_count = 0usize;
            let mut warning_count = 0usize;

            // Summary line is near the end: "X passed, Y failed, Z skipped"
            for line in lines.iter().rev() {
                let lower = line.to_lowercase();
                // The pytest summary line contains "=" borders
                if (lower.contains("passed")
                    || lower.contains("failed")
                    || lower.contains("error"))
                    && (lower.contains('=') || lower.contains("short test summary"))
                {
                    if let Some(n) = extract_before_keyword(&lower, "passed") {
                        passed_count = n;
                    }
                    if let Some(n) = extract_before_keyword(&lower, "failed") {
                        failed_count = n;
                    }
                    if let Some(n) = extract_before_keyword(&lower, "skipped") {
                        skipped_count = n;
                    }
                    if let Some(n) = extract_before_keyword(&lower, "error") {
                        error_count = n;
                    }
                    if let Some(n) = extract_before_keyword(&lower, "warning") {
                        warning_count = n;
                    }
                    break;
                }
            }

            // ── Extract FAILED test names from -v output ────────
            // Lines like: "tests/verify_foo.py::test_bar FAILED"
            let mut failed_tests: Vec<String> = Vec::new();
            for line in &lines {
                let trimmed = line.trim();
                if trimmed.ends_with(" FAILED") || trimmed.starts_with("FAILED ") {
                    let name = trimmed
                        .trim_start_matches("FAILED ")
                        .trim_end_matches(" FAILED")
                        .trim_end_matches(" - *")
                        .trim();
                    if !name.is_empty() {
                        failed_tests.push(name.to_string());
                    }
                }
            }

            // ── Extract failure tracebacks ───────────────────────
            // Capture content between "= FAILURES =" and "= short test summary"
            // or the next "====" boundary
            let mut failure_blocks: Vec<String> = Vec::new();
            let mut in_failures = false;
            let mut current_block = String::new();

            for line in &lines {
                if line.contains("= FAILURES =") || line.contains("= ERRORS =") {
                    in_failures = true;
                    current_block.clear();
                    continue;
                }
                if in_failures {
                    // New test failure header: "_ test_name _"
                    if line.starts_with("_") && line.ends_with("_") && line.len() > 4 {
                        if !current_block.is_empty() {
                            failure_blocks.push(current_block.clone());
                        }
                        current_block = format!("{}\n", line.trim_matches('_').trim_matches(' ').trim());
                        continue;
                    }
                    // End of failures section
                    if line.contains("= short test summary info =")
                        || (line.starts_with("=") && line.ends_with("=") && line.len() > 10
                            && !line.contains("FAILURES") && !line.contains("ERRORS"))
                    {
                        if !current_block.is_empty() {
                            failure_blocks.push(current_block.clone());
                        }
                        in_failures = false;
                        continue;
                    }
                    current_block.push_str(line);
                    current_block.push('\n');
                }
            }
            // Flush last block
            if in_failures && !current_block.is_empty() {
                failure_blocks.push(current_block);
            }

            // ── Extract "short test summary info" section ────────
            let mut short_summary_lines: Vec<String> = Vec::new();
            let mut in_summary = false;
            for line in &lines {
                if line.contains("short test summary info") {
                    in_summary = true;
                    continue;
                }
                if in_summary {
                    if line.starts_with("=") && line.len() > 5 {
                        break;
                    }
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        short_summary_lines.push(trimmed.to_string());
                    }
                }
            }

            let total_failures = failed_count + error_count;

            // ── Evaluate thresholds ─────────────────────────────
            let mut issues = Vec::new();

            let max_fail = max_failures.unwrap_or(0);
            if total_failures > max_fail {
                issues.push(format!(
                    "{total_failures} failure(s) exceeds max allowed ({max_fail})"
                ));
            }

            if let Some(min_p) = min_passed {
                if passed_count < min_p {
                    issues.push(format!(
                        "only {passed_count} test(s) passed, minimum required: {min_p}"
                    ));
                }
            }

            if let Some(max_s) = max_skipped {
                if skipped_count > max_s {
                    issues.push(format!(
                        "{skipped_count} skipped exceeds max allowed ({max_s})"
                    ));
                }
            }

            let passed = issues.is_empty() && code == 0;

            // ── Build focused details ───────────────────────────
            let mut details = format!(
                "Results: {passed_count} passed, {failed_count} failed, \
                 {error_count} errors, {skipped_count} skipped"
            );
            if warning_count > 0 {
                details.push_str(&format!(", {warning_count} warnings"));
            }
            details.push('\n');

            // Show failed test names prominently
            if !failed_tests.is_empty() {
                details.push_str(&format!("\n✗ Failed tests ({}):\n", failed_tests.len()));
                for t in &failed_tests {
                    details.push_str(&format!("  {t}\n"));
                }
            }

            // Show concise failure tracebacks
            if !failure_blocks.is_empty() {
                details.push_str(&format!(
                    "\n─── Failure details ({}) ───\n",
                    failure_blocks.len()
                ));
                for (i, block) in failure_blocks.iter().enumerate() {
                    // Truncate individual blocks to keep output manageable
                    let block_truncated = truncate(block.trim(), 500);
                    details.push_str(&format!("\n[{}] {}\n", i + 1, block_truncated));
                }
            } else if !short_summary_lines.is_empty() {
                // Fallback: show the short summary if we couldn't parse blocks
                details.push_str("\n─── Short summary ───\n");
                for line in &short_summary_lines {
                    details.push_str(&format!("  {line}\n"));
                }
            }

            // Show threshold violations
            if !issues.is_empty() {
                details.push_str("\n⚠ Threshold violations:\n");
                for issue in &issues {
                    details.push_str(&format!("  {issue}\n"));
                }
            }

            // On success, keep it minimal
            if passed {
                details = format!(
                    "Results: {passed_count} passed, {skipped_count} skipped, \
                     {warning_count} warnings — all thresholds met ✓"
                );
            }

            RawResult {
                status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                message: if passed {
                    format!(
                        "pytest: {passed_count} passed, {skipped_count} skipped — all thresholds met"
                    )
                } else {
                    let first_failure = failed_tests
                        .first()
                        .map(|t| format!(" (first: {t})"))
                        .unwrap_or_default();
                    format!(
                        "pytest: {passed_count} passed, {total_failures} failed/errored{first_failure}"
                    )
                },
                details: Some(details),
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("pytest execution failed: {e}"),
            details: None,
        },
    }
}

async fn check_python_import_graph(
    root_path: &str,
    fail_on_circular: bool,
    working_dir: Option<&str>,
    enforced_architecture: Option<&[ArchitectureRule]>,
) -> RawResult {
    // Python script that detects circular imports by analyzing import statements
    let python_script = format!(
        r#"
import ast, os, sys
from collections import defaultdict

def find_imports(filepath, package_root):
    """Extract local imports from a Python file."""
    try:
        with open(filepath) as f:
            tree = ast.parse(f.read(), filepath)
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"PARSE_ERROR: {{filepath}}: {{e}}", file=sys.stderr)
        return []
    
    imports = []
    module_parts = os.path.relpath(filepath, os.path.dirname(package_root))
    module_parts = module_parts.replace(os.sep, '.').removesuffix('.py').removesuffix('.__init__')
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith('{root_path}'.split('/')[0].split(os.sep)[0]):
                    imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                if node.module.startswith('{root_path}'.split('/')[0].split(os.sep)[0]):
                    imports.append(node.module)
            elif node.level > 0 and node.module:
                imports.append(node.module)
    return imports

def find_cycles(graph):
    """Find all cycles using DFS."""
    cycles = []
    visited = set()
    rec_stack = set()
    path = []
    
    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in rec_stack:
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                cycles.append(cycle)
        
        path.pop()
        rec_stack.discard(node)
    
    for node in graph:
        if node not in visited:
            dfs(node)
    
    return cycles

# Build import graph
root = '{root_path}'
graph = defaultdict(list)
module_files = {{}}

for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        if fn.endswith('.py'):
            filepath = os.path.join(dirpath, fn)
            module_name = filepath.replace(os.sep, '.').removesuffix('.py').removesuffix('.__init__')
            module_files[module_name] = filepath
            imports = find_imports(filepath, root)
            for imp in imports:
                graph[module_name].append(imp)

cycles = find_cycles(graph)
unique_cycles = []
seen = set()
for c in cycles:
    key = tuple(sorted(c[:-1]))
    if key not in seen:
        seen.add(key)
        unique_cycles.append(c)

import json
result = {{
    "total_modules": len(module_files),
    "total_edges": sum(len(v) for v in graph.values()),
    "cycles": [" → ".join(c) for c in unique_cycles],
    "cycle_count": len(unique_cycles),
    "edges": graph,
}}
print(json.dumps(result))
"#
    );

    let command = format!("python -c {}", shell_escape(&python_script));

    match execute_command(&command, working_dir, 60, None, true).await {
        Ok((_code, stdout, stderr)) => {
            // Parse the JSON output
            match serde_json::from_str::<serde_json::Value>(&stdout) {
                Ok(result) => {
                    let cycle_count = result["cycle_count"].as_u64().unwrap_or(0);
                    let total_modules = result["total_modules"].as_u64().unwrap_or(0);
                    let total_edges = result["total_edges"].as_u64().unwrap_or(0);
                    let cycles: Vec<String> = result["cycles"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    let mut architecture_violations = Vec::new();
                    if let Some(rules) = enforced_architecture {
                        if let Some(edges) = result["edges"].as_object() {
                            for (source_module, targets_val) in edges {
                                let targets: Vec<String> = targets_val
                                    .as_array()
                                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                    .unwrap_or_default();
                                
                                for rule in rules {
                                    if let Ok(source_re) = Regex::new(&rule.source_match) {
                                        if source_re.is_match(source_module) {
                                            if let Some(allowed) = &rule.allowed_imports {
                                                let allowed_res: Vec<Regex> = allowed.iter().filter_map(|p| Regex::new(p).ok()).collect();
                                                for target in &targets {
                                                    let mut is_allowed = false;
                                                    for re in &allowed_res {
                                                        if re.is_match(target) {
                                                            is_allowed = true;
                                                            break;
                                                        }
                                                    }
                                                    if !is_allowed {
                                                        architecture_violations.push(format!(
                                                            "[{source_module}] imported [{target}] (not in allow-list for '{}')",
                                                            rule.source_match
                                                        ));
                                                    }
                                                }
                                            }
                                            if let Some(forbidden) = &rule.forbidden_imports {
                                                let forbidden_res: Vec<Regex> = forbidden.iter().filter_map(|p| Regex::new(p).ok()).collect();
                                                for target in &targets {
                                                    for re in &forbidden_res {
                                                        if re.is_match(target) {
                                                            architecture_violations.push(format!(
                                                                "[{source_module}] imported [{target}] (forbidden by '{}', matched '{}')",
                                                                rule.source_match, re.as_str()
                                                            ));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Sort violations for deterministic output
                    architecture_violations.sort();

                    let cycles_passed = if fail_on_circular {
                        cycle_count == 0
                    } else {
                        true // just report
                    };
                    
                    let architecture_passed = architecture_violations.is_empty();
                    let passed = cycles_passed && architecture_passed;

                    let mut details = format!(
                        "Import graph: {total_modules} modules, {total_edges} import edges\n"
                    );
                    
                    if !architecture_violations.is_empty() {
                        details.push_str(&format!("\nArchitecture Violations ({}):\n", architecture_violations.len()));
                        for (i, violation) in architecture_violations.iter().enumerate() {
                            if i >= 30 {
                                details.push_str(&format!("  ... and {} more\n", architecture_violations.len() - 30));
                                break;
                            }
                            details.push_str(&format!("  - {violation}\n"));
                        }
                    }

                    if cycles.is_empty() {
                        details.push_str("\nNo circular imports detected.\n");
                    } else {
                        details.push_str(&format!("\nCircular imports ({cycle_count}):\n"));
                        for (i, cycle) in cycles.iter().enumerate() {
                            details.push_str(&format!("  {}. {cycle}\n", i + 1));
                        }
                    }

                    if !stderr.is_empty() {
                        let parse_errors: Vec<&str> = stderr
                            .lines()
                            .filter(|l| l.starts_with("PARSE_ERROR"))
                            .collect();
                        if !parse_errors.is_empty() {
                            details.push_str(&format!(
                                "\n{} file(s) had parse errors (skipped)\n",
                                parse_errors.len()
                            ));
                        }
                    }
                    
                    let mut err_msgs = Vec::new();
                    if !cycles_passed {
                        err_msgs.push(format!("{cycle_count} circular import(s)"));
                    }
                    if !architecture_passed {
                        err_msgs.push(format!("{} architecture violation(s)", architecture_violations.len()));
                    }

                    RawResult {
                        status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
                        message: if passed {
                            let mut ok_msg = format!("Import structure OK in {root_path} ({total_modules} modules scanned)");
                            if cycle_count > 0 && !fail_on_circular {
                                ok_msg.push_str(&format!(" [{} circular imports reported only]", cycle_count));
                            }
                            ok_msg
                        } else {
                            format!("Import issues in {root_path}: {}", err_msgs.join(", "))
                        },
                        details: Some(details),
                    }
                }
                Err(e) => RawResult {
                    status: CheckStatus::Failed,
                    message: format!("Failed to parse import graph output: {e}"),
                    details: Some(format!("stdout: {stdout}\nstderr: {stderr}")),
                },
            }
        }
        Err(e) => RawResult {
            status: CheckStatus::Failed,
            message: format!("Import graph analysis failed: {e}"),
            details: None,
        },
    }
}

fn check_json_registry_consistency(
    json_path: &str,
    id_field: &str,
    source_path: &str,
    reference_pattern: Option<&str>,
) -> RawResult {
    // Read and parse JSON
    let json_content = match std::fs::read_to_string(json_path) {
        Ok(c) => c,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read JSON file '{json_path}': {e}"),
                details: None,
            }
        }
    };

    let json_data: serde_json::Value = match serde_json::from_str(&json_content) {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Invalid JSON in '{json_path}': {e}"),
                details: None,
            }
        }
    };

    // Extract all values for the given id_field at any depth
    let mut ids = Vec::new();
    extract_field_values(&json_data, id_field, &mut ids);

    if ids.is_empty() {
        return RawResult {
            status: CheckStatus::Failed,
            message: format!("No '{id_field}' fields found in {json_path}"),
            details: Some(format!("Expected to find fields named '{id_field}' in the JSON structure")),
        };
    }

    // Read source file
    let source_content = match std::fs::read_to_string(source_path) {
        Ok(c) => c,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read source file '{source_path}': {e}"),
                details: None,
            }
        }
    };

    // Check each ID against source
    let mut missing = Vec::new();
    let mut found = Vec::new();

    for id in &ids {
        let is_referenced = if let Some(pattern) = reference_pattern {
            // Replace {} with the actual ID in the pattern
            let concrete_pattern = pattern.replace("{}", id);
            match Regex::new(&concrete_pattern) {
                Ok(re) => re.is_match(&source_content),
                Err(_) => source_content.contains(id),
            }
        } else {
            // Simple string containment
            source_content.contains(id)
        };

        if is_referenced {
            found.push(id.clone());
        } else {
            missing.push(id.clone());
        }
    }

    let passed = missing.is_empty();

    let mut details = format!(
        "Checked {total} ID(s) from {json_path} against {source_path}\n\
         Found: {found_n}, Missing: {missing_n}\n",
        total = ids.len(),
        found_n = found.len(),
        missing_n = missing.len(),
    );

    if !missing.is_empty() {
        details.push_str("\nMissing IDs (in JSON but not in source):\n");
        for (i, id) in missing.iter().enumerate() {
            if i >= 30 {
                details.push_str(&format!("  ... and {} more\n", missing.len() - 30));
                break;
            }
            details.push_str(&format!("  - \"{id}\"\n"));
        }
    }

    RawResult {
        status: if passed { CheckStatus::Passed } else { CheckStatus::Failed },
        message: if passed {
            format!(
                "All {} ID(s) from {json_path} found in {source_path}",
                ids.len()
            )
        } else {
            format!(
                "{} of {} ID(s) from {json_path} NOT found in {source_path}",
                missing.len(),
                ids.len()
            )
        },
        details: Some(details),
    }
}

/// Recursively extract all string values for a given field name from JSON.
fn extract_field_values(value: &serde_json::Value, field: &str, results: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if key == field {
                    if let Some(s) = val.as_str() {
                        results.push(s.to_string());
                    }
                }
                extract_field_values(val, field, results);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_field_values(item, field, results);
            }
        }
        _ => {}
    }
}

/// Extract the number immediately before a keyword in a string.
/// E.g., "5 passed" → Some(5), "12 failed" → Some(12)
fn extract_before_keyword(text: &str, keyword: &str) -> Option<usize> {
    let re = Regex::new(&format!(r"(\d+)\s+{keyword}")).ok()?;
    re.captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

/// Extract first number from a string.
fn extract_first_number(text: &str) -> Option<usize> {
    let re = Regex::new(r"(\d+)").ok()?;
    re.captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

/// Shell-escape a string for use in `sh -c`.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Execute a command with security-aware dispatch.
///
/// - `sandbox_override`: If `Some(true)`, force execution in a container.
///   If `Some(false)` or `None`, subject to whitelist validation.
/// - `internal`: If `true`, the command was generated by the server itself
///   (e.g., for Python checks) and bypasses dangerous-pattern checks.
async fn execute_command(
    command: &str,
    working_dir: Option<&str>,
    timeout_secs: u64,
    sandbox_override: Option<bool>,
    internal: bool,
) -> Result<(i32, String, String), String> {
    // If sandbox is explicitly requested, always use container
    if sandbox_override == Some(true) {
        info!(command = %command, "Sandbox explicitly requested — executing in container");
        let config = SandboxConfig::from_env();
        return sandbox::execute_sandboxed(command, working_dir, timeout_secs, &config).await;
    }

    // Validate the command through the security policy
    let policy = sandbox::validate_command(command, internal);
    debug!(command = %command, ?policy, "Command policy evaluation");

    match policy {
        CommandPolicy::Allow => {
            // Run directly on host (original behavior)
            execute_on_host(command, working_dir, timeout_secs).await
        }
        CommandPolicy::Sandbox => {
            // Unknown command — run in container
            let config = SandboxConfig::from_env();
            sandbox::execute_sandboxed(command, working_dir, timeout_secs, &config).await
        }
        CommandPolicy::Deny(reason) => {
            Err(format!("🛡 SECURITY: {reason}"))
        }
    }
}

/// Execute a command directly on the host (no sandboxing).
async fn execute_on_host(
    command: &str,
    working_dir: Option<&str>,
    timeout_secs: u64,
) -> Result<(i32, String, String), String> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        cmd.output(),
    )
    .await
    .map_err(|_| format!("Command timed out after {timeout_secs}s"))?
    .map_err(|e| format!("Failed to execute command: {e}"))?;

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((code, stdout, stderr))
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... [truncated]", &s[..max_len])
    }
}

/// Compute a hash of the workspace directory, respecting .gitignore.
pub fn compute_workspace_hash(working_dir: &str) -> String {
    use sha2::{Sha256, Digest};
    use std::fs;
    use ignore::WalkBuilder;
    use std::io::Read;

    let mut hasher = Sha256::new();
    let mut files_hashed = 0;

    let walker = WalkBuilder::new(working_dir)
        .hidden(true)
        .git_ignore(true)
        .git_exclude(true)
        .build();

    let mut paths: Vec<_> = walker.filter_map(Result::ok).collect();
    // Sort paths to ensure deterministic hashing order
    paths.sort_by(|a, b| a.path().cmp(b.path()));

    for entry in paths {
        let path = entry.path();
        if path.is_file() {
            if let Ok(mut file) = fs::File::open(path) {
                // Hash the relative path so renames affect the hash
                if let Ok(rel_path) = path.strip_prefix(working_dir) {
                    hasher.update(rel_path.to_string_lossy().as_bytes());
                }
                
                let mut buffer = [0; 8192];
                while let Ok(count) = file.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    hasher.update(&buffer[..count]);
                }
                files_hashed += 1;
            }
        }
    }

    let result = hasher.finalize();
    format!("{:x}_{}", result, files_hashed)
}
