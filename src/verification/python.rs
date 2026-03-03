use crate::contract::{ArchitectureRule, CheckStatus};
use crate::verification::command::execute_command;
use crate::verification::helpers::{extract_before_keyword, extract_first_number, shell_escape, truncate};
use crate::verification::RawResult;
use regex::Regex;

pub(crate) async fn check_python_types(
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
            if let Some(summary) = lines
                .iter()
                .find(|l| l.contains("Found") && l.contains("error"))
            {
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
                status: if passed {
                    CheckStatus::Passed
                } else {
                    CheckStatus::Failed
                },
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
                if checker_cmd == "pyright" {
                    "pyright"
                } else {
                    "mypy"
                }
            )),
        },
    }
}

pub(crate) async fn check_pytest_result(
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
                if (lower.contains("passed") || lower.contains("failed") || lower.contains("error"))
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
                        current_block =
                            format!("{}\n", line.trim_matches('_').trim_matches(' ').trim());
                        continue;
                    }
                    // End of failures section
                    if line.contains("= short test summary info =")
                        || (line.starts_with("=")
                            && line.ends_with("=")
                            && line.len() > 10
                            && !line.contains("FAILURES")
                            && !line.contains("ERRORS"))
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
                status: if passed {
                    CheckStatus::Passed
                } else {
                    CheckStatus::Failed
                },
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

pub(crate) fn sanitize_path_for_python(input: &str) -> Result<String, String> {
    for c in input.chars() {
        if !c.is_alphanumeric() && c != '/' && c != '_' && c != '-' && c != '.' {
            return Err(format!("path contains invalid character: '{}'", c));
        }
    }
    Ok(input.to_string())
}

pub(crate) async fn check_python_import_graph(
    root_path: &str,
    fail_on_circular: bool,
    working_dir: Option<&str>,
    enforced_architecture: Option<&[ArchitectureRule]>,
) -> RawResult {
    let root_path = match sanitize_path_for_python(root_path) {
        Ok(p) => p,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("root_path contains unsafe characters: {}", e),
                details: None,
            };
        }
    };

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
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str().map(String::from))
                                            .collect()
                                    })
                                    .unwrap_or_default();

                                for rule in rules {
                                    if let Ok(source_re) = Regex::new(&rule.source_match) {
                                        if source_re.is_match(source_module) {
                                            if let Some(allowed) = &rule.allowed_imports {
                                                let allowed_res: Vec<Regex> = allowed
                                                    .iter()
                                                    .filter_map(|p| Regex::new(p).ok())
                                                    .collect();
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
                                                let forbidden_res: Vec<Regex> = forbidden
                                                    .iter()
                                                    .filter_map(|p| Regex::new(p).ok())
                                                    .collect();
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
                        details.push_str(&format!(
                            "\nArchitecture Violations ({}):\n",
                            architecture_violations.len()
                        ));
                        for (i, violation) in architecture_violations.iter().enumerate() {
                            if i >= 30 {
                                details.push_str(&format!(
                                    "  ... and {} more\n",
                                    architecture_violations.len() - 30
                                ));
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
                        err_msgs.push(format!(
                            "{} architecture violation(s)",
                            architecture_violations.len()
                        ));
                    }

                    RawResult {
                        status: if passed {
                            CheckStatus::Passed
                        } else {
                            CheckStatus::Failed
                        },
                        message: if passed {
                            let mut ok_msg = format!("Import structure OK in {root_path} ({total_modules} modules scanned)");
                            if cycle_count > 0 && !fail_on_circular {
                                ok_msg.push_str(&format!(
                                    " [{} circular imports reported only]",
                                    cycle_count
                                ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_path_for_python_normal() {
        let path = "ecs/systems";
        let result = sanitize_path_for_python(path);
        assert_eq!(result.unwrap(), "ecs/systems");
    }

    #[test]
    fn test_sanitize_path_for_python_injection() {
        let path = "'; os.system('id'); '";
        let result = sanitize_path_for_python(path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "path contains invalid character: '''");
    }

    #[test]
    fn test_sanitize_path_for_python_backticks() {
        let path = "`id`";
        let result = sanitize_path_for_python(path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "path contains invalid character: '`'");
    }

    #[test]
    fn test_sanitize_path_for_python_subshell() {
        let path = "$(id)";
        let result = sanitize_path_for_python(path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "path contains invalid character: '$'");
    }
}
