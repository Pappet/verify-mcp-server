//! MCP tool definitions and call handlers.

use crate::contract::*;
use crate::protocol::*;
use crate::storage::Storage;
use crate::verification;
use serde_json::{json, Value};

/// Return all tool definitions for tools/list.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "verify_create_contract".into(),
            description: "Define a verification contract BEFORE starting a task. \
                Specifies what conditions the result must meet. \
                Always create a contract before doing work, then verify after."
                .into(),
            input_schema: json!({
                "type": "object",
                "required": ["description", "task", "checks"],
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of what this contract verifies"
                    },
                    "task": {
                        "type": "string",
                        "description": "The task the agent is about to perform"
                    },
                    "checks": {
                        "type": "array",
                        "description": "List of checks that must pass",
                        "items": {
                            "type": "object",
                            "required": ["name", "check_type"],
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Human-readable check name"
                                },
                                "severity": {
                                    "type": "string",
                                    "enum": ["error", "warning", "info"],
                                    "description": "How severe a failure is (default: error)"
                                },
                                "check_type": {
                                    "type": "object",
                                    "description": "Check specification. Must include a 'type' field. Types: command_succeeds, command_output_matches, file_exists, file_contains_patterns, file_excludes_patterns, json_schema_valid, value_in_range, diff_size_limit, assertion, python_type_check, pytest_result, python_import_graph, json_registry_consistency"
                                }
                            }
                        }
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(false),
                idempotent_hint: Some(false),
            }),
        },
        ToolDefinition {
            name: "verify_run_contract".into(),
            description: "Execute all checks in a contract and get a verification report. \
                Call this AFTER the task is complete to verify the result. \
                Some checks may need an 'input' value (e.g., JSON to validate, diff text, numeric value)."
                .into(),
            input_schema: json!({
                "type": "object",
                "required": ["contract_id"],
                "properties": {
                    "contract_id": {
                        "type": "string",
                        "description": "The contract ID returned by verify_create_contract"
                    },
                    "input": {
                        "type": "string",
                        "description": "Optional input data for checks that need it (JSON for schema validation, diff text, numeric value, or evidence for assertions)"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
            }),
        },
        ToolDefinition {
            name: "verify_quick_check".into(),
            description: "Run a single verification check without creating a full contract. \
                Useful for ad-hoc verification during work. \
                Returns immediate pass/fail result."
                .into(),
            input_schema: json!({
                "type": "object",
                "required": ["check"],
                "properties": {
                    "check": {
                        "type": "object",
                        "required": ["name", "check_type"],
                        "description": "A single check to run",
                        "properties": {
                            "name": { "type": "string" },
                            "check_type": {
                                "type": "object",
                                "description": "Check specification with 'type' field"
                            }
                        }
                    },
                    "input": {
                        "type": "string",
                        "description": "Optional input data for the check"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
            }),
        },
        ToolDefinition {
            name: "verify_list_contracts".into(),
            description: "List all active verification contracts with their status.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
            }),
        },
        ToolDefinition {
            name: "verify_get_report".into(),
            description: "Get the detailed verification report for a contract, \
                including all check results, timing, and an overall assessment."
                .into(),
            input_schema: json!({
                "type": "object",
                "required": ["contract_id"],
                "properties": {
                    "contract_id": {
                        "type": "string",
                        "description": "The contract ID to get the report for"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
            }),
        },
        ToolDefinition {
            name: "verify_delete_contract".into(),
            description: "Delete a contract that is no longer needed.".into(),
            input_schema: json!({
                "type": "object",
                "required": ["contract_id"],
                "properties": {
                    "contract_id": {
                        "type": "string",
                        "description": "The contract ID to delete"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(true),
                idempotent_hint: Some(true),
            }),
        },
        ToolDefinition {
            name: "verify_history".into(),
            description: "Browse verification history across sessions. \
                Shows past contracts with their outcomes. \
                Useful for understanding patterns: what keeps failing, \
                how often verification catches issues, and how the codebase evolved."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max entries to return (default: 20)",
                        "default": 20
                    },
                    "status": {
                        "type": "string",
                        "enum": ["passed", "failed", "pending"],
                        "description": "Filter by contract status"
                    },
                    "days": {
                        "type": "integer",
                        "description": "Only show contracts from the last N days"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
            }),
        },
        ToolDefinition {
            name: "verify_stats".into(),
            description: "Get aggregate verification statistics: pass rate, \
                most commonly failing checks, average duration, total contracts. \
                Helps identify recurring quality issues and track improvement over time."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Period to analyze in days (default: 30)"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
                idempotent_hint: Some(true),
            }),
        },
    ]
}

/// Handle a tool call and return a ToolResult.
pub async fn handle_tool_call(
    name: &str,
    args: &Value,
    store: &Storage,
) -> ToolResult {
    match name {
        "verify_create_contract" => handle_create_contract(args, store).await,
        "verify_run_contract" => handle_run_contract(args, store).await,
        "verify_quick_check" => handle_quick_check(args).await,
        "verify_list_contracts" => handle_list_contracts(store).await,
        "verify_get_report" => handle_get_report(args, store).await,
        "verify_delete_contract" => handle_delete_contract(args, store).await,
        "verify_history" => handle_history(args, store).await,
        "verify_stats" => handle_stats(args, store).await,
        _ => ToolResult::error(format!("Unknown tool: {name}")),
    }
}

// ── Tool Handlers ───────────────────────────────────────────────────

async fn handle_create_contract(args: &Value, store: &Storage) -> ToolResult {
    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed contract")
        .to_string();
    let task = args
        .get("task")
        .and_then(|v| v.as_str())
        .unwrap_or("Unspecified task")
        .to_string();

    let checks_value = match args.get("checks").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => return ToolResult::error("'checks' must be a non-empty array"),
    };

    if checks_value.is_empty() {
        return ToolResult::error("Contract must have at least one check");
    }

    let mut checks = Vec::new();
    for (i, check_val) in checks_value.iter().enumerate() {
        match serde_json::from_value::<Check>(check_val.clone()) {
            Ok(check) => checks.push(check),
            Err(e) => {
                return ToolResult::error(format!(
                    "Invalid check at index {i}: {e}. \
                     Ensure check_type has a 'type' field with one of: \
                     command_succeeds, command_output_matches, file_exists, \
                     file_contains_patterns, file_excludes_patterns, \
                     json_schema_valid, value_in_range, diff_size_limit, assertion, \
                     python_type_check, pytest_result, python_import_graph, \
                     json_registry_consistency"
                ))
            }
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = store.create_contract(&id, &description, &task, &checks).await {
        return ToolResult::error(format!("Failed to store contract: {e}"));
    }

    ToolResult::json(&json!({
        "contract_id": id,
        "description": description,
        "task": task,
        "num_checks": checks.len(),
        "status": "pending",
        "message": format!(
            "Contract created with {} check(s). Complete your task, then call \
             verify_run_contract with this contract_id to verify the result.",
            checks.len()
        )
    }))
}

async fn handle_run_contract(args: &Value, store: &Storage) -> ToolResult {
    let contract_id = match args.get("contract_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return ToolResult::error("'contract_id' is required"),
    };

    let input = args.get("input").and_then(|v| v.as_str());

    let contract = match store.get_contract(contract_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("Contract not found: {contract_id}")),
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    if let Err(e) = store.set_running(contract_id).await {
        return ToolResult::error(format!("Failed to update status: {e}"));
    }

    let results = verification::run_contract(&contract, input).await;
    let status = verification::determine_status(&results);

    if let Err(e) = store.update_results(contract_id, status.clone(), &results).await {
        return ToolResult::error(format!("Failed to store results: {e}"));
    }

    // Build summary
    let passed_count = results.iter().filter(|r| r.passed).count();
    let failed_count = results.iter().filter(|r| !r.passed).count();
    let warnings = results
        .iter()
        .filter(|r| !r.passed && r.severity == Severity::Warning)
        .count();
    let total_ms: u64 = results.iter().map(|r| r.duration_ms).sum();

    let result_details: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "check": r.check_name,
                "passed": r.passed,
                "severity": r.severity,
                "message": r.message,
                "details": r.details,
                "duration_ms": r.duration_ms,
            })
        })
        .collect();

    let verdict = match &status {
        ContractStatus::Passed if warnings > 0 => {
            format!("⚠ PASSED with {warnings} warning(s) — review recommended")
        }
        ContractStatus::Passed => "✓ ALL CHECKS PASSED".into(),
        ContractStatus::Failed => format!(
            "✗ CONTRACT FAILED — {failed_count} check(s) did not pass. \
             Do NOT proceed with this result."
        ),
        _ => "Unknown".into(),
    };

    ToolResult::json(&json!({
        "contract_id": contract_id,
        "status": status,
        "verdict": verdict,
        "summary": {
            "total_checks": results.len(),
            "passed": passed_count,
            "failed": failed_count,
            "warnings": warnings,
            "total_duration_ms": total_ms,
        },
        "checks": result_details,
    }))
}

async fn handle_quick_check(args: &Value) -> ToolResult {
    let check_val = match args.get("check") {
        Some(v) => v,
        None => return ToolResult::error("'check' is required"),
    };

    let check: Check = match serde_json::from_value(check_val.clone()) {
        Ok(c) => c,
        Err(e) => return ToolResult::error(format!("Invalid check definition: {e}")),
    };

    let input = args.get("input").and_then(|v| v.as_str());

    // Create a temporary contract with single check
    let contract = Contract {
        id: "quick-check".into(),
        description: "Ad-hoc quick check".into(),
        task: "Quick verification".into(),
        checks: vec![check],
        created_at: chrono::Utc::now(),
        status: ContractStatus::Running,
        results: vec![],
    };

    let results = verification::run_contract(&contract, input).await;
    let result = &results[0];

    ToolResult::json(&json!({
        "passed": result.passed,
        "check": result.check_name,
        "message": result.message,
        "details": result.details,
        "duration_ms": result.duration_ms,
    }))
}

async fn handle_list_contracts(store: &Storage) -> ToolResult {
    let contracts = match store.list_contracts().await {
        Ok(c) => c,
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    if contracts.is_empty() {
        return ToolResult::text(
            "No active contracts. Use verify_create_contract to define expectations \
             before starting a task.",
        );
    }

    ToolResult::json(&json!({
        "contracts": contracts,
        "total": contracts.len(),
    }))
}

async fn handle_get_report(args: &Value, store: &Storage) -> ToolResult {
    let contract_id = match args.get("contract_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return ToolResult::error("'contract_id' is required"),
    };

    let contract = match store.get_contract(contract_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("Contract not found: {contract_id}")),
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    // Build a formatted report
    let mut report = String::new();
    report.push_str(&format!("# Verification Report: {}\n\n", contract.description));
    report.push_str(&format!("**Task:** {}\n", contract.task));
    report.push_str(&format!("**Status:** {:?}\n", contract.status));
    report.push_str(&format!(
        "**Created:** {}\n\n",
        contract.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    if contract.results.is_empty() {
        report.push_str("_No verification results yet. Run verify_run_contract to execute checks._\n");
    } else {
        report.push_str("## Check Results\n\n");
        for result in &contract.results {
            let icon = if result.passed { "✓" } else { "✗" };
            let severity_tag = match result.severity {
                Severity::Error => "[ERROR]",
                Severity::Warning => "[WARN]",
                Severity::Info => "[INFO]",
            };
            report.push_str(&format!(
                "{icon} {severity_tag} **{}** ({}ms)\n",
                result.check_name, result.duration_ms
            ));
            report.push_str(&format!("  {}\n", result.message));
            if let Some(details) = &result.details {
                report.push_str(&format!("  ```\n  {}\n  ```\n", details));
            }
            report.push('\n');
        }

        // Unverified assertions warning
        let unverified = contract.results.iter().any(|r| {
            r.message.contains("UNVERIFIED")
        });
        if unverified {
            report.push_str(
                "\n⚠ **WARNING:** This report contains agent-provided assertions that \
                 have NOT been independently verified. Treat these with skepticism.\n",
            );
        }
    }

    ToolResult::json(&json!({
        "contract": contract,
        "report_markdown": report,
    }))
}

async fn handle_delete_contract(args: &Value, store: &Storage) -> ToolResult {
    let contract_id = match args.get("contract_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return ToolResult::error("'contract_id' is required"),
    };

    match store.delete_contract(contract_id).await {
        Ok(true) => ToolResult::text(format!("Contract {contract_id} deleted.")),
        Ok(false) => ToolResult::error(format!("Contract not found: {contract_id}")),
        Err(e) => ToolResult::error(format!("Database error: {e}")),
    }
}

async fn handle_history(args: &Value, store: &Storage) -> ToolResult {
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as usize;
    let status_filter = args.get("status").and_then(|v| v.as_str());
    let days = args.get("days").and_then(|v| v.as_i64());

    let entries = match store.get_history(limit, status_filter, days).await {
        Ok(e) => e,
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    if entries.is_empty() {
        let filter_desc = match (status_filter, days) {
            (Some(s), Some(d)) => format!(" (status={s}, last {d} days)"),
            (Some(s), None) => format!(" (status={s})"),
            (None, Some(d)) => format!(" (last {d} days)"),
            (None, None) => String::new(),
        };
        return ToolResult::text(format!(
            "No verification history found{filter_desc}."
        ));
    }

    ToolResult::json(&json!({
        "history": entries,
        "total_shown": entries.len(),
        "filters": {
            "status": status_filter,
            "days": days,
            "limit": limit,
        }
    }))
}

async fn handle_stats(args: &Value, store: &Storage) -> ToolResult {
    let days = args.get("days").and_then(|v| v.as_i64());

    let stats = match store.get_stats(days).await {
        Ok(s) => s,
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    // Build a human-readable summary alongside the structured data
    let mut summary = format!(
        "Verification Stats (last {} days)\n\
         ══════════════════════════════════\n\
         Contracts: {} total ({} passed, {} failed, {} pending)\n\
         Pass rate: {:.1}%\n\
         Checks run: {} total ({} failures)\n\
         Avg duration: {}ms per check\n",
        stats.period_days,
        stats.total_contracts,
        stats.total_passed,
        stats.total_failed,
        stats.total_pending,
        stats.pass_rate_percent,
        stats.total_checks_run,
        stats.total_check_failures,
        stats.avg_verification_duration_ms,
    );

    if !stats.most_common_failures.is_empty() {
        summary.push_str("\nMost frequently failing checks:\n");
        for (i, f) in stats.most_common_failures.iter().enumerate() {
            summary.push_str(&format!(
                "  {}. {} ({} failures, last: {})\n",
                i + 1,
                f.check_name,
                f.failure_count,
                f.last_failure.split('T').next().unwrap_or(&f.last_failure),
            ));
        }
    }

    ToolResult::json(&json!({
        "stats": stats,
        "summary": summary,
    }))
}
