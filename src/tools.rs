//! MCP tool definitions and call handlers.

use crate::contract::*;
use crate::protocol::*;
use crate::storage::Storage;
use crate::templates::{
    instantiate_template, parameterize_contract, TemplateDefinition, TemplateVariables,
};
use crate::verification;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;

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
                "required": ["description", "task", "checks", "agent_id", "language"],
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of what this contract verifies"
                    },
                    "task": {
                        "type": "string",
                        "description": "The task the agent is about to perform"
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Unique identifier for the agent creating the contract (mandatory)"
                    },
                    "language": {
                        "type": "string",
                        "description": "Primary programming language or tech stack for this task (e.g. 'python', 'rust', 'js')"
                    },
                    "bypass_meta_validation_reason": {
                        "type": "string",
                        "description": "Optional reason to skip code-specific meta-validation checks (e.g. 'Nur HTML-Template bearbeitet'). Use when the task involves purely non-code changes where strict tests don't apply."
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
                                    "description": "Check specification. Must include a 'type' field. Types: command_succeeds, command_output_matches, file_exists, file_contains_patterns, file_excludes_patterns, json_schema_valid, value_in_range, diff_size_limit, assertion, python_type_check, pytest_result, python_import_graph, json_registry_consistency, typescript_type_check, jest_vitest_result, css_html_consistency, ast_query.\nIMPORTANT FIELD NAMES:\n* 'python_type_check' and 'typescript_type_check' require an array named 'paths'.\n* 'pytest_result' and 'jest_vitest_result' require a string named 'test_path'.\n* 'ast_query' and file checks require a string named 'path'."
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
        ToolDefinition {
            name: "verify_get_audit_trail".into(),
            description: "Get the exact lifecycle (audit trail) of a contract. \
                Useful to track how often an agent failed a specific contract before passing."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "contract_id": {
                        "type": "string",
                        "description": "Optional contract ID to filter the audit trail"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max entries to return (default: 50)",
                        "default": 50
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
            name: "verify_list_templates".into(),
            description: "List all available verification contract templates, both built-in and promoted. \
                Returns template definitions including required and optional variables."
                .into(),
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
            name: "verify_create_from_template".into(),
            description: "Create a new verification contract from an existing template. \
                This bypasses meta-validation since templates are pre-validated."
                .into(),
            input_schema: json!({
                "type": "object",
                "required": ["template_name", "variables", "agent_id"],
                "properties": {
                    "template_name": {
                        "type": "string",
                        "description": "Name of the template to use"
                    },
                    "variables": {
                        "type": "object",
                        "description": "Key-value map of variables to substitute into the template"
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional human-readable description (overrides template default)"
                    },
                    "task": {
                        "type": "string",
                        "description": "Optional task description"
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Unique identifier for the agent creating the contract"
                    },
                    "extra_checks": {
                        "type": "array",
                        "description": "Optional additional checks to append to the template",
                        "items": { "type": "object" }
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
            name: "verify_promote_to_template".into(),
            description: "Promote a successful contract into a reusable template. \
                Only contracts with status 'passed' can be promoted."
                .into(),
            input_schema: json!({
                "type": "object",
                "required": ["contract_id", "template_name", "description", "path_mapping"],
                "properties": {
                    "contract_id": {
                        "type": "string",
                        "description": "ID of the passed contract to promote"
                    },
                    "template_name": {
                        "type": "string",
                        "description": "Unique name for the new template"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of what the template is for"
                    },
                    "path_mapping": {
                        "type": "object",
                        "description": "Mapping from concrete values in the contract to variable names. Example: {\"/path/to/app.py\": \"module_path\"}"
                    }
                }
            }),
            annotations: Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(false),
                idempotent_hint: Some(false),
            }),
        },
    ]
}

/// Handle a tool call and return a ToolResult.
pub async fn handle_tool_call(name: &str, args: &Value, store: &Storage) -> ToolResult {
    match name {
        "verify_create_contract" => handle_create_contract(args, store).await,
        "verify_run_contract" => handle_run_contract(args, store).await,
        "verify_quick_check" => handle_quick_check(args).await,
        "verify_list_contracts" => handle_list_contracts(store).await,
        "verify_get_report" => handle_get_report(args, store).await,
        "verify_delete_contract" => handle_delete_contract(args, store).await,
        "verify_history" => handle_history(args, store).await,
        "verify_stats" => handle_stats(args, store).await,
        "verify_get_audit_trail" => handle_get_audit_trail(args, store).await,
        "verify_list_templates" => handle_list_templates(args, store).await,
        "verify_create_from_template" => handle_create_from_template(args, store).await,
        "verify_promote_to_template" => handle_promote_to_template(args, store).await,
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
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return ToolResult::error("'agent_id' is mandatory for creating a contract"),
    };
    let language = match args.get("language").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return ToolResult::error("'language' is mandatory for context-aware validation"),
    };

    let bypass_reason = args
        .get("bypass_meta_validation_reason")
        .and_then(|v| v.as_str());

    let checks_value = match args.get("checks").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => return ToolResult::error("'checks' must be a non-empty array"),
    };

    if checks_value.is_empty() {
        return ToolResult::error("Contract must have at least one check");
    }

    // Serialize raw checks JSON before attempting to parse into Rust structs.
    // This preserves the original payload for rejected contracts.
    let raw_checks_json = serde_json::to_string(checks_value).unwrap_or_else(|_| "[]".into());

    // ── Phase 1: Parse all checks, collecting ALL errors ────────
    let mut checks = Vec::new();
    let mut parse_errors: Vec<String> = Vec::new();

    for (i, check_val) in checks_value.iter().enumerate() {
        match serde_json::from_value::<Check>(check_val.clone()) {
            Ok(check) => checks.push(check),
            Err(e) => {
                parse_errors.push(check_type_error_hint(i, check_val, &e));
            }
        }
    }

    // ── Phase 2: Meta-validation (even if some checks failed to parse,
    //    we can still check the ones that DID parse) ─────────────
    let lower_lang = language.to_lowercase();

    if parse_errors.is_empty() && bypass_reason.is_none() {
        // Only enforce meta-validation when all checks parsed successfully,
        // otherwise the agent needs to fix parse errors first anyway.
        if lower_lang.contains("python") {
            let has_type_check = checks
                .iter()
                .any(|c| matches!(c.check_type, CheckType::PythonTypeCheck { .. }));
            let has_tests = checks
                .iter()
                .any(|c| matches!(c.check_type, CheckType::PytestResult { .. }));
            if !has_type_check || !has_tests {
                parse_errors.push(
                    "Meta-Validation Failed: Python tasks must include both a \
                     'python_type_check' AND a 'pytest_result' check. \
                     (If this is a non-code change, provide 'bypass_meta_validation_reason')"
                        .into(),
                );
            }
        } else if lower_lang.contains("rust") {
            let has_cargo_test = checks.iter().any(|c| {
                if let CheckType::CommandSucceeds { command, .. } = &c.check_type {
                    command.contains("cargo test")
                } else {
                    false
                }
            });
            if !has_cargo_test {
                parse_errors.push(
                    "Meta-Validation Failed: Rust tasks must include a \
                     'command_succeeds' check running 'cargo test'. \
                     (If this is a non-code change, provide 'bypass_meta_validation_reason')"
                        .into(),
                );
            }
        } else if lower_lang.contains("javascript") || lower_lang == "js" {
            let has_tests = checks
                .iter()
                .any(|c| matches!(c.check_type, CheckType::JestVitestResult { .. }));
            if !has_tests {
                parse_errors.push(
                    "Meta-Validation Failed: JavaScript tasks must include a \
                     'jest_vitest_result' check. \
                     (If this is a non-code change, provide 'bypass_meta_validation_reason')"
                        .into(),
                );
            }
        } else if lower_lang.contains("typescript") || lower_lang == "ts" {
            let has_type_check = checks
                .iter()
                .any(|c| matches!(c.check_type, CheckType::TypescriptTypeCheck { .. }));
            let has_tests = checks
                .iter()
                .any(|c| matches!(c.check_type, CheckType::JestVitestResult { .. }));
            if !has_type_check || !has_tests {
                parse_errors.push(
                    "Meta-Validation Failed: TypeScript tasks must include both a \
                     'typescript_type_check' AND a 'jest_vitest_result' check. \
                     (If this is a non-code change, provide 'bypass_meta_validation_reason')"
                        .into(),
                );
            }
        } else if lower_lang.contains("html") || lower_lang.contains("css") {
            let has_tests = checks.iter().any(|c| {
                if let CheckType::CommandSucceeds { command, .. } = &c.check_type {
                    command.contains("test")
                } else {
                    false
                }
            });
            if !has_tests {
                parse_errors.push(
                    "Meta-Validation Failed: HTML/CSS tasks must include a \
                     'command_succeeds' check for testing. \
                     (If this is a non-code change, provide 'bypass_meta_validation_reason')"
                        .into(),
                );
            }
        }
    }

    // ── Phase 3: Return all collected errors at once ─────────────
    if !parse_errors.is_empty() {
        let error_count = parse_errors.len();
        let combined_msg = format!(
            "Contract rejected: {error_count} error(s) found.\n\
             Fix ALL issues below and resubmit.\n\n\
             {}\n",
            parse_errors
                .iter()
                .enumerate()
                .map(|(i, e)| format!(
                    "━━━ Error {} of {} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n{}",
                    i + 1,
                    error_count,
                    e
                ))
                .collect::<Vec<_>>()
                .join("\n\n")
        );

        // Store the rejected contract for audit
        let rejected_id = uuid::Uuid::new_v4().to_string();
        if let Err(store_err) = store
            .create_rejected_contract(
                &rejected_id,
                &description,
                &task,
                &agent_id,
                &language,
                &raw_checks_json,
                &combined_msg,
            )
            .await
        {
            tracing::warn!("Failed to store rejected contract: {store_err}");
        }
        return ToolResult::error(combined_msg);
    }

    // ── Phase 3.5: DRY-RUN VALIDATION ─────────────
    let dry_run_errors = dry_run_validate(&checks);
    if !dry_run_errors.is_empty() {
        let error_count = dry_run_errors.len();
        let combined_msg = format!(
            "Contract dry-run failed: {error_count} issue(s) found.\n\
             Fix ALL issues below and resubmit.\n\n{}",
            dry_run_errors
                .iter()
                .enumerate()
                .map(|(i, e)| format!(
                    "━━━ Dry-Run Issue {} of {} ━━━━━━━━━━━━━━━━━━━━\n{}",
                    i + 1,
                    error_count,
                    e
                ))
                .collect::<Vec<_>>()
                .join("\n\n")
        );

        // Store the rejected contract for audit
        let rejected_id = uuid::Uuid::new_v4().to_string();
        if let Err(store_err) = store
            .create_rejected_contract(
                &rejected_id,
                &description,
                &task,
                &agent_id,
                &language,
                &raw_checks_json,
                &combined_msg,
            )
            .await
        {
            tracing::warn!("Failed to store rejected contract: {store_err}");
        }
        return ToolResult::error(combined_msg);
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = store
        .create_contract(&id, &description, &task, &agent_id, &language, &checks)
        .await
    {
        return ToolResult::error(format!("Failed to store contract: {e}"));
    }

    let bypass_msg = bypass_reason
        .map(|r| format!(" (Meta-validation bypassed: {})", r))
        .unwrap_or_default();

    ToolResult::json(&json!({
        "contract_id": id,
        "description": description,
        "task": task,
        "num_checks": checks.len(),
        "status": "pending",
        "message": format!(
            "Contract created with {} check(s){}. Complete your task, then call \
             verify_run_contract with this contract_id to verify the result.",
            checks.len(), bypass_msg
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
    let new_workspace_hash = verification::compute_workspace_hash(".");

    if let Err(e) = store
        .update_results(
            contract_id,
            status.clone(),
            &results,
            Some(new_workspace_hash),
        )
        .await
    {
        return ToolResult::error(format!("Failed to store results: {e}"));
    }

    // Build summary
    let passed_count = results
        .iter()
        .filter(|r| r.status == CheckStatus::Passed)
        .count();
    let failed_count = results
        .iter()
        .filter(|r| r.status == CheckStatus::Failed)
        .count();
    let unverified_count = results
        .iter()
        .filter(|r| r.status == CheckStatus::Unverified)
        .count();
    let warnings = results
        .iter()
        .filter(|r| r.status == CheckStatus::Failed && r.severity == Severity::Warning)
        .count();
    let total_ms: u64 = results.iter().map(|r| r.duration_ms).sum();

    let result_details: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "check": r.check_name,
                "status": r.status,
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
        ContractStatus::ReviewRequired => format!(
            "⚠ REVIEW REQUIRED — {unverified_count} check(s) unverified. \
             Please review manually."
        ),
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
            "unverified": unverified_count,
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
        Err(e) => return ToolResult::error(check_type_error_hint(0, check_val, &e)),
    };

    let input = args.get("input").and_then(|v| v.as_str());

    // Create a temporary contract with single check
    let contract = Contract {
        id: "quick-check".into(),
        description: "Ad-hoc quick check".into(),
        task: "Quick verification".into(),
        agent_id: "quick-check-agent".into(),
        language: "unknown".into(),
        checks: vec![check],
        created_at: chrono::Utc::now(),
        status: ContractStatus::Running,
        results: vec![],
        workspace_hash: None,
    };

    let results = verification::run_contract(&contract, input).await;
    let result = &results[0];

    ToolResult::json(&json!({
        "status": result.status,
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
    report.push_str(&format!(
        "# Verification Report: {}\n\n",
        contract.description
    ));
    report.push_str(&format!("**Task:** {}\n", contract.task));
    report.push_str(&format!("**Status:** {:?}\n", contract.status));
    report.push_str(&format!(
        "**Created:** {}\n\n",
        contract.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    if contract.results.is_empty() {
        report.push_str(
            "_No verification results yet. Run verify_run_contract to execute checks._\n",
        );
    } else {
        report.push_str("## Check Results\n\n");
        for result in &contract.results {
            let icon = match result.status {
                CheckStatus::Passed => "✓",
                CheckStatus::Failed => "✗",
                CheckStatus::Unverified => "?",
            };
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
        let unverified = contract
            .results
            .iter()
            .any(|r| r.message.contains("UNVERIFIED"));
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
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
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
        return ToolResult::text(format!("No verification history found{filter_desc}."));
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

    if !stats.agents.is_empty() {
        summary.push_str("\nAgent Trust Scores:\n");
        for agent in &stats.agents {
            let status = if agent.trust_score >= 100.0 {
                "✓"
            } else if agent.trust_score > 50.0 {
                "⚠"
            } else {
                "✗"
            };
            summary.push_str(&format!(
                "  {} {} ({:.1})\n",
                status, agent.id, agent.trust_score
            ));
        }
    }

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

async fn handle_get_audit_trail(args: &Value, store: &Storage) -> ToolResult {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
    let contract_id = args.get("contract_id").and_then(|v| v.as_str());

    let events = match store.get_audit_events(contract_id, limit).await {
        Ok(e) => e,
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    if events.is_empty() {
        let filter_desc = if let Some(cid) = contract_id {
            format!(" for contract_id '{}'", cid)
        } else {
            String::new()
        };
        return ToolResult::text(format!("No audit events found{filter_desc}."));
    }

    ToolResult::json(&json!({
        "audit_events": events,
        "total_shown": events.len(),
        "filters": {
            "contract_id": contract_id,
            "limit": limit,
        }
    }))
}

async fn handle_list_templates(_args: &Value, store: &Storage) -> ToolResult {
    let templates = match store.list_templates().await {
        Ok(t) => t,
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    if templates.is_empty() {
        return ToolResult::text("No templates available.");
    }

    let mut result_str = String::from("Available templates:\n\n");

    let builtins: Vec<_> = templates.iter().filter(|t| t.source == "builtin").collect();
    let promoted: Vec<_> = templates
        .iter()
        .filter(|t| t.source == "promoted")
        .collect();

    if !builtins.is_empty() {
        result_str.push_str("Built-in:\n");
        for t in builtins {
            result_str.push_str(&format!("  {} — {}\n", t.name, t.description));
            if !t.variables.required.is_empty() {
                let req_keys: Vec<_> = t.variables.required.keys().cloned().collect();
                result_str.push_str(&format!("    requires: {}\n", req_keys.join(", ")));
            }
            if !t.variables.optional.is_empty() {
                let opt_keys: Vec<_> = t.variables.optional.keys().cloned().collect();
                result_str.push_str(&format!("    optional: {}\n", opt_keys.join(", ")));
            }
            result_str.push_str(&format!("    used: {} times\n\n", t.usage_count));
        }
    }

    if !promoted.is_empty() {
        result_str.push_str("Promoted (from successful contracts):\n");
        for t in promoted {
            let from_contract = t
                .variables
                .required
                .keys()
                .next()
                .map(|_| " [from contract]".to_string())
                .unwrap_or_default();
            result_str.push_str(&format!(
                "  {} — {}{}\n",
                t.name, t.description, from_contract
            ));
            if !t.variables.required.is_empty() {
                let req_keys: Vec<_> = t.variables.required.keys().cloned().collect();
                result_str.push_str(&format!("    requires: {}\n", req_keys.join(", ")));
            }
            if !t.variables.optional.is_empty() {
                let opt_keys: Vec<_> = t.variables.optional.keys().cloned().collect();
                result_str.push_str(&format!("    optional: {}\n", opt_keys.join(", ")));
            }
            result_str.push_str(&format!("    used: {} times\n\n", t.usage_count));
        }
    }

    ToolResult::text(result_str.trim_end().to_string())
}

async fn handle_create_from_template(args: &Value, store: &Storage) -> ToolResult {
    let template_name = match args.get("template_name").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return ToolResult::error("'template_name' is required"),
    };

    let variables_val = match args.get("variables").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return ToolResult::error("'variables' is required and must be an object"),
    };

    let mut variables: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (k, v) in variables_val {
        variables.insert(k.clone(), v.as_str().unwrap_or("").to_string());
    }

    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return ToolResult::error("'agent_id' is mandatory"),
    };

    let template_opt = match store.get_template(template_name).await {
        Ok(t) => t,
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    let template = match template_opt {
        Some(t) => t,
        None => {
            if let Ok(all_tmpls) = store.list_templates().await {
                let names: Vec<_> = all_tmpls.iter().map(|t| t.name.clone()).collect();
                return ToolResult::error(format!(
                    "Template '{}' not found.\n\nAvailable templates:\n  {}",
                    template_name,
                    names.join(", ")
                ));
            } else {
                return ToolResult::error(format!("Template '{}' not found.", template_name));
            }
        }
    };

    if let Err(e) = store.increment_template_usage(template_name).await {
        tracing::warn!("Failed to increment usage: {e}");
    }

    let (mut checks, tmpl_description, language) = match instantiate_template(&template, &variables)
    {
        Ok(res) => res,
        Err(e) => return ToolResult::error(e),
    };

    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or(&tmpl_description)
        .to_string();
    let task = args
        .get("task")
        .and_then(|v| v.as_str())
        .unwrap_or("Created from template")
        .to_string();

    if let Some(extra) = args.get("extra_checks").and_then(|v| v.as_array()) {
        for (i, check_val) in extra.iter().enumerate() {
            match serde_json::from_value::<Check>(check_val.clone()) {
                Ok(check) => checks.push(check),
                Err(e) => return ToolResult::error(check_type_error_hint(i, check_val, &e)),
            }
        }
    }

    let dry_run_errors = dry_run_validate(&checks);
    if !dry_run_errors.is_empty() {
        let error_count = dry_run_errors.len();
        let combined_msg = format!(
            "Contract dry-run failed: {error_count} issue(s) found.\n\n{}",
            dry_run_errors.join("\n\n")
        );
        return ToolResult::error(combined_msg);
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = store
        .create_contract(&id, &description, &task, &agent_id, &language, &checks)
        .await
    {
        return ToolResult::error(format!("Failed to store contract: {e}"));
    }

    ToolResult::json(&json!({
        "contract_id": id,
        "description": description,
        "task": task,
        "num_checks": checks.len(),
        "status": "pending",
        "message": format!(
            "Contract created from template '{}' with {} check(s). Complete your task, then call \
             verify_run_contract with this contract_id to verify the result.",
            template_name, checks.len()
        )
    }))
}

async fn handle_promote_to_template(args: &Value, store: &Storage) -> ToolResult {
    let contract_id = match args.get("contract_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return ToolResult::error("'contract_id' is required"),
    };
    let template_name = match args.get("template_name").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return ToolResult::error("'template_name' is required"),
    };
    let description = match args.get("description").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return ToolResult::error("'description' is required"),
    };
    let path_mapping_val = match args.get("path_mapping").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return ToolResult::error("'path_mapping' is required and must be an object"),
    };

    let mut path_mapping: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut variables_required: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (k, v) in path_mapping_val {
        let var_name = v.as_str().unwrap_or("").to_string();
        path_mapping.insert(k.clone(), var_name.clone());
        variables_required.insert(var_name, "Promoted variable".into());
    }

    let contract = match store.get_contract(contract_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("Contract not found: {}", contract_id)),
        Err(e) => return ToolResult::error(format!("Database error: {e}")),
    };

    let status_str = format!("{:?}", contract.status).to_lowercase();
    if contract.status != ContractStatus::Passed {
        return ToolResult::error(format!(
            "Only contracts with status 'passed' can be promoted. Contract {} has status '{}'.",
            contract_id, status_str
        ));
    }

    let checks_json_str = serde_json::to_string(&contract.checks).unwrap_or_default();
    let parameterized_checks = parameterize_contract(&checks_json_str, &path_mapping);

    let template_def = TemplateDefinition {
        id: uuid::Uuid::new_v4().to_string(),
        name: template_name.to_string(),
        description: description.to_string(),
        language: contract.language,
        source: "promoted".to_string(),
        source_contract_id: Some(contract_id.to_string()),
        variables: TemplateVariables {
            required: variables_required,
            optional: std::collections::HashMap::new(),
        },
        checks_json: parameterized_checks,
        created_at: chrono::Utc::now().to_rfc3339(),
        usage_count: 0,
    };

    if let Err(e) = store.save_template(&template_def).await {
        return ToolResult::error(format!("Failed to save template: {}", e));
    }

    ToolResult::json(&json!({
        "status": "success",
        "template_name": template_name,
        "message": format!("Successfully promoted contract {} to template {}", contract_id, template_name),
        "variables": template_def.variables.required.keys().cloned().collect::<Vec<_>>()
    }))
}

// ── Dry-Run Validation ──────────────────────────────────────────────
fn dry_run_validate(checks: &[Check]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen_working_dirs = HashSet::new();

    for (index, check) in checks.iter().enumerate() {
        let check_name = &check.name;
        let mut check_wd = None;

        match &check.check_type {
            CheckType::CommandSucceeds { working_dir, .. }
            | CheckType::FileExists { working_dir, .. } => {
                check_wd = working_dir.as_deref();
            }
            CheckType::CommandOutputMatches {
                working_dir,
                pattern,
                ..
            } => {
                check_wd = working_dir.as_deref();
                if let Err(e) = Regex::new(pattern) {
                    errors.push(format!(
                        "Check '{}' (index {}): invalid regex in 'pattern': {}\n\n\
                         💡 HINT: Test your regex at https://regex101.com (Rust flavor)\n\
                         Common mistakes:\n\
                         - Unescaped special chars: ( ) [ ] {{ }} need \\\n\
                         - Unmatched brackets: '[1-9' → '[1-9]'\n\
                         - Unescaped dots: 'app.py' → 'app\\.py'",
                        check_name, index, e
                    ));
                }
            }
            CheckType::FileContainsPatterns {
                working_dir,
                required_patterns,
                ..
            } => {
                check_wd = working_dir.as_deref();
                for (p_idx, pattern) in required_patterns.iter().enumerate() {
                    if let Err(e) = Regex::new(pattern) {
                        errors.push(format!(
                            "Check '{}' (index {}): invalid regex in 'required_patterns' at index {}: {}\n\n\
                             💡 HINT: Test your regex at https://regex101.com (Rust flavor)\n\
                             Common mistakes:\n\
                             - Unescaped special chars: ( ) [ ] {{ }} need \\\n\
                             - Unmatched brackets: '[1-9' → '[1-9]'\n\
                             - Unescaped dots: 'app.py' → 'app\\.py'",
                            check_name, index, p_idx, e
                        ));
                    }
                }
            }
            CheckType::FileExcludesPatterns {
                working_dir,
                forbidden_patterns,
                ..
            } => {
                check_wd = working_dir.as_deref();
                for (p_idx, pattern) in forbidden_patterns.iter().enumerate() {
                    if let Err(e) = Regex::new(pattern) {
                        errors.push(format!(
                            "Check '{}' (index {}): invalid regex in 'forbidden_patterns' at index {}: {}\n\n\
                             💡 HINT: Test your regex at https://regex101.com (Rust flavor)\n\
                             Common mistakes:\n\
                             - Unescaped special chars: ( ) [ ] {{ }} need \\\n\
                             - Unmatched brackets: '[1-9' → '[1-9]'\n\
                             - Unescaped dots: 'app.py' → 'app\\.py'",
                            check_name, index, p_idx, e
                        ));
                    }
                }
            }
            CheckType::AstQuery {
                working_dir, query, ..
            } => {
                check_wd = working_dir.as_deref();
                let trimmed = query.trim();
                if trimmed.is_empty() {
                    errors.push(format!(
                        "Check '{}' (index {}): query is empty.",
                        check_name, index
                    ));
                } else if !trimmed.starts_with("macro:") {
                    // Very basic unbalanced bracket check
                    let mut round = 0_i32;
                    let mut square = 0_i32;
                    let mut curly = 0_i32;
                    for c in trimmed.chars() {
                        match c {
                            '(' => round += 1,
                            ')' => round -= 1,
                            '[' => square += 1,
                            ']' => square -= 1,
                            '{' => curly += 1,
                            '}' => curly -= 1,
                            _ => {}
                        }
                    }
                    if round != 0 || square != 0 || curly != 0 {
                        errors.push(format!(
                            "Check '{}' (index {}): AST query has unbalanced brackets. \
                             (Round: {}, Square: {}, Curly: {})",
                            check_name, index, round, square, curly
                        ));
                    }
                }
            }
            CheckType::PythonTypeCheck { working_dir, .. }
            | CheckType::PytestResult { working_dir, .. }
            | CheckType::PythonImportGraph { working_dir, .. }
            | CheckType::JsonRegistryConsistency { working_dir, .. } => {
                check_wd = working_dir.as_deref();
            }
            _ => {}
        }

        if let Some(wd) = check_wd {
            if !wd.is_empty() && seen_working_dirs.insert(wd) {
                let wd_path = Path::new(wd);
                if !wd_path.exists() {
                    errors.push(format!(
                        "Check '{}' (index {}): working_dir '{}' does not exist.\n\n\
                         💡 HINT: Verify the path is correct. Common issues:\n\
                         - Typo in path\n\
                         - Path is relative (use absolute path)\n\
                         - Project not yet cloned to this location",
                        check_name, index, wd
                    ));
                } else if !wd_path.is_dir() {
                    errors.push(format!(
                        "Check '{}' (index {}): working_dir '{}' exists but is not a directory.",
                        check_name, index, wd
                    ));
                }
            }
        }
    }

    errors
}

// ── Error Hint System ───────────────────────────────────────────────

/// Generate a targeted error message when a check fails to deserialize.
/// Instead of dumping all 13 check types, identifies what type the agent intended
/// and shows exactly which fields are missing plus a copy-paste example.
fn check_type_error_hint(index: usize, check_val: &Value, serde_err: &serde_json::Error) -> String {
    let check_type_obj = check_val.get("check_type");
    let type_name = check_type_obj
        .and_then(|ct| ct.get("type"))
        .and_then(|t| t.as_str());
    let check_name = check_val
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("?");

    let serde_msg = serde_err.to_string();

    match type_name {
        Some(t) => {
            let schema = check_type_schema(t);
            match schema {
                Some(s) => format!(
                    "Invalid check at index {index} ('{check_name}'): {serde_msg}\n\n\
                     ╭─ Required fields for '{t}' ─────────────────────\n\
                     {}\n\
                     ├─ Optional fields ────────────────────────────────\n\
                     {}\n\
                     ╰─ Example ────────────────────────────────────────\n\
                     {}",
                    s.required, s.optional, s.example,
                ),
                None => format!(
                    "Invalid check at index {index} ('{check_name}'): unknown check type '{t}'.\n\n\
                     Valid types:\n\
                     │ command_succeeds        │ command_output_matches │ file_exists\n\
                     │ file_contains_patterns  │ file_excludes_patterns │ ast_query\n\
                     │ json_schema_valid       │ value_in_range         │ diff_size_limit\n\
                     │ assertion               │ python_type_check      │ pytest_result\n\
                     │ python_import_graph     │ json_registry_consistency\n\
                     │ typescript_type_check   │ jest_vitest_result     │ css_html_consistency"
                ),
            }
        }
        None => {
            // No 'type' field — diagnose the structural issue
            let has_type_at_root = check_val.get("type").is_some();
            let has_check_type = check_val.get("check_type").is_some();

            if has_type_at_root && !has_check_type {
                format!(
                    "Invalid check at index {index} ('{check_name}'): \
                     'type' field found at root level, but it must be inside 'check_type'.\n\n\
                     ✗ Wrong:  {{\"name\": \"...\", \"type\": \"command_succeeds\", \"command\": \"...\"}}\n\
                     ✓ Right:  {{\"name\": \"...\", \"check_type\": {{\"type\": \"command_succeeds\", \"command\": \"...\"}}}}"
                )
            } else if has_check_type {
                format!(
                    "Invalid check at index {index} ('{check_name}'): \
                     missing 'type' field inside 'check_type'.\n\n\
                     Error: {serde_msg}\n\n\
                     Your check_type: {}\n\n\
                     Expected: {{\"type\": \"<check_type_name>\", ...fields...}}",
                    serde_json::to_string_pretty(check_type_obj.unwrap()).unwrap_or_default()
                )
            } else {
                format!(
                    "Invalid check at index {index} ('{check_name}'): \
                     missing 'check_type' object.\n\n\
                     Error: {serde_msg}\n\n\
                     Expected structure:\n\
                     {{\n  \
                       \"name\": \"my_check\",\n  \
                       \"check_type\": {{\n    \
                         \"type\": \"command_succeeds\",\n    \
                         \"command\": \"cargo test\",\n    \
                         \"working_dir\": \".\"\n  \
                       }}\n\
                     }}"
                )
            }
        }
    }
}

struct CheckTypeSchema {
    required: &'static str,
    optional: &'static str,
    example: &'static str,
}

fn check_type_schema(type_name: &str) -> Option<CheckTypeSchema> {
    match type_name {
        "command_succeeds" => Some(CheckTypeSchema {
            required: "│  command: string  — the shell command to run",
            optional: "│  working_dir: string   (default: current dir)\n\
                       │  timeout_secs: integer  (default: 30)\n\
                       │  sandbox: boolean       (force container execution)",
            example: r#"{"type": "command_succeeds", "command": "cargo test", "working_dir": "."}"#,
        }),
        "command_output_matches" => Some(CheckTypeSchema {
            required: "│  command: string  — the shell command to run\n\
                       │  pattern: string  — regex that stdout must match",
            optional: "│  working_dir: string   (default: current dir)\n\
                       │  timeout_secs: integer  (default: 30)\n\
                       │  sandbox: boolean       (force container execution)",
            example: r#"{"type": "command_output_matches", "command": "python --version", "pattern": "3\\.\\d+"}"#,
        }),
        "file_exists" => Some(CheckTypeSchema {
            required: "│  path: string  — absolute or relative file path",
            optional: "│  working_dir: string",
            example: r#"{"type": "file_exists", "path": "src/main.rs"}"#,
        }),
        "file_contains_patterns" => Some(CheckTypeSchema {
            required: "│  path: string                    — file to check\n\
                       │  required_patterns: [string, ...]  — regex patterns that must ALL match",
            optional: "│  working_dir: string",
            example: r#"{"type": "file_contains_patterns", "path": "src/lib.rs", "required_patterns": ["pub fn main", "use std"]}"#,
        }),
        "file_excludes_patterns" => Some(CheckTypeSchema {
            required: "│  path: string                     — file to check\n\
                       │  forbidden_patterns: [string, ...]  — regex patterns that must NOT match",
            optional: "│  working_dir: string",
            example: r#"{"type": "file_excludes_patterns", "path": "src/lib.rs", "forbidden_patterns": ["println!", "dbg!"]}"#,
        }),
        "ast_query" => Some(CheckTypeSchema {
            required: "│  path: string      — file to parse\n\
                       │  language: string   — e.g. \"python\"\n\
                       │  query: string      — tree-sitter query or macro (e.g. \"macro:function_exists:main\")",
            optional: "│  mode: \"required\" (default) or \"forbidden\"\n\
                       │  working_dir: string",
            example: r#"{"type": "ast_query", "language": "python", "path": "src/app.py", "query": "macro:function_exists:main"}"#,
        }),
        "json_schema_valid" => Some(CheckTypeSchema {
            required: "│  schema: string  — JSON Schema as a string\n\
                       │  ⚠ Also pass 'input' (the JSON to validate) when calling verify_run_contract",
            optional: "│  (none)",
            example: r#"{"type": "json_schema_valid", "schema": "{\"type\": \"object\", \"required\": [\"id\"]}"}"#,
        }),
        "value_in_range" => Some(CheckTypeSchema {
            required: "│  ⚠ Pass 'input' (a numeric string) when calling verify_run_contract",
            optional: "│  min: number\n\
                       │  max: number",
            example: r#"{"type": "value_in_range", "min": 0.0, "max": 100.0}"#,
        }),
        "diff_size_limit" => Some(CheckTypeSchema {
            required: "│  ⚠ Pass 'input' (unified diff text) when calling verify_run_contract",
            optional: "│  max_additions: integer\n\
                       │  max_deletions: integer",
            example: r#"{"type": "diff_size_limit", "max_additions": 200, "max_deletions": 50}"#,
        }),
        "assertion" => Some(CheckTypeSchema {
            required: "│  claim: string  — what you're asserting\n\
                       │  ⚠ Pass 'input' (evidence) when calling verify_run_contract\n\
                       │  ⚠ Results in 'unverified' status — cannot auto-pass a contract",
            optional: "│  (none)",
            example: r#"{"type": "assertion", "claim": "UI looks correct after changes"}"#,
        }),
        "python_type_check" => Some(CheckTypeSchema {
            required: "│  paths: [string, ...]  — files or directories to check\n\
                       │                          e.g. [\"src/\", \"lib/app.py\"]",
            optional: "│  checker: \"mypy\" (default) or \"pyright\"\n\
                       │  extra_args: [string, ...]  e.g. [\"--ignore-missing-imports\"]\n\
                       │  working_dir: string\n\
                       │  timeout_secs: integer  (default: 120)",
            example: r#"{"type": "python_type_check", "paths": ["src/app.py"], "checker": "mypy", "extra_args": ["--ignore-missing-imports"], "working_dir": "."}"#,
        }),
        "pytest_result" => Some(CheckTypeSchema {
            required: "│  test_path: string  — path + optional pytest args\n\
                       │                       e.g. \"tests/ -x --tb=short\" or \"tests/test_foo.py -v\"",
            optional: "│  min_passed: integer     (minimum tests that must pass)\n\
                       │  max_failures: integer    (default: 0)\n\
                       │  max_skipped: integer\n\
                       │  working_dir: string\n\
                       │  timeout_secs: integer    (default: 120)",
            example: r#"{"type": "pytest_result", "test_path": "tests/ -x --tb=short", "min_passed": 5, "max_failures": 0, "working_dir": "."}"#,
        }),
        "python_import_graph" => Some(CheckTypeSchema {
            required: "│  root_path: string  — package to scan (e.g. \"ecs\" or \"services\")",
            optional: "│  fail_on_circular: boolean  (default: true)\n\
                       │  working_dir: string\n\
                       │  enforced_architecture: [{source_match, allowed_imports?, forbidden_imports?}, ...]",
            example: r#"{"type": "python_import_graph", "root_path": "ecs", "fail_on_circular": true, "working_dir": "."}"#,
        }),
        "json_registry_consistency" => Some(CheckTypeSchema {
            required: "│  json_path: string    — path to JSON data file (e.g. \"data/items.json\")\n\
                       │  id_field: string      — field name to extract IDs from (e.g. \"id\")\n\
                       │  source_path: string   — Python file that should reference the IDs",
            optional: "│  reference_pattern: string  — regex with {} placeholder for ID\n\
                       │  working_dir: string",
            example: r#"{"type": "json_registry_consistency", "json_path": "assets/data/items.json", "id_field": "id", "source_path": "entities/item_registry.py"}"#,
        }),
        "typescript_type_check" => Some(CheckTypeSchema {
            required: "│  paths: [string, ...]  — files or directories to check",
            optional: "│  working_dir: string\n\
                       │  timeout_secs: integer  (default: 120)",
            example: r#"{"type": "typescript_type_check", "paths": ["."], "working_dir": "."}"#,
        }),
        "jest_vitest_result" => Some(CheckTypeSchema {
            required: "│  test_path: string  — path to test file or directory or command flags",
            optional: "│  min_passed: integer     (minimum tests that must pass)\n\
                       │  max_failures: integer    (default: 0)\n\
                       │  max_skipped: integer\n\
                       │  working_dir: string\n\
                       │  timeout_secs: integer    (default: 120)",
            example: r#"{"type": "jest_vitest_result", "test_path": "tests/", "min_passed": 1, "max_failures": 0, "working_dir": "."}"#,
        }),
        "css_html_consistency" => Some(CheckTypeSchema {
            required: "│  html_path: string    — path to HTML file\n\
                       │  css_path: string      — path to CSS file",
            optional: "│  working_dir: string",
            example: r#"{"type": "css_html_consistency", "html_path": "index.html", "css_path": "styles.css", "working_dir": "."}"#,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{Check, CheckType, QueryMode, Severity};

    #[test]
    fn test_valid_regex() {
        let checks = vec![Check {
            name: "valid_regex_check".into(),
            severity: Severity::Error,
            check_type: CheckType::CommandOutputMatches {
                command: "echo test".into(),
                pattern: "^test$".into(),
                working_dir: None,
                timeout_secs: 30,
                sandbox: None,
            },
        }];
        let errors = dry_run_validate(&checks);
        assert!(errors.is_empty(), "Should be valid regex");
    }

    #[test]
    fn test_invalid_regex() {
        let checks = vec![Check {
            name: "invalid_regex_check".into(),
            severity: Severity::Error,
            check_type: CheckType::CommandOutputMatches {
                command: "echo test".into(),
                pattern: "[1-9".into(),
                working_dir: None,
                timeout_secs: 30,
                sandbox: None,
            },
        }];
        let errors = dry_run_validate(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid regex in 'pattern'"));
    }

    #[test]
    fn test_invalid_working_dir() {
        let checks = vec![Check {
            name: "invalid_wd_check".into(),
            severity: Severity::Error,
            check_type: CheckType::CommandSucceeds {
                command: "cargo test".into(),
                working_dir: Some("/nonexistent/path/here/123XYZ".into()),
                timeout_secs: 30,
                sandbox: None,
            },
        }];
        let errors = dry_run_validate(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("does not exist"));
    }

    #[test]
    fn test_ast_query_validation() {
        let checks = vec![Check {
            name: "unbalanced_ast_query".into(),
            severity: Severity::Error,
            check_type: CheckType::AstQuery {
                path: "src/main.rs".into(),
                language: "rust".into(),
                query: "(function_item) (".into(),
                mode: QueryMode::Required,
                working_dir: None,
            },
        }];
        let errors = dry_run_validate(&checks);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unbalanced brackets"));
    }
}
