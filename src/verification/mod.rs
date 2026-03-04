//! Verification engine: executes contract checks and produces results.

pub(crate) mod ast;
pub(crate) mod command;
pub(crate) mod file;
pub(crate) mod helpers;
pub(crate) mod json;
pub(crate) mod misc;
pub(crate) mod python;
pub(crate) mod web;
pub(crate) mod workspace;

use crate::contract::*;
use std::time::Instant;
use tracing::{info, warn};

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

    let has_unverified = results.iter().any(|r| r.status == CheckStatus::Unverified);

    if has_error_failure {
        ContractStatus::Failed
    } else if has_unverified {
        ContractStatus::ReviewRequired
    } else {
        ContractStatus::Passed
    }
}

pub use workspace::compute_workspace_hash;

// ── Internal ────────────────────────────────────────────────────────

pub(crate) struct RawResult {
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
            command::run_command_succeeds(command, working_dir.as_deref(), *timeout_secs, *sandbox)
                .await
        }

        CheckType::CommandOutputMatches {
            command,
            pattern,
            working_dir,
            timeout_secs,
            sandbox,
        } => {
            command::run_command_output_matches(
                command,
                pattern,
                working_dir.as_deref(),
                *timeout_secs,
                *sandbox,
            )
            .await
        }

        CheckType::FileExists { path, working_dir } => {
            file::check_file_exists(path, working_dir.as_deref())
        }

        CheckType::FileContainsPatterns {
            path,
            required_patterns,
            working_dir,
        } => file::check_file_contains_patterns(path, required_patterns, working_dir.as_deref()),

        CheckType::FileExcludesPatterns {
            path,
            forbidden_patterns,
            working_dir,
        } => file::check_file_excludes_patterns(path, forbidden_patterns, working_dir.as_deref()),

        CheckType::AstQuery {
            path,
            language,
            query,
            mode,
            working_dir,
        } => {
            ast::run_ast_query(
                path,
                language,
                query,
                mode,
                working_dir.as_deref(),
                ast_cache,
            )
            .await
        }

        CheckType::JsonSchemaValid { schema } => json::check_json_schema(input, schema),

        CheckType::ValueInRange { min, max } => misc::check_value_in_range(input, *min, *max),

        CheckType::DiffSizeLimit {
            max_additions,
            max_deletions,
        } => misc::check_diff_size(input, *max_additions, *max_deletions),

        CheckType::Assertion { claim } => misc::handle_assertion(claim, input),

        // ── Python-Specific Checks ──────────────────────────────
        CheckType::PythonTypeCheck {
            paths,
            checker,
            extra_args,
            working_dir,
            timeout_secs,
        } => {
            python::check_python_types(
                paths,
                checker,
                extra_args,
                working_dir.as_deref(),
                *timeout_secs,
            )
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
            python::check_pytest_result(
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
        } => {
            python::check_python_import_graph(
                root_path,
                *fail_on_circular,
                working_dir.as_deref(),
                enforced_architecture.as_deref(),
            )
            .await
        }

        CheckType::JsonRegistryConsistency {
            json_path,
            id_field,
            source_path,
            reference_pattern,
            working_dir,
        } => json::check_json_registry_consistency(
            json_path,
            id_field,
            source_path,
            reference_pattern.as_deref(),
            working_dir.as_deref(),
        ),

        // ── JS/TS/HTML-Specific Checks ──────────────────────────────
        CheckType::TypescriptTypeCheck {
            paths,
            working_dir,
            timeout_secs,
        } => web::check_typescript_type_check(paths, working_dir.as_deref(), *timeout_secs).await,

        CheckType::JestVitestResult {
            test_path,
            working_dir,
            min_passed,
            max_failures,
            max_skipped,
            timeout_secs,
        } => {
            web::check_jest_vitest_result(
                test_path,
                *min_passed,
                *max_failures,
                *max_skipped,
                working_dir.as_deref(),
                *timeout_secs,
            )
            .await
        }

        CheckType::CssHtmlConsistency {
            html_path,
            css_path,
            working_dir,
        } => web::check_css_html_consistency(html_path, css_path, working_dir.as_deref()),
    }
}
