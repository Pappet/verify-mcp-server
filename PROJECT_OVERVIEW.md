# Project Overview: verify-mcp-server

## What Is This?

A **Rust-based MCP (Model Context Protocol) server** that provides **contract-based verification** for AI agents. It solves the "blind trust" problem — where AI agents accept tool outputs without checking them — by letting agents define expectations *before* work and verify results *after*.

---

## Project Stats

| Property | Value |
|---|---|
| **Language** | Rust (edition 2021) |
| **Version** | 0.1.0 |
| **License** | MIT |
| **Tests** | ✅ 40 passing unit tests |
| **Build** | ✅ Compiles cleanly |
| **Binary** | `target/release/verify-mcp-server` |
| **Persistence** | SQLite at `~/.local/share/verify-mcp/verify.db` |
| **MCP Tools** | 12 tools exposed |
| **Check Types** | 17 supported verification check types |

---

## Architectural Decisions

This project is built around several core design decisions to ensure safety, reliability, and precision when evaluating agent outputs.

### 1. Three-Tier Command Security
Agents have a tendency to run unsafe commands (e.g., `rm -rf`, unexpected network calls) or chain commands in ways that bypass monitoring.
- **Whitelisting**: Basic commands (`cargo`, `python`, `pytest`, `grep`) are allowed by default if they do not contain dangerous characters.
- **Pattern Blocking**: Any payload containing shell-injection patterns (`&&`, `||`, `$()`, `>`, etc.) is immediately rejected unless inside an allowed context. The pattern checker is **quote-aware** — semicolons or pipes inside quoted strings (e.g. `python -c "import x; y"`) are correctly recognized as language syntax, not shell injection.
- **Sandboxing**: Unknown or explicitly sandboxed commands (`"sandbox": true`) run in short-lived, ephemeral **Podman** containers with severe restrictions (no network, 512MB RAM limit, 2 CPU limit).
- **Actionable Suggestions**: When a command is blocked, the server generates targeted hints (e.g. "Use `working_dir` instead of `cd ... && command`").

### 2. Precise Assertion Handling (`CheckStatus`)
Originally, agents could arbitrarily claim an assertion was "passed" (`passed: true`), breaking the trustless model.
- We introduced a 3-state `CheckStatus` enum (`Passed`, `Failed`, `Unverified`). 
- If an agent provides an assertion with evidence, it is logged as `Unverified`.
- Contracts containing `Unverified` checks cannot achieve a `Passed` status. Instead, they result in `ContractStatus::ReviewRequired`. This prevents false confidence while still capturing agent insights.

### 3. Local SQLite Persistence
Instead of appending to JSON files or using an external database, the server uses a bundled `rusqlite` implementation. 
- It maintains structured trails of all created contracts, executions, check results, and audit events.
- Templates (both built-in and promoted from successful contracts) are stored and tracked with usage counts.
- **No Migration Framework**: Because this is a local developer tool, if schema changes are required, the database file is safely wiped and re-created rather than bloating the system with a heavy versioned migration tool.

### 4. Context-Sensitive Meta-Validation
To prevent agents from skipping crucial checks on specific tech stacks, the server requires two metadata fields on every contract: `agent_id` and `language`.
- Meta-validation rules enforce minimum check standards based on the `language`.
- E.g., Python tasks MUST include `python_type_check` AND `pytest_result`.
- Rust tasks MUST include a `command_succeeds` check running `cargo test`.
- JS/TS tasks MUST include a `jest_vitest_result` check, and TS additionally needs `typescript_type_check`.
- HTML/CSS tasks MUST include a test-related `command_succeeds` check.
- Non-code changes can bypass meta-validation by providing a `bypass_meta_validation_reason`.

### 5. Multi-Stage Contract Validation
Contract creation goes through three gates before being accepted:
1. **Check Parsing**: All checks are deserialized with a targeted error hint system that identifies the intended check type and shows exactly which fields are missing, with copy-paste examples.
2. **Meta-Validation**: Language-specific minimum standards (see above).
3. **Dry-Run Validation**: Regex patterns are compiled, working directories are verified to exist, and AST queries are checked for balanced brackets — all before the contract is stored.

Rejected contracts are stored in the database with status `rejected` for audit purposes, enabling analysis of common agent mistakes.

### 6. Batched Error Reporting
Instead of failing on the first error and requiring multiple round-trips, the server collects ALL parsing, meta-validation, and dry-run errors and returns them in a single response. This drastically reduces retry cycles for agents.

### 7. Contract Templates
To reduce boilerplate and enforce patterns, the server supports a template system:
- **Built-in templates** are seeded on startup for common scenarios (Python endpoints, bugfixes, new modules, Rust features, HTML changes).
- **Promoted templates** are created from successful contracts via `verify_promote_to_template`, with concrete paths replaced by variables.
- Templates support required and optional variables, default values (`{{var:default}}`), and conditional checks (`_condition` field).

### 8. Agent Trust Scores
The server tracks agent reliability over time:
- Each agent starts with a trust score of 100.0.
- **Flaky detection**: If a previously-passed contract fails with the same workspace hash, a severe penalty is applied.
- **Trial-and-error detection**: Repeated consecutive failures trigger a penalty after a configurable number of retries.
- Trust scores are visible in `verify_stats` and can be tuned via environment variables.

---

## Source Files

### [main.rs](src/main.rs)
Entry point. Sets up tracing (to stderr per MCP spec), opens SQLite storage, and runs the stdio JSON-RPC loop. Handles `initialize`, `tools/list`, `tools/call`, and `ping` methods.

### [protocol.rs](src/protocol.rs)
MCP protocol types: `JsonRpcRequest`, `JsonRpcResponse`, `ToolDefinition`, `ToolResult`, etc. Implements the JSON-RPC 2.0 subset needed for an MCP tool server. Includes `ToolAnnotations` for read-only/destructive/idempotent hints.

### [contract.rs](src/contract.rs)
Data model for contracts and checks. Defines:
- `Contract` — a set of expectations with metadata (`agent_id`, `language`, `workspace_hash`)
- `Check` — a single verifiable check with severity
- `CheckType` — the 17 supported check types (commands, files, AstQuery, JSON schema, pytest, TypeScript types, Jest/Vitest results, import graph w/ architecture rules, etc.)
- `CheckResult` — contains a `CheckStatus` (`Passed`, `Failed`, `Unverified`).
- `ContractStatus` — Overall health (`Pending`, `Running`, `Passed`, `Failed`, `ReviewRequired`, `Rejected`).
- `ArchitectureRule` — import constraints for `PythonImportGraph` checks.

### [tools.rs](src/tools.rs)
MCP tool definitions and call handlers. Exposes 12 tools for contract lifecycle, templates, history, and stats. Key responsibilities:
- Multi-phase contract validation (parsing → meta-validation → dry-run).
- Batched error collection and targeted error hint generation.
- Template instantiation and promotion logic.
- Check type schema documentation for the error hint system.

### [verification.rs](src/verification.rs)
The verification engine. Implements all 17 check evaluation mechanisms, including:
- Command evaluations with security-aware dispatch to strict `CheckStatus` results.
- `AstQuery`: AST-based semantic analysis using `tree-sitter` for Python, JS, TS, HTML, and CSS, with macro expansion (e.g. `macro:function_exists:name`, `macro:react_component_exists:name`).
- `PythonImportGraph`: Extracts internal import relationships, detects cycles, and verifies against optional architectural rules.
- `PytestResult`: Structured pytest output parsing with pass/fail/skip thresholds and detailed failure extraction.
- `PythonTypeCheck`: Structured mypy/pyright output parsing.
- `TypescriptTypeCheck`: Runs `tsc --noEmit` to validate TypeScript files.
- `JestVitestResult`: Parses structured Jest/Vitest JSON reports.
- `CssHtmlConsistency`: Verifies that CSS classes used in HTML files exist in the corresponding CSS code.
- `JsonRegistryConsistency`: Cross-references JSON data files against Python source registries.
- Workspace hashing via `ignore` crate (respects `.gitignore`) for flaky-detection support.

### [sandbox.rs](src/sandbox.rs)
Implements the 3-tier security policies with quote-aware pattern matching, regex filters to deny destructive behaviors, and Podman container execution. Provides actionable suggestions when commands are blocked (e.g. suggesting `working_dir` instead of `cd && ...`).

### [storage.rs](src/storage.rs)
SQLite-backed persistence. Stores contracts, check results, templates, agent trust scores, and a full, queryable audit trail. Handles:
- CRUD for contracts and templates.
- Rejected contract storage for audit purposes.
- Agent trust score management with flaky/trial-and-error penalty logic.
- Built-in template seeding on startup.

### [templates.rs](src/templates.rs)
Template system for reusable contract patterns. Provides:
- Variable substitution with `{{var}}` and `{{var:default}}` syntax.
- Conditional check inclusion via `_condition` field.
- Automatic numeric conversion for substituted values.
- Contract parameterization for promoting concrete contracts to templates.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `serde` + `serde_json` | JSON serialization |
| `tokio` | Async runtime + process spawning |
| `uuid` | Contract ID generation |
| `chrono` | Timestamps |
| `regex` | Pattern matching in checks and template substitution |
| `rusqlite` (bundled) | SQLite storage |
| `tracing` + `tracing-subscriber` | Structured logging |
| `thiserror` | Error handling |
| `tree-sitter` + grammars | AST-based semantic code analysis (Python, JS, TS, HTML, CSS) |
| `ignore` | Gitignore-aware file walking for workspace hashing |
| `sha2` | SHA-256 workspace hashing for flaky detection |

---

## MCP Tools Reference

| # | Tool | Read-Only | Destructive | Idempotent |
|---|---|---|---|---|
| 1 | `verify_create_contract` | ✗ | ✗ | ✗ |
| 2 | `verify_run_contract` | ✗ | ✗ | ✓ |
| 3 | `verify_quick_check` | ✓ | ✗ | ✓ |
| 4 | `verify_list_contracts` | ✓ | ✗ | ✓ |
| 5 | `verify_get_report` | ✓ | ✗ | ✓ |
| 6 | `verify_delete_contract` | ✗ | ✓ | ✓ |
| 7 | `verify_history` | ✓ | ✗ | ✓ |
| 8 | `verify_stats` | ✓ | ✗ | ✓ |
| 9 | `verify_get_audit_trail` | ✓ | ✗ | ✓ |
| 10 | `verify_list_templates` | ✓ | ✗ | ✓ |
| 11 | `verify_create_from_template` | ✗ | ✗ | ✗ |
| 12 | `verify_promote_to_template` | ✗ | ✗ | ✗ |

---

## Additional References

- [README.md](README.md) — The Quick Start guide and entry point.
- [examples/CLAUDE_roguelike_verification_v2.md](examples/CLAUDE_roguelike_verification_v2.md) — A comprehensive verification template tailored for a roguelike Python/ECS project.
- [examples/antigravity_rule_verify-workflow-ruke.md](examples/antigravity_rule_verify-workflow-ruke.md) — German-language workspace rule for always-on verify integration.
- [examples/rust_project_contract.json](examples/rust_project_contract.json) — Example contract for a Rust project.
- [examples/mcp_config.json](examples/mcp_config.json) — Example MCP client configuration.
