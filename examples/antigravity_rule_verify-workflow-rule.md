---
trigger: always_on
---

# Workspace Rule: Verify MCP Server Integration

## Core Principle: Zero Blind Trust

The `verify-mcp-server` solves the "blind trust" problem in agent workflows. Tasks must be mathematically and robustly proven through explicit contracts before they are considered complete. Claims without computational proof are marked as `Unverified` and force the status `ReviewRequired`.

## The Verification Cycle (MANDATORY)

Every code change must follow this workflow:

1. **DEFINE (Before work):** Call `verify_create_contract` to specify the exact conditions the code must meet.
2. **WORK:** Write the code or make the changes.
3. **VERIFY (After work):** Call `verify_run_contract` with the generated contract ID.
4. **FIX:** If the contract fails, analyze the errors, fix them, and run the contract again until it passes.

**Never skip verification.** Not because you're "confident", not for small changes, not for JSON-only edits.

## Using Templates

For recurring tasks, prefer templates over defining checks from scratch:

1. Call `verify_list_templates` to see available templates (built-in and promoted).
2. Call `verify_create_from_template` with the template name and variables.
3. Templates are pre-validated — no meta-validation is enforced.
4. Append `extra_checks` if the template doesn't cover everything.
5. After a successful contract, promote it with `verify_promote_to_template` if it's reusable.

## Context-Sensitive Meta-Validation

To prevent critical checks from being skipped, every contract requires the metadata fields `agent_id` and `language`.

Meta-validation rules enforce minimum standards based on the language:
* **Python tasks** MUST include `python_type_check` AND `pytest_result` checks.
* **Rust tasks** MUST include a `command_succeeds` check running `cargo test`.
* **JS/TS/Web tasks** MUST include a `command_succeeds` check for testing (e.g. `npm test`, `jest`).

For non-code changes (HTML templates, config files, documentation), provide `bypass_meta_validation_reason` to skip these requirements:
```json
"bypass_meta_validation_reason": "HTML template change only, no code logic affected"
```

## Contract Creation Safeguards

Contracts go through three validation stages before being accepted:

1. **Check Parsing** — All checks are deserialized. If a field name is wrong (e.g. `path` instead of `paths` for `python_type_check`), the agent gets a targeted hint showing required fields and a copy-paste example.
2. **Meta-Validation** — Language-specific minimum standards (see above).
3. **Dry-Run Validation** — Regex patterns are compiled, working directories are verified to exist, and AST queries are checked for balanced brackets.

**All errors are collected and returned at once** — no more one-error-at-a-time round-trips.

Rejected contracts are stored for audit purposes and visible in `verify_history`.

## Security and Sandboxing

The server restricts command execution through a strict 3-tier security model:

* **Whitelisted Commands:** Safe commands (`python`, `pytest`, `mypy`, `cargo`, etc.) run directly on the host, provided they don't contain dangerous characters.
* **Blocked Patterns:** Commands with shell injection patterns (e.g. `&&`, `||`, `rm `, `sudo `, `>`) are immediately blocked — with actionable suggestions (e.g. "Use `working_dir` instead of `cd ... &&`").
* **Sandboxing:** Unknown commands or those with `"sandbox": true` run in ephemeral Podman containers (no network, limited to 512MB RAM and 2 CPUs).

The validation is **quote-aware** — semicolons inside quoted strings (e.g. `python -c "import x; y"`) are correctly recognized as safe.

## Check Type Selection

Do not rely on error-prone text matching for source code. Use structural and semantic checks:

* **`ast_query`:** Uses `tree-sitter` for robust semantic analysis (e.g. `macro:function_exists:<name>`) independent of formatting.
* **`python_type_check`:** Uses `mypy` or `pyright` to parse structured type errors.
* **`pytest_result`:** Parses results (passed/failed/skipped) and enforces thresholds.
* **`python_import_graph`:** Detects circular imports and enforces architecture boundaries.
* **`json_registry_consistency`:** Validates that IDs in JSON files also exist in Python registries.
* **LEGACY NOTE:** `file_contains_patterns` and `file_excludes_patterns` are considered legacy for source code. Use them only for simple text or log files.

## Agent Trust Scores

The server tracks agent reliability over time:
* Agents start at a trust score of 100.0.
* **Flaky detection:** A previously-passed contract failing with the same workspace hash triggers a severe penalty.
* **Trial-and-error detection:** Repeated consecutive failures trigger a penalty after N retries.
* View trust scores with `verify_stats`.

---

## Agent Example: Define a Contract (with Meta-Validation)

Here is a complete, current JSON example for calling `verify_create_contract`. This example defines a strict Python task and includes the required metadata fields.

```json
{
  "description": "Implement sorting logic and stabilize user module",
  "task": "Add sort_users_by_age to user_service.py, ensure type safety, and verify no circular imports in the services package.",
  "agent_id": "claude-sonnet-4-5",
  "language": "python",
  "checks": [
    {
      "name": "syntax_valid",
      "severity": "error",
      "check_type": {
        "type": "command_succeeds",
        "command": "python -m py_compile services/user_service.py",
        "working_dir": "."
      }
    },
    {
      "name": "type_check_services",
      "severity": "warning",
      "check_type": {
        "type": "python_type_check",
        "paths": ["services/user_service.py"],
        "checker": "mypy",
        "extra_args": ["--ignore-missing-imports"],
        "working_dir": "."
      }
    },
    {
      "name": "test_suite_passes",
      "severity": "error",
      "check_type": {
        "type": "pytest_result",
        "test_path": "tests/test_user_service.py -v",
        "min_passed": 3,
        "max_failures": 0,
        "working_dir": "."
      }
    },
    {
      "name": "no_circular_imports",
      "check_type": {
        "type": "python_import_graph",
        "root_path": "services",
        "fail_on_circular": true,
        "working_dir": "."
      }
    }
  ]
}
```

## Agent Example: Create from Template

For common scenarios, use templates instead of building checks from scratch:

```json
{
  "template_name": "python_bugfix",
  "agent_id": "claude-sonnet-4-5",
  "task": "Fix off-by-one error in pagination",
  "variables": {
    "working_dir": "/home/user/project",
    "test_path": "tests/test_pagination.py"
  },
  "extra_checks": [
    {
      "name": "no_print_debug",
      "check_type": {
        "type": "file_excludes_patterns",
        "path": "services/pagination.py",
        "forbidden_patterns": ["^\\s*print\\(", "breakpoint\\(\\)"],
        "working_dir": "/home/user/project"
      }
    }
  ]
}
```

## Agent Example: Quick Ad-Hoc Check

When you need to verify a quick assumption during work without creating a full contract, use `verify_quick_check`:

```json
{
  "check": {
    "name": "json_syntax_valid",
    "check_type": {
      "type": "command_succeeds",
      "command": "python -m json.tool assets/data/users.json > /dev/null",
      "working_dir": "."
    }
  }
}
```

## Debugging & History

If you are stuck and repeatedly failing a contract:

- `verify_history` — View past contracts and their outcomes to identify recurring problems.
- `verify_stats` — See aggregate pass rates, most common failures, and agent trust scores.
- `verify_get_audit_trail` — Get the exact lifecycle of a specific contract using its `contract_id`. Useful to track how often an agent failed before passing and what kind of failures occurred.
