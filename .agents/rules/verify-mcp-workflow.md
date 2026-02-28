---
trigger: always_on
---

# Workspace Rule: Verify MCP Server Integration

# ============================================================

## Core Principle: Zero Blind Trust

The `verify-mcp-server` exists to solve the "blind trust" problem in agentic workflows. You must mathematically and robustly prove your work using explicit contracts before declaring a task complete. If you assert a claim without computational proof, the server will mark it as `Unverified`, forcing a `ReviewRequired` state.

## The Verification Loop (MANDATORY)

Every code change must strictly follow this cycle:

1. **DEFINE (Before work):** Call `verify_create_contract` to establish the exact conditions the code must meet.
2. **WORK:** Write the code or perform the necessary modifications.
3. **VERIFY (After work):** Call `verify_run_contract` using the generated contract ID.
4. **FIX:** If the contract fails, analyze the output, fix the issues, and run the contract again until it passes.

## Security and Sandboxing

The server restricts command execution using a strict 3-tier security model:

* **Whitelisted Commands:** Safe commands like `python`, `pytest`, `mypy`, and `cargo` execute directly on the host if they do not contain dangerous characters.
* **Blocked Patterns:** Payloads containing shell-injection patterns (e.g., `&&`, `||`, `rm `, `sudo `, `>`) are immediately rejected.
* **Sandboxing:** Unknown commands, or checks explicitly flagged with `"sandbox": true`, run inside ephemeral Podman containers with no network, limited to 512MB RAM and 2 CPUs.

## Selecting Check Types

Do not rely on brittle text matching for source code. Use structural and semantic checks.

* **`ast_query`:** Uses `tree-sitter` for robust semantic analysis (e.g., `macro:function_exists:<name>`) regardless of formatting.
* **`python_type_check`:** Uses `mypy` or `pyright` to parse structured type errors.
* **`pytest_result`:** Parses pass/fail/skip counts and enforces thresholds.
* **`python_import_graph`:** Detects circular imports and enforces architectural boundaries.
* **`json_registry_consistency`:** Validates that IDs in JSON data files actually exist in Python registries.
* **LEGACY NOTICE:** `file_contains_patterns` and `file_excludes_patterns` are legacy for source code. Use them exclusively for simple text files like READMEs or JSON logs.

---

## Agent Example: Defining a Contract

Below is a complete, deployable JSON payload example for a `verify_create_contract` tool call. This example defines a strict Python development task.

```json
{
  "description": "Implement sorting logic and stabilize user module",
  "task": "Add sort_users_by_age to user_service.py, ensure type safety, and verify no circular imports in the services package.",
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
      "name": "function_exists_ast",
      "severity": "error",
      "check_type": {
        "type": "ast_query",
        "language": "python",
        "path": "services/user_service.py",
        "query": "macro:function_exists:sort_users_by_age",
        "mode": "required"
      }
    },
    {
      "name": "no_print_statements",
      "severity": "error",
      "check_type": {
        "type": "file_excludes_patterns",
        "path": "services/user_service.py",
        "forbidden_patterns": ["^\\s*print\\("]
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
      "severity": "error",
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

## Agent Example: Quick Ad-Hoc Check

If you need to verify a quick assumption during your work without creating a full contract, use the `verify_quick_check` tool.

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