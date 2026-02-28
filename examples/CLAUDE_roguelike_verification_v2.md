# ============================================================
# Verification Workflow (verify MCP server)
# ============================================================
# Append this section to the existing CLAUDE.md
# ============================================================

## Verification Workflow (MANDATORY)

This project uses the `verify` MCP server for contract-based verification.
**Every code change MUST follow the Define → Work → Verify → Fix loop.**

### The Loop

1. **BEFORE writing code:** Call `verify_create_contract` with checks tailored to the task
2. **Write the code** as normal
3. **AFTER writing code:** Call `verify_run_contract` with the contract ID
4. **If FAILED:** Fix issues, run contract again. Repeat until it passes.
5. **Once PASSED:** Create the git commit (per existing rule: commit after every completed task)

**Never skip verification.** Not because you're "confident", not for small changes, not for JSON-only edits.

---

## Baseline Checks (ALWAYS include)

Every contract must include these three checks, adapted to the files you touched:

```json
[
  {
    "name": "syntax_valid",
    "check_type": {
      "type": "command_succeeds",
      "command": "python -m py_compile <CHANGED_FILE>",
      "working_dir": "."
    }
  },
  {
    "name": "imports_resolve",
    "check_type": {
      "type": "command_succeeds",
      "command": "python -c \"import <DOTTED_MODULE_PATH>\"",
      "working_dir": "."
    }
  },
  {
    "name": "full_test_suite",
    "check_type": {
      "type": "command_succeeds",
      "command": "python -m pytest tests/ -x -q --tb=short",
      "working_dir": ".",
      "timeout_secs": 120
    }
  }
]
```

Replace `<CHANGED_FILE>` with actual path (e.g. `ecs/systems/ai_system.py`) and `<DOTTED_MODULE_PATH>` with the Python import path (e.g. `ecs.systems.ai_system`).

---

> [!NOTE]
> **Legacy Notice:** `file_contains_patterns` and `file_excludes_patterns` are considered legacy for source code verification. For code files (Python, Rust, etc.), prefer **`ast_query`** which uses `tree-sitter` for semantic analysis and is robust against format changes. The pattern checks remain useful for simple text files like READMEs or JSON logs.

## Check Templates by Area

Add these checks **on top of the baseline** depending on what you're changing:

### ECS Components (`ecs/components.py`)

```json
{
  "name": "component_is_dataclass",
  "check_type": {
    "type": "ast_query",
    "language": "python",
    "path": "ecs/components.py",
    "query": "macro:class_exists:<NewComponent>"
  }
},
{
  "name": "no_side_effect_methods_in_components",
  "check_type": {
    "type": "ast_query",
    "language": "python",
    "path": "ecs/components.py",
    "query": "macro:imports_module:esper",
    "mode": "forbidden"
  }
}
```

### ECS Frame Processors (`ecs/systems/`)

```json
{
  "name": "system_file_exists",
  "check_type": {
    "type": "file_exists",
    "path": "ecs/systems/<system_file>.py"
  }
},
{
  "name": "processor_has_process_method",
  "check_type": {
    "type": "ast_query",
    "language": "python",
    "path": "ecs/systems/<system_file>.py",
    "query": "macro:function_exists:process"
  }
},
{
  "name": "uses_esper_module_not_world_instance",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "ecs/systems/<system_file>.py",
    "forbidden_patterns": ["esper\\.World\\(", "self\\.world\\.", "world = esper\\.World"]
  }
},
{
  "name": "no_stored_entity_references",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "ecs/systems/<system_file>.py",
    "forbidden_patterns": ["self\\._entities", "self\\.entities", "self\\.player_entity"]
  },
  "severity": "warning"
},
{
  "name": "system_specific_tests_pass",
  "check_type": {
    "type": "command_succeeds",
    "command": "python -m pytest tests/verify_<system_name>.py -v --tb=short",
    "working_dir": ".",
    "timeout_secs": 60
  }
}
```

### MapAwareSystem Subclasses

If the system uses `MapAwareSystem`, add:

```json
{
  "name": "inherits_map_aware_system",
  "check_type": {
    "type": "file_contains_patterns",
    "path": "ecs/systems/<system_file>.py",
    "required_patterns": ["MapAwareSystem", "def set_map\\(self"]
  }
},
{
  "name": "no_map_container_in_constructor",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "ecs/systems/<system_file>.py",
    "forbidden_patterns": ["def __init__\\(self,\\s*map_container"]
  }
}
```

### Services (`services/`)

```json
{
  "name": "service_test_exists",
  "check_type": {
    "type": "file_exists",
    "path": "tests/verify_<service_name>.py"
  },
  "severity": "warning"
},
{
  "name": "service_tests_pass",
  "check_type": {
    "type": "command_succeeds",
    "command": "python -m pytest tests/verify_<service_name>.py -v --tb=short",
    "working_dir": ".",
    "timeout_secs": 60
  }
},
{
  "name": "uses_logging_not_print",
  "check_type": {
    "type": "file_contains_patterns",
    "path": "services/<service>.py",
    "required_patterns": ["import logging", "logger|log"]
  }
}
```

### JSON Data (`assets/data/`)

```json
{
  "name": "json_syntax_valid",
  "check_type": {
    "type": "command_succeeds",
    "command": "python -m json.tool assets/data/<file>.json > /dev/null",
    "working_dir": "."
  }
},
{
  "name": "all_json_files_valid",
  "check_type": {
    "type": "command_succeeds",
    "command": "python -c \"import json, glob; [json.load(open(f)) for f in glob.glob('assets/data/**/*.json', recursive=True)]\"",
    "working_dir": "."
  }
},
{
  "name": "sprite_layers_use_enum_names",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "assets/data/<file>.json",
    "forbidden_patterns": ["\"sprite_layer\":\\s*\\d"]
  },
  "severity": "warning"
}
```

### Entity/Item Templates (`entities/`)

```json
{
  "name": "factory_function_exists",
  "check_type": {
    "type": "ast_query",
    "language": "python",
    "path": "entities/<factory_file>.py",
    "query": "macro:function_exists:create"
  }
},
{
  "name": "uses_registry_not_hardcode",
  "check_type": {
    "type": "file_contains_patterns",
    "path": "entities/<factory_file>.py",
    "required_patterns": ["Registry\\.get|registry\\.get|_registry"]
  }
}
```

### Map Code (`map/`)

```json
{
  "name": "map_tests_pass",
  "check_type": {
    "type": "command_succeeds",
    "command": "python -m pytest tests/ -k 'map or tile or layer or portal' -v --tb=short",
    "working_dir": ".",
    "timeout_secs": 60
  }
},
{
  "name": "uses_tile_registry_not_hardcoded_props",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "map/<file>.py",
    "forbidden_patterns": ["walkable\\s*=\\s*(True|False)", "Tile\\(.*sprite="]
  },
  "severity": "warning"
},
{
  "name": "no_hardcoded_map_dimensions",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "map/<file>.py",
    "forbidden_patterns": ["range\\(80\\)", "range\\(50\\)", "width\\s*=\\s*80", "height\\s*=\\s*50"]
  },
  "severity": "warning"
}
```

### AI Behavior (`ecs/systems/ai_system.py`)

```json
{
  "name": "ai_tests_pass",
  "check_type": {
    "type": "command_succeeds",
    "command": "python -m pytest tests/verify_ai_system.py -v --tb=short",
    "working_dir": ".",
    "timeout_secs": 60
  }
},
{
  "name": "uses_ecs_query_not_stored_refs",
  "check_type": {
    "type": "file_contains_patterns",
    "path": "ecs/systems/ai_system.py",
    "required_patterns": ["esper\\.get_component"]
  }
},
{
  "name": "has_traceability_comments",
  "check_type": {
    "type": "file_contains_patterns",
    "path": "ecs/systems/ai_system.py",
    "required_patterns": ["AISYS-|CHAS-|WNDR-"]
  },
  "severity": "info"
}
```

---

## Forbidden Patterns (global)

Include relevant subset in every contract:

```json
{
  "name": "no_print_statements",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "<file>",
    "forbidden_patterns": ["^\\s*print\\(", "breakpoint\\(\\)", "pdb\\.set_trace"]
  }
},
{
  "name": "no_esper_world_instantiation",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "<file>",
    "forbidden_patterns": ["esper\\.World\\("]
  }
},
{
  "name": "no_bare_except",
  "check_type": {
    "type": "file_excludes_patterns",
    "path": "<file>",
    "forbidden_patterns": ["except:\\s*$"]
  }
}
```

---

## Python-Specific Checks

These check types provide deeper Python analysis than generic command/pattern checks.

### Type Checking (mypy/pyright)

Use instead of `command_succeeds` with mypy — gives structured error counts and details:

```json
{
  "name": "type_check_systems",
  "check_type": {
    "type": "python_type_check",
    "paths": ["ecs/systems/", "services/"],
    "checker": "mypy",
    "extra_args": ["--ignore-missing-imports"],
    "working_dir": "."
  },
  "severity": "warning"
}
```

### Structured Pytest Results

Use instead of `command_succeeds` with pytest — enforces thresholds on pass/fail/skip:

```json
{
  "name": "test_suite_quality",
  "check_type": {
    "type": "pytest_result",
    "test_path": "tests/ -x --tb=short",
    "min_passed": 40,
    "max_failures": 0,
    "max_skipped": 5,
    "working_dir": "."
  }
}
```

For system-specific tests:

```json
{
  "name": "ai_system_tests",
  "check_type": {
    "type": "pytest_result",
    "test_path": "tests/verify_ai_system.py -v",
    "min_passed": 5,
    "max_failures": 0,
    "working_dir": "."
  }
}
```

### Circular Import Detection

**Use this on every change that adds new imports between packages.** The ECS architecture
with components, systems, services, and entities has high circular import risk:

```json
{
  "name": "no_circular_imports_ecs",
  "check_type": {
    "type": "python_import_graph",
    "root_path": "ecs",
    "fail_on_circular": true,
    "working_dir": "."
  }
},
{
  "name": "no_circular_imports_services",
  "check_type": {
    "type": "python_import_graph",
    "root_path": "services",
    "fail_on_circular": true,
    "working_dir": "."
  }
},
{
  "name": "no_circular_imports_entities",
  "check_type": {
    "type": "python_import_graph",
    "root_path": "entities",
    "fail_on_circular": true,
    "working_dir": "."
  }
}
```

### JSON ↔ Registry Consistency

Verify that all IDs defined in JSON data files are actually registered/used in Python code.
**Use this when adding new entities, items, tiles, or schedules:**

```json
{
  "name": "all_entity_ids_registered",
  "check_type": {
    "type": "json_registry_consistency",
    "json_path": "assets/data/entities.json",
    "id_field": "id",
    "source_path": "entities/entity_registry.py"
  }
},
{
  "name": "all_item_ids_registered",
  "check_type": {
    "type": "json_registry_consistency",
    "json_path": "assets/data/items.json",
    "id_field": "id",
    "source_path": "entities/item_registry.py"
  }
},
{
  "name": "all_tile_ids_registered",
  "check_type": {
    "type": "json_registry_consistency",
    "json_path": "assets/data/tile_types.json",
    "id_field": "id",
    "source_path": "map/tile_registry.py"
  }
},
{
  "name": "all_schedule_ids_registered",
  "check_type": {
    "type": "json_registry_consistency",
    "json_path": "assets/data/schedules.json",
    "id_field": "id",
    "source_path": "entities/schedule_registry.py"
  }
}
```

---

## Quick Check Examples

Use `verify_quick_check` for ad-hoc checks during work:

**"Does the game still import?"**
```json
{ "check": { "name": "game_imports", "check_type": { "type": "command_succeeds", "command": "python -c \"from game_states import Game\"", "working_dir": "." } } }
```

**"Do the smoke tests pass?"**
```json
{ "check": { "name": "smoke", "check_type": { "type": "command_succeeds", "command": "python -m pytest tests/verify_smoke*.py -v --tb=short", "working_dir": ".", "timeout_secs": 60 } } }
```

**"Is this JSON valid?"**
```json
{ "check": { "name": "json_ok", "check_type": { "type": "command_succeeds", "command": "python -m json.tool assets/data/scenarios/village.json > /dev/null", "working_dir": "." } } }
```

---

## Full Contract Example: Adding a New ECS Phase System

Task: "Add ScheduleSystem that processes NPC schedules during ENEMY_TURN"

```json
{
  "description": "New ScheduleSystem phase system",
  "task": "Create ScheduleSystem that updates NPC Activity components based on WorldClockService time during ENEMY_TURN phase",
  "agent_id": "claude-3.7-sonnet",
  "language": "python",
  "checks": [
    {
      "name": "syntax_valid",
      "check_type": { "type": "command_succeeds", "command": "python -m py_compile ecs/systems/schedule_system.py", "working_dir": "." }
    },
    {
      "name": "imports_resolve",
      "check_type": { "type": "command_succeeds", "command": "python -c \"from ecs.systems.schedule_system import ScheduleSystem\"", "working_dir": "." }
    },
    {
      "name": "file_exists",
      "check_type": { "type": "file_exists", "path": "ecs/systems/schedule_system.py" }
    },
    {
      "name": "has_process_method",
      "check_type": { "type": "ast_query", "language": "python", "path": "ecs/systems/schedule_system.py", "query": "macro:function_exists:process" }
    },
    {
      "name": "queries_schedule_and_activity",
      "check_type": { "type": "file_contains_patterns", "path": "ecs/systems/schedule_system.py", "required_patterns": ["esper\\.get_component", "Schedule", "Activity"] }
    },
    {
      "name": "uses_esper_module_level",
      "check_type": { "type": "file_excludes_patterns", "path": "ecs/systems/schedule_system.py", "forbidden_patterns": ["esper\\.World\\(", "self\\.world"] }
    },
    {
      "name": "no_stored_entity_refs",
      "check_type": { "type": "file_excludes_patterns", "path": "ecs/systems/schedule_system.py", "forbidden_patterns": ["self\\._entities", "self\\.player_ent"] },
      "severity": "warning"
    },
    {
      "name": "no_print",
      "check_type": { "type": "file_excludes_patterns", "path": "ecs/systems/schedule_system.py", "forbidden_patterns": ["^\\s*print\\("] }
    },
    {
      "name": "uses_logging",
      "check_type": { "type": "file_contains_patterns", "path": "ecs/systems/schedule_system.py", "required_patterns": ["import logging"] },
      "severity": "warning"
    },
    {
      "name": "test_file_exists",
      "check_type": { "type": "file_exists", "path": "tests/verify_schedule_system.py" },
      "severity": "warning"
    },
    {
      "name": "all_tests_structured",
      "check_type": {
        "type": "pytest_result",
        "test_path": "tests/ -x --tb=short",
        "min_passed": 40,
        "max_failures": 0,
        "working_dir": "."
      }
    },
    {
      "name": "no_circular_imports_ecs",
      "check_type": {
        "type": "python_import_graph",
        "root_path": "ecs",
        "fail_on_circular": true,
        "working_dir": "."
      }
    },
    {
      "name": "schedule_ids_consistent",
      "check_type": {
        "type": "json_registry_consistency",
        "json_path": "assets/data/schedules.json",
        "id_field": "id",
        "source_path": "entities/schedule_registry.py"
      }
    },
    {
      "name": "type_check",
      "check_type": {
        "type": "python_type_check",
        "paths": ["ecs/systems/schedule_system.py"],
        "checker": "mypy",
        "extra_args": ["--ignore-missing-imports"],
        "working_dir": "."
      },
      "severity": "warning"
    },
    {
      "name": "diff_is_focused",
      "check_type": { "type": "diff_size_limit", "max_additions": 250, "max_deletions": 50 },
      "severity": "warning"
    }
  ]
}
```
