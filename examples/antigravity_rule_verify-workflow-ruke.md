---
trigger: always_on
---

# Workspace Rule: Verify MCP Server Integration

# ============================================================

## Grundprinzip: Zero Blind Trust

Der `verify-mcp-server` löst das Problem des "blinden Vertrauens" in Agenten-Workflows. Aufgaben müssen mathematisch und robust durch explizite Verträge bewiesen werden, bevor sie als abgeschlossen gelten. Behauptungen ohne maschinellen Beweis werden als `Unverified` markiert und erzwingen den Status `ReviewRequired`.

## Der Verifizierungs-Zyklus (MANDATORY)

Jede Code-Änderung muss zwingend diesem Ablauf folgen:

1. **DEFINE (Vor der Arbeit):** Rufe `verify_create_contract` auf, um die exakten Bedingungen festzulegen, die der Code erfüllen muss.
2. **WORK:** Schreibe den Code oder führe die Änderungen durch.
3. **VERIFY (Nach der Arbeit):** Rufe `verify_run_contract` mit der generierten Vertrags-ID auf.
4. **FIX:** Wenn der Vertrag fehlschlägt, analysiere die Fehler, korrigiere sie und führe den Vertrag erneut aus, bis er besteht.

## NEU: Kontextsensitive Meta-Validierung

Um zu verhindern, dass kritische Überprüfungen übersprungen werden, erfordert jeder Vertrag zwingend die beiden Metadaten-Felder `agent_id` und `language`. 

Die Meta-Validierungsregeln erzwingen Mindeststandards basierend auf der Sprache:
* **Python-Aufgaben** MÜSSEN die Checks `python_type_check` UND `pytest_result` enthalten.
* **Rust-Aufgaben** MÜSSEN einen `command_succeeds`-Check enthalten, der `cargo test` ausführt.

## Sicherheit und Sandboxing

Der Server schränkt die Befehlsausführung über ein striktes 3-Stufen-Sicherheitsmodell ein:

* **Whitelisted Commands:** Sichere Befehle (`python`, `pytest`, `mypy`, `cargo` etc.) laufen direkt auf dem Host, sofern sie keine gefährlichen Zeichen enthalten.
* **Blocked Patterns:** Befehle mit Shell-Injection-Mustern (z. B. `&&`, `||`, `rm `, `sudo `, `>`) werden sofort blockiert.
* **Sandboxing:** Unbekannte Befehle oder solche mit dem Flag `"sandbox": true` laufen in flüchtigen Podman-Containern (ohne Netzwerk, limitiert auf 512MB RAM und 2 CPUs).

## Auswahl der Check-Typen

Verlasse dich bei Quellcode nicht auf fehleranfälliges Text-Matching. Nutze strukturelle und semantische Checks:

* **`ast_query`:** Nutzt `tree-sitter` für robuste semantische Analysen (z. B. `macro:function_exists:<name>`) unabhängig von der Formatierung.
* **`python_type_check`:** Verwendet `mypy` oder `pyright`, um strukturierte Typfehler zu parsen.
* **`pytest_result`:** Parst Ergebnisse (Passed/Failed/Skipped) und erzwingt Grenzwerte.
* **`python_import_graph`:** Erkennt zirkuläre Importe und erzwingt Architekturgrenzen.
* **`json_registry_consistency`:** Validiert, ob IDs in JSON-Dateien auch in den Python-Registries existieren.
* **LEGACY-HINWEIS:** `file_contains_patterns` und `file_excludes_patterns` sind für Quellcode veraltet. Nutze sie nur für einfache Text- oder Log-Dateien.

---

## Agenten-Beispiel: Einen Vertrag definieren (inkl. Meta-Validierung)

Hier ist ein vollständiges, aktuelles JSON-Beispiel für den Aufruf von `verify_create_contract`. Dieses Beispiel definiert eine strikte Python-Aufgabe und enthält nun die erforderlichen Metadaten-Felder.

```json
{
  "description": "Implement sorting logic and stabilize user module",
  "task": "Add sort_users_by_age to user_service.py, ensure type safety, and verify no circular imports in the services package.",
  "agent_id": "claude-3-7-sonnet",
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
    }
  ]
}

```

## Agenten-Beispiel: Schneller Ad-Hoc Check

Wenn du während der Arbeit eine schnelle Annahme überprüfen musst, ohne einen vollständigen Vertrag zu erstellen, verwende das `verify_quick_check` Tool.

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