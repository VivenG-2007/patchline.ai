# Unit tests for the two-engine deterministic scanner
# (app/services/deterministic_scanner.py + app/services/scanning/*).
#
# The Semgrep subprocess itself is NOT exercised here — that needs the real
# `semgrep` binary and is exactly the kind of environment-dependent call
# unit tests should avoid. Instead:
#   - regex_rules is tested directly (pure Python, no subprocess)
#   - semgrep_engine's pure-Python helpers (path safety, result parsing,
#     severity mapping) are tested directly against fixture data shaped
#     like real semgrep --json output
#   - the orchestrator's merge/dedupe logic is tested by monkeypatching
#     both engines, so it's exercised without invoking either for real

import os
from pathlib import Path

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")


from app.services import deterministic_scanner
from app.services.scanning import regex_rules, semgrep_engine, treesitter_engine


# ──────────────────────── regex_rules ────────────────────────

def test_regex_sqli_fstring_detected():
    findings = regex_rules.scan_file("app.py", 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")')
    assert any(f["ruleKey"] == "sqli-py-fstring" for f in findings)
    assert all(f["engine"] == "regex" for f in findings)


def test_regex_no_findings_on_clean_file():
    findings = regex_rules.scan_file("app.py", "def add(a, b):\n    return a + b\n")
    assert findings == []


def test_regex_dedupes_same_rule_same_line():
    # \bDES\b would match "DES" twice on one line without the seen_lines guard.
    findings = regex_rules.scan_file("cipher.py", "cipher = DES.new(key, DES.MODE_ECB)")
    des_findings = [f for f in findings if f["ruleKey"] == "crypto-des"]
    assert len(des_findings) == 1


# ──────────────────────── semgrep_engine helpers ────────────────────────

def test_safe_relpath_rejects_traversal():
    assert semgrep_engine._safe_relpath("../../etc/passwd") is None
    assert semgrep_engine._safe_relpath("a/../../b") is None


def test_safe_relpath_strips_leading_slash_and_rejects_empty():
    # An absolute path isn't a traversal by itself — it's just made relative
    # to the temp dir like everything else; only ".." segments are rejected.
    assert semgrep_engine._safe_relpath("/etc/passwd") == "etc/passwd"
    assert semgrep_engine._safe_relpath("") is None
    assert semgrep_engine._safe_relpath(".") is None


def test_safe_relpath_allows_normal_paths():
    assert semgrep_engine._safe_relpath("src/app.py") == "src/app.py"
    assert semgrep_engine._safe_relpath("./src/app.py") == "src/app.py"


def test_parse_results_maps_finding_shape():
    payload = {
        "results": [
            {
                "check_id": "semgrep-rules.patchline-rules.sqli-py-concat",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {
                    "message": "SQL string built by concatenation. More detail here.",
                    "severity": "ERROR",
                    "lines": 'cursor.execute("SELECT * FROM t WHERE id=" + user_id)',
                    "metadata": {
                        "category": "SQL Injection",
                        "severity_label": "HIGH",
                        "suggested_fix": "Use parameterized queries.",
                    },
                },
            }
        ],
        "errors": [],
    }
    path_map = {"app.py": "services/app.py"}
    # _parse_results also takes the semgrep scan's cwd (target_dir) now, so it
    # can strip a leaked temp-dir prefix from a result path defensively (see
    # semgrep_engine.py) — any Path works here since none of this fixture's
    # paths are absolute / prefixed with it.
    findings = semgrep_engine._parse_results(payload, path_map, Path("/tmp/patchline-scan"))
    assert len(findings) == 1
    f = findings[0]
    assert f["ruleKey"] == "sqli-py-concat"
    assert f["file"] == "services/app.py"
    assert f["line"] == 12
    assert f["category"] == "SQL Injection"
    assert f["severity"] == "HIGH"
    assert f["engine"] == "semgrep"
    assert f["title"] == "SQL string built by concatenation"


def test_severity_falls_back_to_semgrep_severity_when_no_label():
    assert semgrep_engine._severity_for({}, "ERROR") == "HIGH"
    assert semgrep_engine._severity_for({}, "WARNING") == "MEDIUM"
    assert semgrep_engine._severity_for({}, "INFO") == "LOW"
    assert semgrep_engine._severity_for({"severity_label": "CRITICAL"}, "WARNING") == "CRITICAL"


# ──────────────────────── orchestrator ────────────────────────

def _finding(engine, file, line, category, rule_key):
    return {
        "ruleKey": rule_key, "category": category, "severity": "HIGH", "title": rule_key,
        "file": file, "line": line, "description": "", "suggestedFix": "", "snippet": "",
        "engine": engine,
    }


def test_dedupe_prefers_semgrep_over_regex_on_same_line():
    findings = [
        _finding("semgrep", "app.py", 10, "SQL Injection", "sqli-py-concat"),
        _finding("regex", "app.py", 10, "SQL Injection", "sqli-py-concat-regex"),
    ]
    deduped = deterministic_scanner._dedupe(findings)
    assert len(deduped) == 1
    assert deduped[0]["engine"] == "semgrep"


def test_dedupe_keeps_findings_only_one_engine_caught():
    findings = [
        _finding("semgrep", "app.py", 10, "SQL Injection", "sqli-py-concat"),
        _finding("regex", "app.py", 99, "Hardcoded Secret", "secret-aws-key"),
    ]
    deduped = deterministic_scanner._dedupe(findings)
    assert len(deduped) == 2


def test_scan_repo_files_assigns_sequential_ids_after_merge(monkeypatch):
    monkeypatch.setattr(
        semgrep_engine, "scan_paths",
        lambda files: [_finding("semgrep", "a.py", 1, "SQL Injection", "sqli-py-concat")],
    )
    monkeypatch.setattr(
        regex_rules, "scan_file",
        lambda path, content: [_finding("regex", "b.py", 5, "Hardcoded Secret", "secret-aws-key")],
    )
    files = [{"path": "a.py", "content": "x"}, {"path": "b.py", "content": "y"}]
    result = deterministic_scanner.scan_repo_files(files)
    assert [f["id"] for f in result] == ["DET-001", "DET-002"]
    assert all(f["source"] == "deterministic" for f in result)


def test_scan_repo_files_empty_input_returns_empty():
    assert deterministic_scanner.scan_repo_files([]) == []


# ──────────────────────── orchestrator: three-engine evidence merge ────────────────────────

def test_dedupe_merges_three_engines_into_one_finding_with_evidence():
    findings = [
        _finding("semgrep", "app.py", 42, "SQL Injection", "sqli-py-concat"),
        _finding("regex", "app.py", 42, "SQL Injection", "sqli-py-concat"),
        _finding("treesitter", "app.py", 42, "SQL Injection", "sqli-py-dynamic-execute"),
    ]
    deduped = deterministic_scanner._dedupe(findings)
    assert len(deduped) == 1
    # Semgrep still wins as the primary finding's text/engine...
    assert deduped[0]["engine"] == "semgrep"
    # ...but all three engines that independently agreed show up as evidence.
    assert deduped[0]["evidence"] == ["semgrep", "regex", "treesitter"]


def test_dedupe_single_engine_finding_has_single_item_evidence():
    findings = [_finding("treesitter", "app.py", 7, "Command Injection", "cmdi-py-os-system-dynamic")]
    deduped = deterministic_scanner._dedupe(findings)
    assert deduped[0]["evidence"] == ["treesitter"]


# ──────────────────────── treesitter_engine ────────────────────────

def test_treesitter_language_for_known_and_unknown_extensions():
    assert treesitter_engine._language_for("app.py") == "python"
    assert treesitter_engine._language_for("Component.tsx") == "tsx"
    assert treesitter_engine._language_for("data.bin") is None


def test_treesitter_scan_file_degrades_gracefully_without_grammar():
    # In this test environment the tree-sitter-language-pack grammars may
    # not be importable; either way scan_file must never raise — it degrades
    # to no findings for that file rather than taking the scan down.
    findings = treesitter_engine.scan_file("app.py", "cursor.execute(f\"SELECT * FROM t WHERE id={x}\")")
    assert isinstance(findings, list)
