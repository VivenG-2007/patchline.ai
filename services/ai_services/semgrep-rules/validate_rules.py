#!/usr/bin/env python3
"""Validate patchline-rules.yml against the annotated fixtures in this
directory (test_*.py / .js / .tsx / .php / .html / .txt).

Why this exists instead of `semgrep --test`:
`semgrep scan --test` crashes on every currently-released semgrep version
(1.99.0 here, confirmed still broken on the latest release too) with
`IndexError: tuple index out of range` in `relatively_eq` when the rule
config is a single file rather than a directory —
https://github.com/semgrep/semgrep/issues/11391. Rather than block rule
validation on an upstream fix, this script does the same job `--test` is
supposed to do: run the real rule pack against fixture files annotated
with `ruleid:` / `ok:` comments (same convention semgrep's own `--test`
uses) and assert every one matches.

Usage:
    cd services/ai-storage-service/semgrep-rules
    python3 validate_rules.py

Exits non-zero (and prints every mismatch) if any rule fires where an
`ok:` comment says it shouldn't, fails to fire where a `ruleid:` comment
says it should, or if any rule in patchline-rules.yml never fires in any
fixture (silent dead-rule detection — a rule with zero coverage is a rule
whose pattern syntax could be silently broken and no one would know).

Annotation convention (matches semgrep's own `--test` format): a comment
on the line immediately before the code under test.
    # ruleid: sqli-py-concat        <- Python/generic (#), JS/TS/PHP (//)
    cursor.execute("..." + x)          the line right after must match

    # ok: sqli-py-concat
    cursor.execute("...", (x,))        the line right after must NOT match

JSX/TSX and HTML fixtures use `{/* ruleid: ... */}` / `<!-- ruleid: ... -->`.
"""
import glob
import json
import re
import subprocess
import sys
from pathlib import Path

RULES_FILE = "patchline-rules.yml"
ANNOTATION = re.compile(r"(?:#|//|<!--|\{/\*)\s*(ruleid|ok):\s*([\w-]+)")


def run_semgrep() -> dict:
    proc = subprocess.run(
        ["semgrep", "--config", RULES_FILE, ".", "--json", "--metrics=off"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):  # 1 = findings present, still success
        print(proc.stderr, file=sys.stderr)
        sys.exit(f"semgrep exited {proc.returncode}")
    return json.loads(proc.stdout)


def load_all_rule_ids() -> set:
    # Regex instead of a YAML parser on purpose: neither PyYAML nor
    # ruamel.yaml is a declared dependency of this service (semgrep pulls
    # in ruamel.yaml transitively, but relying on that would be an
    # undeclared dependency). Every rule in this file follows the same
    # `- id: <value>` shape as the first key, so this is a safe, dependency-
    # free way to enumerate rule ids for the dead-rule check below.
    text = Path(RULES_FILE).read_text()
    return set(re.findall(r"^\s*-\s*id:\s*(\S+)\s*$", text, re.MULTILINE))


def main() -> int:
    data = run_semgrep()

    hits: dict[tuple[str, int], set] = {}
    for r in data["results"]:
        key = (r["path"], r["start"]["line"])
        hits.setdefault(key, set()).add(r["check_id"].split(".")[-1])

    fired_rule_ids = {r["check_id"].split(".")[-1] for r in data["results"]}

    failures = []
    total = 0
    fixture_files = [f for f in glob.glob("test_*") if Path(f).is_file()]
    if not fixture_files:
        sys.exit("No test_* fixture files found next to patchline-rules.yml")

    for fname in fixture_files:
        with open(fname) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            m = ANNOTATION.search(line)
            if not m:
                continue
            kind, rule_id = m.group(1), m.group(2)
            target_line = i + 2  # annotation is on the line before the code
            actual = hits.get((fname, target_line), set())
            total += 1
            ok = (rule_id in actual) if kind == "ruleid" else (rule_id not in actual)
            if not ok:
                failures.append(
                    f"{fname}:{target_line} expected {kind}={rule_id}, semgrep reported {sorted(actual) or 'nothing'}"
                )

    all_rules = load_all_rule_ids()
    dead_rules = all_rules - fired_rule_ids
    for rid in sorted(dead_rules):
        failures.append(f"rule '{rid}' never fired against any fixture (zero coverage)")

    print(f"{total - len([f for f in failures if 'expected' in f])}/{total} annotation checks passed")
    print(f"{len(all_rules) - len(dead_rules)}/{len(all_rules)} rules fired at least once")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\nAll rules validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
