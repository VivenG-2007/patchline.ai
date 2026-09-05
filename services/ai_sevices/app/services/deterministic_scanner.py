"""
Deterministic scanner — orchestrates three engines and merges their output
into the single primary finding source for the platform (see
docs/architecture.md). No LLM call, no token cost, fully reproducible.

  1. semgrep_engine  — AST-based SAST engine (app/services/scanning/
     semgrep_engine.py), rules in semgrep-rules/patchline-rules.yml. This is
     the precision layer: matches real code structure via a dedicated SAST
     engine, not text shape.
  2. treesitter_engine — in-process AST engine (app/services/scanning/
     treesitter_engine.py). Parses each file once with Tree-sitter and
     re-derives the same categories from real syntax nodes (a call whose
     argument is a concatenation/interpolation, not a literal). Runs
     alongside Semgrep as a second, independent structural signal and as a
     same-process fallback if the semgrep binary is unavailable.
  3. regex_rules     — line-based regex detectors (app/services/scanning/
     regex_rules.py), kept as (a) the engine for text-shape-only categories
     like hardcoded secrets, and (b) a same-process fallback so a scan still
     produces deterministic findings if neither of the above is available.

The AI layer (see routers/scanner.py) does two separate things on top of
this combined output:
  1. Explains/enriches each deterministic finding with a contextual
     description + suggested fix (still tagged source="deterministic"),
     using the `evidence` list below (which engines independently agreed on
     this finding) as part of what it's given.
  2. Runs its own supplementary scan for issues none of the three engines
     here can catch (business logic, auth/authz, insecure design) — tagged
     source="ai" and always reported as EXTRA findings, never replacing a
     deterministic one.

Deliberately conservative and over-broad rather than exhaustive: false
positives are cheap here because nothing merges without human review; false
negatives are partially offset by the AI supplemental pass.
"""

from app.core.logging import get_logger
from app.services.scanning import regex_rules, semgrep_engine, treesitter_engine

logger = get_logger()

# Precedence used to pick which engine's finding "wins" as the primary
# text/severity/description when more than one engine fires at the same
# (file, line, category): Semgrep is the most precise (real SAST engine),
# regex is the plain-text fallback, Tree-sitter's structural findings exist
# mainly as corroborating evidence for the other two (and as their own
# same-process fallback when neither is available).
_ENGINE_PRECEDENCE = {"semgrep": 0, "regex": 1, "treesitter": 2}


def _dedupe(findings: list[dict]) -> list[dict]:
    """Group findings by (file, line, category) across all three engines.
    Each group collapses to ONE finding — text/severity taken from whichever
    engine fired with the highest precedence — with an `evidence` list
    recording every engine that independently caught it. A finding only one
    engine caught still comes through with a single-item evidence list, so
    this is a strict generalization of the old semgrep-vs-regex-only
    behavior, not a change to it."""
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for f in findings:
        key = (f["file"], f["line"], f["category"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    deduped: list[dict] = []
    for key in order:
        group = sorted(groups[key], key=lambda f: _ENGINE_PRECEDENCE.get(f.get("engine"), 99))
        primary = dict(group[0])
        evidence: list[str] = []
        for f in group:
            eng = f.get("engine")
            if eng and eng not in evidence:
                evidence.append(eng)
        primary["evidence"] = sorted(evidence, key=lambda e: _ENGINE_PRECEDENCE.get(e, 99))
        deduped.append(primary)
    return deduped


def scan_file(path: str, content: str) -> list[dict]:
    """Run all three engines against one file's content and return the
    merged, deduped finding list. Used directly by _rescan_verify_fix
    (routers/scanner.py) to independently re-check a single finding's
    ruleKey against post-fix content — works unchanged for rules from any
    engine, since ruleKey is unique across all three rule packs."""
    if not content:
        return []
    combined = (
        semgrep_engine.scan_file(path, content)
        + treesitter_engine.scan_file(path, content)
        + regex_rules.scan_file(path, content)
    )
    return _dedupe(combined)


def scan_repo_files(files: list[dict]) -> list[dict]:
    """
    Run all three engines across the full file set — Semgrep in one batched
    subprocess call, Tree-sitter and regex rules per-file in-process —
    merge, dedupe (with cross-engine evidence), and assign sequential
    DET-### ids. This is the platform's primary finding source; AI-only
    findings are appended separately with an AI- prefix.
    """
    if not files:
        return []

    print(f"[SCANNER] Starting deterministic SAST across {len(files)} files...", flush=True)
    semgrep_findings = semgrep_engine.scan_paths(files)
    print(f"[SEMGREP] Checked patchline-rules.yml rulesets -> {len(semgrep_findings)} matches found", flush=True)
    
    treesitter_findings = treesitter_engine.scan_paths(files)
    print(f"[TREE-SITTER] AST structural parser evaluated -> {len(treesitter_findings)} AST taint paths matched", flush=True)

    regex_findings: list[dict] = []
    for f in files:
        regex_findings.extend(regex_rules.scan_file(f["path"], f.get("content", "")))
    print(f"[REGEX] Pattern scanner -> {len(regex_findings)} matches found", flush=True)

    combined = _dedupe(semgrep_findings + treesitter_findings + regex_findings)
    print(f"[SAST_SUMMARY] Combined & deduplicated findings: {len(combined)} (Semgrep: {len(semgrep_findings)}, Tree-sitter AST: {len(treesitter_findings)}, Regex: {len(regex_findings)})", flush=True)

    logger.info(
        "deterministic_scan_engines_summary",
        semgrep_raw=len(semgrep_findings), treesitter_raw=len(treesitter_findings), regex_raw=len(regex_findings),
        combined_after_dedupe=len(combined),
    )


    for i, finding in enumerate(combined, start=1):
        finding["id"] = f"DET-{i:03d}"
        finding["source"] = "deterministic"

    return combined
