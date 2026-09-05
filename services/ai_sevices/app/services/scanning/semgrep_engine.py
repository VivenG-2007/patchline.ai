"""
Semgrep-based SAST engine — the AST-driven half of the deterministic
scanner (see app/services/deterministic_scanner.py for the orchestrator
that merges this with regex_rules.py).

Unlike the regex layer, this engine understands code structure: a rule like
sqli-py-concat (semgrep-rules/patchline-rules.yml) only fires on a genuine
"string literal + expression passed to execute()" AST match, not on any
line that happens to contain both ".execute(" and a "+" character. That's
the actual precision gain a real SAST engine is expected to bring over
line-based regex.

Semgrep runs as a subprocess (the `semgrep` CLI from the `semgrep` PyPI
package — it ships a bundled native binary, no separate install step).
Findings come back as JSON on stdout. This module never executes the
scanned code, only reads it — same "read via API, don't clone/exec"
posture as ai-storage-service's GitHub file collection (docs/security.md).

Failure posture: any problem here (binary missing, timeout, bad JSON,
non-zero exit) logs a warning and returns an empty list rather than
raising — a semgrep hiccup degrades a scan to "regex findings only", never
takes the whole scan down. See regex_rules.py's module docstring for why
that fallback exists.
"""

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from app.config import get_settings
from app.core.logging import get_logger
from app.services import severity

logger = get_logger()

# services/ai-storage-service/ — three levels up from this file
# (app/services/scanning/semgrep_engine.py) — used to resolve a relative
# semgrep_config_path regardless of the process's current working directory.
_SERVICE_ROOT = Path(__file__).resolve().parents[3]

_SEMGREP_TO_INTERNAL_SEVERITY = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

_binary_checked = False
_binary_available = False


def _binary_path() -> Optional[str]:
    """Resolve + cache whether the configured semgrep binary exists —
    shutil.which() walks $PATH on every call otherwise, and this would
    otherwise run on every single scan."""
    global _binary_checked, _binary_available
    settings = get_settings()
    if not _binary_checked:
        _binary_available = shutil.which(settings.semgrep_binary) is not None
        _binary_checked = True
        if not _binary_available:
            logger.warning("semgrep_binary_not_found", configured=settings.semgrep_binary)
    return settings.semgrep_binary if _binary_available else None


def _safe_relpath(path: str) -> Optional[str]:
    """Reject anything that could escape the scan temp dir (absolute paths,
    `..` segments) before it's used to build a filesystem path — same
    posture as the upload filename sanitization documented in
    docs/security.md. Returns None for a path that should be skipped."""
    normalized = path.replace("\\", "/").lstrip("/")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def _write_files(files: list[dict], target_dir: Path) -> dict[str, str]:
    """Write each file's content into target_dir at its relative path.
    Returns {safe_relpath: original_path} so semgrep's results (keyed by
    the path it saw on disk) can be mapped back to the caller's path."""
    path_map: dict[str, str] = {}
    for f in files:
        rel = _safe_relpath(f.get("path", ""))
        if rel is None:
            logger.warning("semgrep_skipped_unsafe_path", path=f.get("path"))
            continue
        dest = target_dir / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f.get("content", "") or "", encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("semgrep_write_failed", path=f.get("path"), error=str(exc))
            continue
        path_map[rel] = f["path"]
    return path_map


def _resolve_config(config: str) -> str:
    """A bare rule-pack name like `p/security-audit` (registry shorthand)
    is passed through untouched; a local path is resolved against the
    service root so it works regardless of the process's cwd."""
    if config.startswith("p/") or config.startswith("r/") or "://" in config:
        return config
    resolved = (_SERVICE_ROOT / config).resolve()
    if not resolved.exists():
        logger.warning("semgrep_config_not_found", config=config, resolved=str(resolved))
    return str(resolved)


def _configs() -> list[str]:
    settings = get_settings()
    return [_resolve_config(settings.semgrep_config_path)] + [
        _resolve_config(c) for c in settings.semgrep_extra_config_list
    ]


def _run_semgrep_cli(target_dir: Path) -> Optional[dict]:
    settings = get_settings()
    binary = _binary_path()
    if binary is None:
        return None

    cmd = [
        binary, "scan", "--json", "--quiet", "--no-git-ignore", "--metrics=off",
        f"--max-target-bytes={settings.semgrep_max_target_bytes}",
    ]
    for cfg in _configs():
        cmd += ["--config", cfg]
    # Scan "." with cwd=target_dir rather than passing target_dir's absolute
    # path — semgrep echoes back whatever target string it was given as the
    # base for each result's "path" field, so an absolute target produces
    # absolute result paths (leaking the local temp dir into findings).
    # Scanning "." from inside target_dir keeps result paths relative,
    # matching the relative keys in path_map below.
    cmd.append(".")

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=settings.semgrep_timeout_seconds, check=False,
            cwd=target_dir,
        )
    except subprocess.TimeoutExpired:
        logger.warning("semgrep_timed_out", timeout_seconds=settings.semgrep_timeout_seconds)
        return None
    except OSError as exc:
        logger.warning("semgrep_invocation_failed", error=str(exc))
        return None

    elapsed_ms = int((time.monotonic() - started) * 1000)

    # semgrep exits 0 for a clean run regardless of whether findings were
    # produced; a non-zero exit here means a scan-level failure (bad rule
    # syntax, internal crash), not "findings exist" — treat it as no
    # usable output rather than trying to partially trust stdout.
    if proc.returncode != 0:
        logger.warning(
            "semgrep_nonzero_exit", returncode=proc.returncode,
            stderr=(proc.stderr or "")[-1000:],
        )
        return None

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        logger.warning("semgrep_json_parse_failed", error=str(exc), raw=(proc.stdout or "")[:300])
        return None

    logger.info(
        "semgrep_scan_complete", elapsed_ms=elapsed_ms,
        result_count=len(payload.get("results", [])),
        error_count=len(payload.get("errors", [])),
    )
    for err in (payload.get("errors") or [])[:5]:
        # Per-file/per-rule errors (e.g. one unparseable file) — semgrep
        # still returns results for everything else, so this is a warning,
        # not a reason to discard the whole payload.
        logger.warning("semgrep_scan_error", message=str(err.get("message", err))[:300])

    return payload


def _severity_for(rule_meta: dict, semgrep_severity: str) -> str:
    label = (rule_meta.get("severity_label") or "").upper()
    raw = label or _SEMGREP_TO_INTERNAL_SEVERITY.get(semgrep_severity.upper(), "MEDIUM")
    # Belt-and-suspenders: rule_meta.severity_label comes from the YAML rule
    # file (human-edited), so route it through the same canonical whitelist
    # everything else uses rather than trusting it's a typo-free CRITICAL/
    # HIGH/MEDIUM/LOW. See app/services/severity.py for why this scale
    # exists as a shared choke point instead of being normalized per-caller.
    return severity.normalize(raw)


def _title_for(rule_key: str, message: str) -> str:
    first_sentence = message.strip().split(". ")[0].strip()
    return first_sentence[:140] if first_sentence else rule_key


def _parse_results(payload: dict, path_map: dict[str, str], target_dir: Path) -> list[dict]:
    findings: list[dict] = []
    target_prefix = target_dir.resolve().as_posix().rstrip("/") + "/"
    for result in payload.get("results", []):
        rel_path = result.get("path", "").replace("\\", "/")
        if rel_path.startswith("./"):
            rel_path = rel_path[2:]
        # Defensive: even though semgrep is invoked with cwd=target_dir and
        # target "." (see _run_semgrep_cli), strip an absolute target_dir
        # prefix if one still shows up, so a temp-dir path can never leak
        # into a finding instead of silently falling through to rel_path.
        if rel_path.startswith(target_prefix):
            rel_path = rel_path[len(target_prefix):]
        original_path = path_map.get(rel_path, rel_path)
        extra = result.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        check_id = result.get("check_id", "unknown-rule")
        # A locally-loaded config's check_id is prefixed with the rule
        # pack's path (e.g. "semgrep-rules.patchline-rules.sqli-py-fstring")
        # — strip back to the bare id we authored (see patchline-rules.yml)
        # so it matches the ruleKey _rescan_verify_fix looks up by.
        rule_key = check_id.rsplit(".", 1)[-1]
        message = extra.get("message", "")
        findings.append({
            "ruleKey": rule_key,
            "category": meta.get("category", "Other"),
            "severity": _severity_for(meta, extra.get("severity", "WARNING")),
            "title": _title_for(rule_key, message),
            "file": original_path,
            "line": result.get("start", {}).get("line", 0),
            "description": message.strip(),
            "suggestedFix": meta.get("suggested_fix", "Review and remediate this finding."),
            "snippet": (extra.get("lines") or "").strip()[:500],
            "engine": "semgrep",
        })
    return findings


def scan_paths(files: list[dict]) -> list[dict]:
    """Batch-scan a set of {path, content} dicts in ONE semgrep invocation —
    the efficient path, used for full/incremental repo scans. A single
    subprocess covering the whole file set is what keeps a real-repo scan's
    wall-clock time reasonable; invoking semgrep per-file would multiply
    process-startup overhead by the file count."""
    settings = get_settings()
    if not settings.semgrep_enabled or not files:
        return []

    with tempfile.TemporaryDirectory(prefix="patchline-semgrep-") as tmp:
        target_dir = Path(tmp)
        path_map = _write_files(files, target_dir)
        if not path_map:
            return []
        payload = _run_semgrep_cli(target_dir)
        if payload is None:
            return []
        return _parse_results(payload, path_map, target_dir)


def scan_file(path: str, content: str) -> list[dict]:
    """Single-file convenience wrapper, used by _rescan_verify_fix to
    re-check one file's post-fix content. Still a full semgrep subprocess
    call under the hood (there's no cheaper single-rule mode without also
    loading the config), so this is slower than the regex layer's
    equivalent — acceptable since it runs once per fix verification, not
    once per scanned file."""
    if not content:
        return []
    return scan_paths([{"path": path, "content": content}])