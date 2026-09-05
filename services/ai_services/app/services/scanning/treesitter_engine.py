"""
Tree-sitter based AST engine — the third and newest pass in the
deterministic scanner (see app/services/deterministic_scanner.py for the
orchestrator that merges this with semgrep_engine.py and regex_rules.py).

Where the other two engines work over source *text* (regex_rules.py) or a
subprocess's opinion of the AST (semgrep_engine.py), this one parses each
file directly, in-process, with Tree-sitter and re-derives the same
vulnerability categories from real syntax nodes: a call whose argument is a
`binary_operator`/`template_string` interpolation instead of a plain string
literal, an assignment whose target is a sensitive attribute, and so on.
Two things follow from that:

  1. Structural corroboration. When a regex pattern and/or a Semgrep rule
     also fire at the same (file, line, category), this engine's finding
     doesn't create a fourth thing to show the developer — the aggregator
     (deterministic_scanner._dedupe) folds all engines that agreed into one
     finding's `evidence` list, which is what should give a developer more
     confidence in a finding, and is also what gets handed to GPT-4.1-mini
     as structured evidence instead of raw text (see
     routers/scanner.py:_enrich_deterministic_findings).
  2. A same-process fallback. Like regex_rules.py, this needs no subprocess
     and no external binary, so a scan still gets a structural signal even
     in an environment where the `semgrep` binary isn't available.

Supported languages: Python, JavaScript, TypeScript/TSX, PHP. C/C++ get
language detection and AST parsing (useful as structural context for the AI
layer) but no dedicated detector rules yet — the existing regex/Semgrep
rules don't cover C/C++ either, so there's nothing here to corroborate.

Failure posture matches semgrep_engine.py: anything that goes wrong (the
tree-sitter-language-pack import missing, a grammar failing to load, a file
that fails to parse) logs a warning and yields no findings for that
file/language rather than raising — one bad file degrades this engine's
coverage of that file, never the whole scan.
"""

from typing import Callable, Optional

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger()

_MAX_MATCHES_PER_RULE_PER_FILE = 5

# Extension -> tree-sitter-language-pack grammar name.
LANGUAGE_FOR_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
}

_import_checked = False
_import_ok = False
_get_parser = None  # tree_sitter_language_pack.get_parser, once imported

_parser_cache: dict[str, object] = {}


def _ensure_import() -> bool:
    """Lazy, cached import — mirrors semgrep_engine._binary_path()'s
    check-once-and-cache pattern. Keeps this module importable (and the
    rest of the scanner working) even in an environment where
    tree-sitter-language-pack isn't installed."""
    global _import_checked, _import_ok, _get_parser
    if not _import_checked:
        _import_checked = True
        try:
            from tree_sitter_language_pack import get_parser
            _get_parser = get_parser
            _import_ok = True
        except ImportError as exc:
            logger.warning("treesitter_import_failed", error=str(exc))
            _import_ok = False
    return _import_ok


def _language_for(path: str) -> Optional[str]:
    idx = path.rfind(".")
    if idx == -1:
        return None
    return LANGUAGE_FOR_EXT.get(path[idx:].lower())


def _parser_for(language: str):
    if language in _parser_cache:
        return _parser_cache[language]
    if not _ensure_import():
        return None
    try:
        parser = _get_parser(language)
    except Exception as exc:  # unsupported/broken grammar in this build
        logger.warning("treesitter_grammar_unavailable", language=language, error=str(exc))
        parser = None
    _parser_cache[language] = parser
    return parser


# ──────────────────────── AST helpers ────────────────────────

def _line_of(node) -> int:
    return node.start_point[0] + 1


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    """Depth-first traversal over every descendant node, self included —
    the "parse once, traverse for everything" step the doc calls for:
    every detector below re-walks this same in-memory tree, no re-parsing."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _has_descendant_of_type(node, types: frozenset) -> bool:
    for n in _walk(node):
        if n.type in types:
            return True
    return False


def _snippet(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 2)
    end = min(len(lines), line_no + 1)
    return "\n".join(lines[start:end]).strip()[:500]


def _make_finding(
    *, rule_key: str, category: str, severity: str, title: str,
    description: str, suggested_fix: str, path: str, node, source: bytes, lines: list[str],
) -> dict:
    line_no = _line_of(node)
    return {
        "ruleKey": rule_key,
        "category": category,
        "severity": severity,
        "title": title,
        "file": path,
        "line": line_no,
        "description": description,
        "suggestedFix": suggested_fix,
        "snippet": _snippet(lines, line_no),
        "engine": "treesitter",
    }


# ──────────────────────── Python detectors ────────────────────────
# Node types per the tree-sitter-python grammar: call/attribute/assignment/
# binary_operator/keyword_argument/string, with f-strings represented as a
# `string` node containing an `interpolation` child.

_PY_DYNAMIC_STRING_TYPES = frozenset({"binary_operator", "call"})  # concatenation or a .format()/f-string call result


def _py_is_dynamic_arg(node) -> bool:
    """True if a call argument is NOT a plain static string literal — i.e.
    it's built at runtime (concatenation, an f-string with interpolation,
    %-formatting, or a call like .format())."""
    if node.type == "string":
        return _has_descendant_of_type(node, frozenset({"interpolation"}))
    if node.type in _PY_DYNAMIC_STRING_TYPES:
        return True
    return False


def _py_sqli(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break
        if node.type != "call":
            continue
        func = node.child_by_field_name("function")
        if func is None or func.type != "attribute":
            continue
        attr = func.child_by_field_name("attribute")
        if attr is None or _text(attr, source) != "execute":
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not arg_nodes or not _py_is_dynamic_arg(arg_nodes[0]):
            continue
        findings.append(_make_finding(
            rule_key="sqli-py-dynamic-execute", category="SQL Injection", severity="HIGH",
            title="SQL query built dynamically before execute()",
            description="AST analysis shows execute() is called with an argument built at runtime (concatenation, f-string interpolation, or %-formatting) rather than a static string literal.",
            suggested_fix="Use parameterized queries (e.g. cursor.execute(query, params)) instead of building the query string dynamically.",
            path=path, node=node, source=source, lines=lines,
        ))
        matched += 1
    return findings


def _py_cmdi(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break
        if node.type != "call":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        func_text = _text(func, source)
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        if func_text == "os.system":
            arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
            if arg_nodes and _py_is_dynamic_arg(arg_nodes[0]):
                findings.append(_make_finding(
                    rule_key="cmdi-py-os-system-dynamic", category="Command Injection", severity="CRITICAL",
                    title="os.system() called with a dynamically built command",
                    description="AST analysis shows os.system() receives an argument built at runtime (concatenation or interpolation) rather than a static string, which allows shell metacharacter injection if any part is user-controlled.",
                    suggested_fix="Avoid the shell entirely: use subprocess.run([...]) with a list of arguments and shell=False.",
                    path=path, node=node, source=source, lines=lines,
                ))
                matched += 1
                continue

        if func_text in ("subprocess.call", "subprocess.run", "subprocess.Popen"):
            for c in args.children:
                if c.type == "keyword_argument":
                    name = c.child_by_field_name("name")
                    value = c.child_by_field_name("value")
                    if name is not None and value is not None and _text(name, source) == "shell" and _text(value, source) == "True":
                        findings.append(_make_finding(
                            rule_key="cmdi-py-subprocess-shell-true-dynamic", category="Command Injection", severity="HIGH",
                            title="subprocess call with shell=True",
                            description="AST analysis confirms a subprocess call has a shell=True keyword argument, which runs the command through a shell and allows injection via any interpolated input.",
                            suggested_fix="Use a list of arguments with shell=False (the subprocess default) instead of a shell string.",
                            path=path, node=node, source=source, lines=lines,
                        ))
                        matched += 1
                        break
    return findings


def _py_crypto(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    weak = {"hashlib.md5": ("crypto-md5-dynamic", "MEDIUM", "MD5"), "hashlib.sha1": ("crypto-sha1-dynamic", "LOW", "SHA-1")}
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break
        if node.type != "call":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        func_text = _text(func, source)
        if func_text in weak:
            key, severity, algo = weak[func_text]
            findings.append(_make_finding(
                rule_key=key, category="Weak Cryptography", severity=severity,
                title=f"{algo} used for hashing",
                description=f"AST analysis confirms a call to {func_text}(), a hash function considered cryptographically broken/deprecated for security-sensitive use.",
                suggested_fix="Use a modern password hash (bcrypt/argon2/scrypt) for passwords, or SHA-256+ for general integrity checks.",
                path=path, node=node, source=source, lines=lines,
            ))
            matched += 1
    return findings


_PY_DETECTORS: list[Callable] = [_py_sqli, _py_cmdi, _py_crypto]


# ──────────────────────── JavaScript / TypeScript detectors ────────────────────────
# Node types per tree-sitter-javascript / tree-sitter-typescript: call_expression,
# member_expression, template_string (with template_substitution children for
# ${...}), binary_expression, assignment_expression, jsx_attribute.

def _js_is_dynamic_arg(node) -> bool:
    if node.type == "template_string":
        return _has_descendant_of_type(node, frozenset({"template_substitution"}))
    if node.type == "binary_expression":
        return True
    return False


def _js_sqli(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            continue
        prop = func.child_by_field_name("property")
        if prop is None or _text(prop, source) not in ("query", "execute"):
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not arg_nodes or not _js_is_dynamic_arg(arg_nodes[0]):
            continue
        findings.append(_make_finding(
            rule_key="sqli-js-dynamic-query", category="SQL Injection", severity="HIGH",
            title="SQL query built dynamically before query()/execute()",
            description="AST analysis shows query()/execute() is called with a template literal containing ${...} interpolation or a concatenated (binary) expression, rather than a static string.",
            suggested_fix="Use a parameterized/prepared query (e.g. db.query('... WHERE id = ?', [id])) instead of interpolating values into the SQL string.",
            path=path, node=node, source=source, lines=lines,
        ))
        matched += 1
    return findings


def _js_xss(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break

        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "member_expression" and right is not None:
                prop = left.child_by_field_name("property")
                if prop is not None and _text(prop, source) == "innerHTML" and _js_is_dynamic_arg(right):
                    findings.append(_make_finding(
                        rule_key="xss-innerhtml-dynamic", category="Cross-Site Scripting (XSS)", severity="MEDIUM",
                        title="Unsanitized input assigned to innerHTML",
                        description="AST analysis shows a dynamically built value (template interpolation or concatenation) assigned directly to .innerHTML.",
                        suggested_fix="Use .textContent for plain text, or sanitize the HTML (e.g. DOMPurify) before assigning to innerHTML.",
                        path=path, node=node, source=source, lines=lines,
                    ))
                    matched += 1
                    continue

        if node.type == "jsx_attribute":
            name_node = node.children[0] if node.children else None
            if name_node is not None and _text(name_node, source) == "dangerouslySetInnerHTML":
                findings.append(_make_finding(
                    rule_key="xss-dangerously-set-dynamic", category="Cross-Site Scripting (XSS)", severity="MEDIUM",
                    title="React dangerouslySetInnerHTML usage",
                    description="AST analysis confirms a dangerouslySetInnerHTML JSX attribute, which renders raw HTML without React's escaping.",
                    suggested_fix="Avoid dangerouslySetInnerHTML for user-controlled content, or sanitize it first (e.g. DOMPurify.sanitize()).",
                    path=path, node=node, source=source, lines=lines,
                ))
                matched += 1
    return findings


def _js_cmdi(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None or _text(func, source) != "exec":
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not arg_nodes or not _js_is_dynamic_arg(arg_nodes[0]):
            continue
        findings.append(_make_finding(
            rule_key="cmdi-js-exec-dynamic", category="Command Injection", severity="CRITICAL",
            title="child_process exec() with a dynamically built command",
            description="AST analysis shows exec() is called with a template literal containing ${...} interpolation or a concatenated expression, which runs through the shell and allows metacharacter injection.",
            suggested_fix="Use execFile()/spawn() with an argument array instead of exec() with a shell string.",
            path=path, node=node, source=source, lines=lines,
        ))
        matched += 1
    return findings


_JS_DETECTORS: list[Callable] = [_js_sqli, _js_xss, _js_cmdi]


# ──────────────────────── PHP detectors ────────────────────────
# Node types per tree-sitter-php: function_call_expression, variable_name.

_PHP_SHELL_FUNCS = frozenset({"shell_exec", "system", "passthru", "exec"})
_PHP_SUPERGLOBALS = frozenset({"$_GET", "$_POST", "$_REQUEST"})


def _php_cmdi(root, source: bytes, path: str, lines: list[str]) -> list[dict]:
    findings = []
    matched = 0
    for node in _walk(root):
        if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
            break
        if node.type != "function_call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None or _text(func, source) not in _PHP_SHELL_FUNCS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        if not _has_descendant_of_type(args, frozenset({"variable_name"})):
            continue
        superglobal_arg = any(
            _text(n, source) in _PHP_SUPERGLOBALS for n in _walk(args) if n.type == "variable_name"
        )
        if not superglobal_arg:
            continue
        findings.append(_make_finding(
            rule_key="cmdi-php-shell-funcs-dynamic", category="Command Injection", severity="CRITICAL",
            title="PHP shell function called with request input",
            description="AST analysis shows a shell-executing function called with an argument derived from a request superglobal ($_GET/$_POST/$_REQUEST).",
            suggested_fix="Avoid passing request-derived data to shell functions; if unavoidable, use escapeshellarg()/escapeshellcmd() and an allowlist of permitted values.",
            path=path, node=node, source=source, lines=lines,
        ))
        matched += 1
    return findings


_PHP_DETECTORS: list[Callable] = [_php_cmdi]


_DETECTORS_BY_LANGUAGE: dict[str, list[Callable]] = {
    "python": _PY_DETECTORS,
    "javascript": _JS_DETECTORS,
    "typescript": _JS_DETECTORS,
    "tsx": _JS_DETECTORS,
    "php": _PHP_DETECTORS,
    # c / cpp: parsed (see scan_file), no detector rules yet.
}


# ──────────────────────── Public API ────────────────────────

def scan_file(path: str, content: str) -> list[dict]:
    """Parse one file once and run every detector registered for its
    language against the resulting AST. Returns [] for unsupported
    languages, empty content, or anything that fails to parse — this engine
    degrading never blocks the regex/Semgrep findings from a scan."""
    settings = get_settings()
    if not settings.treesitter_enabled or not content:
        return []

    language = _language_for(path)
    if language is None:
        return []

    parser = _parser_for(language)
    if parser is None:
        return []

    detectors = _DETECTORS_BY_LANGUAGE.get(language)
    if not detectors:
        return []  # parses fine (e.g. c/cpp) but nothing to detect yet

    source = content.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(source)
    except Exception as exc:
        logger.warning("treesitter_parse_failed", path=path, language=language, error=str(exc))
        return []

    lines = content.split("\n")
    findings: list[dict] = []
    for detector in detectors:
        try:
            findings.extend(detector(tree.root_node, source, path, lines))
        except Exception as exc:
            # One detector misbehaving on one file's structure shouldn't cost
            # the rest of this file's findings.
            logger.warning("treesitter_detector_failed", path=path, detector=detector.__name__, error=str(exc))
    return findings


def scan_paths(files: list[dict]) -> list[dict]:
    """Batch entry point mirroring semgrep_engine.scan_paths/regex_rules'
    per-file loop — unlike Semgrep this never shells out, so there's no
    subprocess cost to batch away; each file is just parsed in turn."""
    settings = get_settings()
    if not settings.treesitter_enabled or not files:
        return []
    findings: list[dict] = []
    for f in files:
        findings.extend(scan_file(f.get("path", ""), f.get("content", "") or ""))
    return findings


def structural_context(path: str, content: str, line: int) -> Optional[str]:
    """Best-effort one-line description of the AST node enclosing `line`,
    for the AI enrichment prompt's "Relevant AST" evidence (see
    routers/scanner.py:_enrich_deterministic_findings and the doc example:
    'Relevant AST: cursor.execute(...) ↑ dynamic query'). Returns None if
    tree-sitter isn't available, the file doesn't parse, or nothing on that
    line looks structurally interesting."""
    settings = get_settings()
    if not settings.treesitter_enabled or not content:
        return None
    language = _language_for(path)
    if language is None:
        return None
    parser = _parser_for(language)
    if parser is None:
        return None

    source = content.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(source)
    except Exception:
        return None

    interesting = frozenset({
        "call", "call_expression", "function_call_expression",
        "assignment", "assignment_expression",
    })
    best = None
    for node in _walk(tree.root_node):
        if _line_of(node) != line or node.type not in interesting:
            continue
        # Prefer the smallest (most specific) matching node on the line.
        if best is None or (node.end_byte - node.start_byte) < (best.end_byte - best.start_byte):
            best = node
    if best is None:
        return None
    text = _text(best, source).strip().replace("\n", " ")
    return text[:200]
