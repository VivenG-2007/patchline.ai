"""
Regex-based vulnerability detectors — one of two engines feeding the
deterministic scanner (see app/services/deterministic_scanner.py for the
orchestrator, and semgrep_engine.py for the AST-based SAST engine that now
runs alongside this one).

This layer stays in place after the Semgrep integration for two reasons:
  1. Zero-cost, zero-dependency, single-line-scope checks (secrets, a
     private-key block, a known API-token prefix) are fundamentally
     text-shape questions — semgrep_engine.py's rules cover the same ground
     via `pattern-regex`, but keeping a plain-Python fallback here means a
     scan degrades to "regex only" instead of "nothing" if the semgrep
     binary is ever unavailable in a given environment.
  2. `_rescan_verify_fix` (see routers/scanner.py) re-runs a finding's exact
     originating rule by ruleKey against post-fix content — regex rules are
     effectively free to re-run inline on every fix verification, no
     subprocess involved.

The deterministic_scanner orchestrator dedupes when both engines fire on the
same (file, line): Semgrep's AST-driven match wins as the more precise
signal, and the regex finding is dropped rather than double-reported.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Rule:
    key: str
    category: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    suggested_fix: str
    pattern: "re.Pattern"
    extensions: Optional[frozenset] = None  # None = applies to any scanned extension


_MAX_MATCHES_PER_RULE_PER_FILE = 5

# ──────────────────────── SQL Injection ────────────────────────

_SQLI_RULES = [
    Rule(
        key="sqli-py-fstring",
        category="SQL Injection",
        severity="HIGH",
        title="SQL query built from an f-string",
        description="An f-string is interpolated directly into a SQL execute() call, letting attacker-controlled input alter query structure.",
        suggested_fix="Use parameterized queries (e.g. cursor.execute(query, params)) instead of interpolating values into the SQL string.",
        pattern=re.compile(r"\.execute\s*\(\s*f[\"']"),
    ),
    Rule(
        key="sqli-py-concat",
        category="SQL Injection",
        severity="HIGH",
        title="SQL query built by string concatenation",
        description="A SQL string is concatenated with a variable before being executed, which allows SQL injection if the variable is user-controlled.",
        suggested_fix="Use parameterized queries instead of concatenating values into the SQL string.",
        pattern=re.compile(r"\.execute\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
        extensions=frozenset({".py"}),
    ),
    Rule(
        key="sqli-py-percent",
        category="SQL Injection",
        severity="HIGH",
        title="SQL query built with %-string formatting",
        description="A SQL string uses %-formatting to insert a value, which allows SQL injection if the value is user-controlled.",
        suggested_fix="Use parameterized queries (placeholders + a params tuple) instead of %-formatting the SQL string.",
        # Non-greedy match across the whole quoted string (.*?) rather than
        # excluding quote characters — the previous version's [^"']* stopped
        # at ANY quote, so the common '%s' placeholder style (single quotes
        # wrapped around the placeholder itself, inside an outer double-quoted
        # string) was never reached and silently never matched.
        pattern=re.compile(r"\.execute\s*\(\s*[\"'].*?%s.*?[\"']\s*%"),
        extensions=frozenset({".py"}),
    ),
    Rule(
        key="sqli-js-template",
        category="SQL Injection",
        severity="HIGH",
        title="SQL query built from a JS template literal",
        description="A template literal with interpolation (`${...}`) is passed to a query/execute call, allowing SQL injection if the interpolated value is user-controlled.",
        suggested_fix="Use a parameterized/prepared query (e.g. `db.query('... WHERE id = ?', [id])`) instead of interpolating values into the SQL string.",
        pattern=re.compile(r"\.(query|execute)\s*\(\s*`[^`]*\$\{"),
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        key="sqli-js-concat",
        category="SQL Injection",
        severity="HIGH",
        title="SQL query built by string concatenation (JS)",
        description="A SQL string is concatenated with a variable before being passed to query/execute, allowing SQL injection if the variable is user-controlled.",
        suggested_fix="Use a parameterized/prepared query instead of concatenating values into the SQL string.",
        pattern=re.compile(r"\.(query|execute)\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
]

# ──────────────────────── XSS ────────────────────────

_XSS_RULES = [
    Rule(
        key="xss-innerhtml-concat",
        category="Cross-Site Scripting (XSS)",
        severity="MEDIUM",
        title="Unsanitized input assigned to innerHTML",
        description="A value built with string concatenation/interpolation is assigned to .innerHTML, which lets attacker-controlled input execute as HTML/JS in the browser.",
        suggested_fix="Use .textContent for plain text, or sanitize the HTML (e.g. DOMPurify) before assigning to innerHTML.",
        pattern=re.compile(r"\.innerHTML\s*=\s*[^;]*(\+|\$\{)"),
    ),
    Rule(
        key="xss-dangerously-set",
        category="Cross-Site Scripting (XSS)",
        severity="MEDIUM",
        title="React dangerouslySetInnerHTML usage",
        description="dangerouslySetInnerHTML renders raw HTML without React's escaping — if the source includes user input, it's an XSS vector.",
        suggested_fix="Avoid dangerouslySetInnerHTML for user-controlled content, or sanitize it first (e.g. DOMPurify.sanitize()).",
        pattern=re.compile(r"dangerouslySetInnerHTML"),
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        key="xss-document-write",
        category="Cross-Site Scripting (XSS)",
        severity="LOW",
        title="document.write() usage",
        description="document.write() with dynamic content can introduce XSS and also degrades page load behavior.",
        suggested_fix="Use safe DOM APIs (createElement/textContent) instead of document.write().",
        pattern=re.compile(r"document\.write\s*\("),
    ),
    Rule(
        key="xss-express-send-concat",
        category="Cross-Site Scripting (XSS)",
        severity="MEDIUM",
        title="Unescaped user input reflected in an HTTP response",
        description="A response body is built by concatenating a variable directly into res.send(), which can reflect unescaped attacker input as HTML.",
        suggested_fix="Use res.json() for data responses, or escape/encode any user-controlled value before including it in an HTML response.",
        pattern=re.compile(r"res\.send\s*\(\s*[^)]*\+"),
        extensions=frozenset({".js", ".ts"}),
    ),
    Rule(
        key="xss-vue-v-html",
        category="Cross-Site Scripting (XSS)",
        severity="MEDIUM",
        title="Vue v-html directive usage",
        description="v-html renders raw HTML without escaping — if the bound value includes user input, it's an XSS vector.",
        suggested_fix="Bind with {{ }} text interpolation instead, or sanitize the HTML (e.g. DOMPurify) before using v-html.",
        pattern=re.compile(r"v-html\s*="),
        extensions=frozenset({".vue", ".html"}),
    ),
]

# ──────────────────────── Hardcoded Secrets ────────────────────────

_SECRET_RULES = [
    Rule(
        key="secret-aws-key",
        category="Hardcoded Secret",
        severity="CRITICAL",
        title="Hardcoded AWS access key ID",
        description="An AWS access key ID literal is committed in source, which lets anyone with repo access use those credentials.",
        suggested_fix="Revoke this key immediately, then load credentials from environment variables or a secrets manager (never commit them).",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    Rule(
        key="secret-generic-assignment",
        category="Hardcoded Secret",
        severity="CRITICAL",
        title="Hardcoded credential-like value",
        description="A variable named like a password/API key/secret/token is assigned a hardcoded literal string, which exposes it to anyone with repo access.",
        suggested_fix="Move this value to an environment variable or secrets manager and remove it from source control (rotate the credential if it was ever pushed).",
        pattern=re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_\-/+=]{8,}[\"']"),
    ),
    Rule(
        key="secret-private-key-block",
        category="Hardcoded Secret",
        severity="CRITICAL",
        title="Private key material committed to source",
        description="A PEM-format private key block is present in the file, exposing the private key to anyone with repo access.",
        suggested_fix="Remove the key from source control, rotate it immediately, and load it at runtime from a secrets manager or mounted secret file.",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    Rule(
        key="secret-slack-token",
        category="Hardcoded Secret",
        severity="HIGH",
        title="Hardcoded Slack token",
        description="A Slack API token literal is present in source, which lets anyone with repo access act as that Slack app/bot.",
        suggested_fix="Revoke this token and load it from an environment variable or secrets manager instead.",
        pattern=re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ),
]

# ──────────────────────── Weak Cryptography ────────────────────────

_CRYPTO_RULES = [
    Rule(
        key="crypto-md5",
        category="Weak Cryptography",
        severity="MEDIUM",
        title="MD5 used for hashing",
        description="MD5 is cryptographically broken and unsuitable for password hashing or integrity checks where collisions matter.",
        suggested_fix="Use a modern password hash (bcrypt/argon2/scrypt) for passwords, or SHA-256+ for general integrity checks.",
        pattern=re.compile(r"(?i)\b(hashlib\.md5|md5\s*\()"),
    ),
    Rule(
        key="crypto-sha1",
        category="Weak Cryptography",
        severity="LOW",
        title="SHA-1 used for hashing",
        description="SHA-1 has known collision weaknesses and is deprecated for security-sensitive hashing.",
        suggested_fix="Use SHA-256 or better for integrity checks, or a dedicated password hash (bcrypt/argon2) for credentials.",
        pattern=re.compile(r"(?i)\b(hashlib\.sha1|sha1\s*\()"),
    ),
    Rule(
        key="crypto-des",
        category="Weak Cryptography",
        severity="HIGH",
        title="DES/3DES cipher usage",
        description="DES and 3DES use small block/key sizes and are considered broken for modern use.",
        suggested_fix="Use AES-256 (with a secure mode such as GCM) instead of DES/3DES.",
        pattern=re.compile(r"\bDES\b"),
    ),
    Rule(
        key="crypto-ecb-mode",
        category="Weak Cryptography",
        severity="HIGH",
        title="ECB cipher mode usage",
        description="ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking structural information about the plaintext.",
        suggested_fix="Use an authenticated mode such as AES-GCM instead of ECB.",
        pattern=re.compile(r"(?i)MODE_ECB|[\"']ecb[\"']"),
    ),
    Rule(
        key="crypto-weak-random-for-token",
        category="Weak Cryptography",
        severity="MEDIUM",
        title="Non-cryptographic RNG used for a token/secret",
        description="Math.random() (or similar non-CSPRNG) is used near a token/password/secret/key, and is predictable — unsuitable for security-sensitive values.",
        suggested_fix="Use a cryptographically secure RNG (e.g. crypto.randomBytes() in Node, `secrets` module in Python) for tokens, passwords, and keys.",
        pattern=re.compile(r"(?i)Math\.random\(\)[^\n;]{0,40}(token|password|secret|apikey|api_key)"),
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
]

# ──────────────────────── Command Injection ────────────────────────

_CMDI_RULES = [
    Rule(
        key="cmdi-py-os-system-concat",
        category="Command Injection",
        severity="CRITICAL",
        title="os.system() called with concatenated input",
        description="os.system() runs a string through the shell; concatenating a variable into it allows shell metacharacter injection if the variable is user-controlled.",
        suggested_fix="Avoid the shell entirely: use subprocess.run([...]) with a list of arguments and shell=False.",
        pattern=re.compile(r"os\.system\s*\(\s*[^)]*\+"),
    ),
    Rule(
        key="cmdi-py-subprocess-shell-true",
        category="Command Injection",
        severity="HIGH",
        title="subprocess call with shell=True",
        description="shell=True runs the command through a shell, so any interpolated user input can inject additional shell commands.",
        suggested_fix="Use a list of arguments with shell=False (the subprocess default) instead of a shell string.",
        pattern=re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
    ),
    Rule(
        key="cmdi-js-exec-template",
        category="Command Injection",
        severity="CRITICAL",
        title="child_process exec() with interpolated input",
        description="exec() runs a string through the shell; a template literal with `${...}` interpolation allows shell metacharacter injection if the value is user-controlled.",
        suggested_fix="Use execFile()/spawn() with an argument array instead of exec() with a shell string.",
        pattern=re.compile(r"\bexec\s*\(\s*`[^`]*\$\{"),
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        key="cmdi-js-exec-concat",
        category="Command Injection",
        severity="CRITICAL",
        title="child_process exec() with concatenated input",
        description="exec() runs a string through the shell; string concatenation into it allows shell metacharacter injection if the value is user-controlled.",
        suggested_fix="Use execFile()/spawn() with an argument array instead of exec() with a shell string.",
        pattern=re.compile(r"\bexec\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        key="cmdi-php-shell-funcs",
        category="Command Injection",
        severity="CRITICAL",
        title="PHP shell function called with request input",
        description="A shell-executing function (shell_exec/system/passthru/exec) is called with a value derived directly from request input ($_GET/$_POST/etc.).",
        suggested_fix="Avoid passing request-derived data to shell functions; if unavoidable, use escapeshellarg()/escapeshellcmd() and an allowlist of permitted values.",
        pattern=re.compile(r"\b(shell_exec|system|passthru|exec)\s*\(\s*\$_(GET|POST|REQUEST)"),
        extensions=frozenset({".php"}),
    ),
]

RULES: list[Rule] = _SQLI_RULES + _XSS_RULES + _SECRET_RULES + _CRYPTO_RULES + _CMDI_RULES


def _extension(path: str) -> str:
    idx = path.rfind(".")
    return path[idx:].lower() if idx != -1 else ""


def scan_file(path: str, content: str) -> list[dict]:
    """Run every applicable rule against one file's content."""
    if not content:
        return []
    ext = _extension(path)
    lines = content.split("\n")
    findings: list[dict] = []

    for rule in RULES:
        if rule.extensions is not None and ext not in rule.extensions:
            continue
        matched = 0
        seen_lines: set[int] = set()  # one finding per (rule, line) — a rule
        # whose pattern matches twice on the same line (e.g. \bDES\b matching
        # "DES" twice in "DES.new(key, DES.MODE_ECB)") is one real issue, not two.
        for m in rule.pattern.finditer(content):
            if matched >= _MAX_MATCHES_PER_RULE_PER_FILE:
                break
            line_no = content.count("\n", 0, m.start()) + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            start = max(0, line_no - 2)
            end = min(len(lines), line_no + 1)
            snippet = "\n".join(lines[start:end]).strip()
            findings.append({
                "ruleKey": rule.key,
                "category": rule.category,
                "severity": rule.severity,
                "title": rule.title,
                "file": path,
                "line": line_no,
                "description": rule.description,
                "suggestedFix": rule.suggested_fix,
                "snippet": snippet[:500],
                "engine": "regex",
            })
            matched += 1

    return findings
