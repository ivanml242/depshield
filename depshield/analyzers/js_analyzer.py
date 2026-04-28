"""JavaScript static analyzer.

Scans .js files for suspicious patterns using esprima for AST parsing,
with a regex fallback for files esprima can't handle (JSX, etc.).

Detected signals: NETWORK_CALLS, ENV_ACCESS, FILE_SENSITIVE,
CODE_EXECUTION, OBFUSCATION, INSTALL_SCRIPTS.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path



@dataclass
class Finding:
    """A single suspicious finding in a source file."""

    signal_type: str       # e.g. "NETWORK_CALLS"
    severity: str          # "HIGH", "MEDIUM", or "LOW"
    file: str              # Relative file path
    line: int              # 1-based line number (0 if unknown)
    snippet: str           # Code fragment (max 100 chars)

    def __repr__(self) -> str:
        return (
            f"Finding({self.signal_type}, {self.severity}, "
            f"{self.file}:{self.line}, {self.snippet!r})"
        )



def _walk_ast(node: dict) -> list[dict]:
    """Recursively yield all AST nodes."""
    if not isinstance(node, dict):
        return []
    nodes = [node]
    for value in node.values():
        if isinstance(value, dict):
            nodes.extend(_walk_ast(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    nodes.extend(_walk_ast(item))
    return nodes


def _get_node_name(node: dict) -> str:
    """Extract a human-readable name from a CallExpression callee."""
    ntype = node.get("type", "")

    if ntype == "Identifier":
        return node.get("name", "")

    if ntype == "MemberExpression":
        obj = _get_node_name(node.get("object", {}))
        prop = _get_node_name(node.get("property", {}))
        return f"{obj}.{prop}" if obj and prop else obj or prop

    return ""


# -- NETWORK_CALLS --

_NETWORK_NAMES = {
    "fetch", "XMLHttpRequest",
    "http.request", "http.get",
    "https.request", "https.get",
    "axios", "axios.get", "axios.post", "axios.put", "axios.delete",
    "request", "got", "got.get", "got.post",
    "node-fetch",
}

_URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)


def _check_network_ast(node: dict, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for n in _walk_ast(node):
        if n.get("type") != "CallExpression":
            continue
        name = _get_node_name(n.get("callee", {}))
        if name in _NETWORK_NAMES:
            line = n.get("loc", {}).get("start", {}).get("line", 0)
            snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
            findings.append(Finding("NETWORK_CALLS", "HIGH", filepath, line, snippet))

    # Also check for URL string literals
    for n in _walk_ast(node):
        if n.get("type") == "Literal" and isinstance(n.get("value"), str):
            val = n["value"]
            if _URL_PATTERN.match(val):
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                findings.append(Finding(
                    "NETWORK_CALLS", "MEDIUM", filepath, line,
                    val[:100],
                ))
    return findings


# -- ENV_ACCESS --

_ENV_PATTERNS = {"process.env", "process.argv"}


def _check_env_ast(node: dict, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for n in _walk_ast(node):
        if n.get("type") == "MemberExpression":
            name = _get_node_name(n)
            if name in _ENV_PATTERNS:
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
                findings.append(Finding("ENV_ACCESS", "HIGH", filepath, line, snippet))
    return findings


# -- FILE_SENSITIVE --

_SENSITIVE_PATHS = [
    ".ssh", ".npmrc", ".env", ".aws", ".gnupg",
    "/etc/passwd", "/etc/shadow",
    "id_rsa", "id_ed25519",
    ".bash_history", ".zsh_history",
]


def _check_file_sensitive_ast(node: dict, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for n in _walk_ast(node):
        if n.get("type") == "Literal" and isinstance(n.get("value"), str):
            val = n["value"].lower()
            for sensitive in _SENSITIVE_PATHS:
                if sensitive.lower() in val:
                    line = n.get("loc", {}).get("start", {}).get("line", 0)
                    findings.append(Finding(
                        "FILE_SENSITIVE", "HIGH", filepath, line,
                        n["value"][:100],
                    ))
                    break
    return findings


# -- CODE_EXECUTION --

_EXEC_NAMES = {
    "eval", "Function",
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.spawnSync",
    "child_process.fork",
}


def _check_code_execution_ast(node: dict, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for n in _walk_ast(node):
        ntype = n.get("type", "")

        # CallExpression: eval(...), child_process.exec(...)
        if ntype == "CallExpression":
            name = _get_node_name(n.get("callee", {}))
            if name in _EXEC_NAMES:
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
                findings.append(Finding("CODE_EXECUTION", "HIGH", filepath, line, snippet))

        # NewExpression: new Function(...)
        if ntype == "NewExpression":
            name = _get_node_name(n.get("callee", {}))
            if name in _EXEC_NAMES:
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
                findings.append(Finding("CODE_EXECUTION", "HIGH", filepath, line, snippet))

    # require('child_process')
    for n in _walk_ast(node):
        if n.get("type") == "CallExpression":
            callee = n.get("callee", {})
            if _get_node_name(callee) == "require":
                args = n.get("arguments", [])
                if args and args[0].get("value") == "child_process":
                    line = n.get("loc", {}).get("start", {}).get("line", 0)
                    snippet = source_lines[line - 1].strip()[:100] if line > 0 else "require('child_process')"
                    findings.append(Finding(
                        "CODE_EXECUTION", "HIGH", filepath, line, snippet,
                    ))
    return findings


# -- OBFUSCATION --

_HEX_RE = re.compile(r"[0-9a-fA-F]{50,}")


def _check_obfuscation_ast(node: dict, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for n in _walk_ast(node):
        ntype = n.get("type", "")

        # Buffer.from(..., 'base64') or atob(...)
        if ntype == "CallExpression":
            name = _get_node_name(n.get("callee", {}))
            args = n.get("arguments", [])

            if name == "Buffer.from" and len(args) >= 2:
                if args[1].get("value") == "base64":
                    line = n.get("loc", {}).get("start", {}).get("line", 0)
                    snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
                    findings.append(Finding(
                        "OBFUSCATION", "HIGH", filepath, line, snippet,
                    ))

            if name == "atob":
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
                findings.append(Finding(
                    "OBFUSCATION", "MEDIUM", filepath, line, snippet,
                ))

            # String.fromCharCode with many arguments
            if name == "String.fromCharCode" and len(args) > 5:
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                snippet = source_lines[line - 1].strip()[:100] if line > 0 else name
                findings.append(Finding(
                    "OBFUSCATION", "HIGH", filepath, line, snippet,
                ))

        # Long hex strings
        if ntype == "Literal" and isinstance(n.get("value"), str):
            if _HEX_RE.search(n["value"]):
                line = n.get("loc", {}).get("start", {}).get("line", 0)
                findings.append(Finding(
                    "OBFUSCATION", "MEDIUM", filepath, line,
                    n["value"][:100],
                ))

    return findings


# -- Regex fallback (when esprima can't parse the file) --

_REGEX_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    # (signal_type, severity, description, pattern)
    ("NETWORK_CALLS", "HIGH", "fetch/http call",
     re.compile(r"\b(fetch|axios|http\.request|https\.request|XMLHttpRequest)\s*\(", re.I)),
    ("NETWORK_CALLS", "MEDIUM", "URL literal",
     re.compile(r"""["']https?://[^"']+["']""")),
    ("ENV_ACCESS", "HIGH", "process.env access",
     re.compile(r"\bprocess\.(env|argv)\b")),
    ("FILE_SENSITIVE", "HIGH", "sensitive path",
     re.compile(r"""["'].*?(\.ssh|\.npmrc|\.env|\.aws|/etc/passwd|id_rsa).*?["']""", re.I)),
    ("CODE_EXECUTION", "HIGH", "eval/exec",
     re.compile(r"\b(eval|Function)\s*\(")),
    ("CODE_EXECUTION", "HIGH", "child_process",
     re.compile(r"""require\s*\(\s*["']child_process["']\s*\)""")),
    ("CODE_EXECUTION", "HIGH", "child_process exec/spawn",
     re.compile(r"\bchild_process\.(exec|spawn|fork)\s*\(")),
    ("OBFUSCATION", "HIGH", "base64 decoding",
     re.compile(r"""Buffer\.from\s*\([^)]+,\s*["']base64["']\s*\)""")),
    ("OBFUSCATION", "MEDIUM", "atob call",
     re.compile(r"\batob\s*\(")),
    ("OBFUSCATION", "HIGH", "String.fromCharCode",
     re.compile(r"String\.fromCharCode\s*\((?:[^)]*,){5,}[^)]*\)")),
    ("OBFUSCATION", "MEDIUM", "long hex string",
     re.compile(r"""["'][0-9a-fA-F]{50,}["']""")),
]


def _analyze_with_regex(source: str, filepath: str) -> list[Finding]:
    """Fallback analysis using regex when esprima fails."""
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line_text in enumerate(lines, start=1):
        for signal_type, severity, _desc, pattern in _REGEX_PATTERNS:
            for match in pattern.finditer(line_text):
                findings.append(Finding(
                    signal_type=signal_type,
                    severity=severity,
                    file=filepath,
                    line=i,
                    snippet=match.group(0)[:100],
                ))
    return findings


# -- Install scripts in package.json --

_DANGEROUS_SCRIPTS = {"preinstall", "postinstall", "preuninstall"}


def _check_install_scripts(package_json_path: Path, filepath: str) -> list[Finding]:
    """Check package.json for dangerous lifecycle scripts."""
    findings: list[Finding] = []
    try:
        with open(package_json_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return findings

    scripts = data.get("scripts", {})
    for script_name in _DANGEROUS_SCRIPTS:
        if script_name in scripts:
            findings.append(Finding(
                signal_type="INSTALL_SCRIPTS",
                severity="HIGH",
                file=filepath,
                line=0,
                snippet=f"{script_name}: {scripts[script_name][:80]}",
            ))
    return findings


# -- Public API --

def analyze_file(filepath: str | Path, source: str | None = None) -> list[Finding]:
    """Analyze a single JS file. Tries esprima first, falls back to regex."""
    filepath = Path(filepath)
    rel_path = str(filepath)

    if source is None:
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

    source_lines = source.splitlines()

    # Try esprima first
    try:
        import esprima
        ast = esprima.parseScript(source, loc=True, tolerant=True)
        tree = ast.toDict() if hasattr(ast, "toDict") else ast

        findings: list[Finding] = []
        findings.extend(_check_network_ast(tree, source_lines, rel_path))
        findings.extend(_check_env_ast(tree, source_lines, rel_path))
        findings.extend(_check_file_sensitive_ast(tree, source_lines, rel_path))
        findings.extend(_check_code_execution_ast(tree, source_lines, rel_path))
        findings.extend(_check_obfuscation_ast(tree, source_lines, rel_path))
        return findings

    except Exception:
        # esprima failed (modern JS, JSX, TypeScript, etc.) → regex fallback
        return _analyze_with_regex(source, rel_path)


def analyze_directory(directory: str | Path) -> list[Finding]:
    """Analyze all .js files in a directory tree for malicious signals.

    Also checks any package.json files for dangerous install scripts.
    """
    directory = Path(directory)
    findings: list[Finding] = []

    # Analyze all .js files
    for js_file in directory.rglob("*.js"):
        findings.extend(analyze_file(js_file))

    # Check package.json files for install scripts
    for pkg_json in directory.rglob("package.json"):
        rel_path = str(pkg_json)
        findings.extend(_check_install_scripts(pkg_json, rel_path))

    return findings
