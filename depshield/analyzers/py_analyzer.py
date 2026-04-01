"""Python static analyzer.

Analyzes Python source files for signals of malicious behavior using
the built-in ``ast`` module (no external dependencies).

Detects 6 signal types:
  1. NETWORK_CALLS    — urllib, requests, http.client, socket, httpx
  2. ENV_ACCESS       — os.environ, os.getenv, subprocess with env
  3. FILE_SENSITIVE   — Access to ~/.ssh, ~/.aws, /etc/passwd, etc.
  4. CODE_EXECUTION   — eval, exec, compile, os.system, subprocess, __import__
  5. OBFUSCATION      — base64.b64decode, codecs.decode, marshal.loads, long hex
  6. INSTALL_HOOKS    — setup.py cmdclass overriding install/develop
"""

import ast
import re
from pathlib import Path

from depshield.analyzers.js_analyzer import Finding


# ---------------------------------------------------------------------------
# AST analysis helpers
# ---------------------------------------------------------------------------

def _get_call_name(node: ast.Call) -> str:
    """Extract a dotted name from a Call node's func attribute."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _get_import_names(node: ast.AST) -> list[str]:
    """Extract module names from Import / ImportFrom nodes."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        return [node.module or ""]
    return []


def _snippet(source_lines: list[str], lineno: int) -> str:
    """Get a trimmed snippet from source at the given line."""
    if 0 < lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()[:100]
    return ""


# ---------------------------------------------------------------------------
# Signal: NETWORK_CALLS
# ---------------------------------------------------------------------------

_NETWORK_MODULES = {
    "urllib", "urllib.request", "urllib.parse",
    "requests", "httpx",
    "http.client", "http",
    "socket",
    "aiohttp",
}

_NETWORK_CALLS = {
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.request",
    "httpx.get", "httpx.post", "httpx.Client",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.socket", "socket.create_connection",
    "aiohttp.ClientSession",
}


def _check_network(tree: ast.AST, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        # Import of network modules
        for name in _get_import_names(node):
            if name in _NETWORK_MODULES:
                findings.append(Finding(
                    "NETWORK_CALLS", "MEDIUM", filepath,
                    getattr(node, "lineno", 0),
                    _snippet(source_lines, getattr(node, "lineno", 0)),
                ))

        # Direct calls to network functions
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in _NETWORK_CALLS:
                findings.append(Finding(
                    "NETWORK_CALLS", "HIGH", filepath,
                    node.lineno,
                    _snippet(source_lines, node.lineno),
                ))

    return findings


# ---------------------------------------------------------------------------
# Signal: ENV_ACCESS
# ---------------------------------------------------------------------------

_ENV_CALLS = {"os.environ", "os.getenv", "os.environ.get"}


def _check_env(tree: ast.AST, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        # os.environ access (attribute)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                findings.append(Finding(
                    "ENV_ACCESS", "HIGH", filepath,
                    node.lineno,
                    _snippet(source_lines, node.lineno),
                ))

        # os.getenv() call
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in _ENV_CALLS:
                findings.append(Finding(
                    "ENV_ACCESS", "HIGH", filepath,
                    node.lineno,
                    _snippet(source_lines, node.lineno),
                ))

    return findings


# ---------------------------------------------------------------------------
# Signal: FILE_SENSITIVE
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS = [
    ".ssh", ".aws", ".env", ".gnupg", ".npmrc",
    "/etc/passwd", "/etc/shadow",
    "id_rsa", "id_ed25519",
    ".bash_history", ".zsh_history",
]


def _check_file_sensitive(tree: ast.AST, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        # String literals containing sensitive paths
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.lower()
            for pattern in _SENSITIVE_PATTERNS:
                if pattern.lower() in val:
                    findings.append(Finding(
                        "FILE_SENSITIVE", "HIGH", filepath,
                        getattr(node, "lineno", 0),
                        node.value[:100],
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# Signal: CODE_EXECUTION
# ---------------------------------------------------------------------------

_EXEC_CALLS = {
    "eval", "exec", "compile",
    "os.system", "os.popen",
    "subprocess.Popen", "subprocess.run", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
    "__import__",
}


def _check_code_execution(tree: ast.AST, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in _EXEC_CALLS:
                findings.append(Finding(
                    "CODE_EXECUTION", "HIGH", filepath,
                    node.lineno,
                    _snippet(source_lines, node.lineno),
                ))

    return findings


# ---------------------------------------------------------------------------
# Signal: OBFUSCATION
# ---------------------------------------------------------------------------

_OBFUSCATION_CALLS = {
    "base64.b64decode", "base64.decodebytes",
    "codecs.decode",
    "marshal.loads",
}

_HEX_RE = re.compile(r"[0-9a-fA-F]{50,}")


def _check_obfuscation(tree: ast.AST, source_lines: list[str], filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        # Calls to obfuscation functions
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in _OBFUSCATION_CALLS:
                findings.append(Finding(
                    "OBFUSCATION", "HIGH", filepath,
                    node.lineno,
                    _snippet(source_lines, node.lineno),
                ))

            # compile() with a long string argument
            if name == "compile":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if len(arg.value) > 200:
                            findings.append(Finding(
                                "OBFUSCATION", "HIGH", filepath,
                                node.lineno,
                                f"compile() with {len(arg.value)}-char string",
                            ))

        # Long hex strings in literals
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _HEX_RE.search(node.value):
                findings.append(Finding(
                    "OBFUSCATION", "MEDIUM", filepath,
                    getattr(node, "lineno", 0),
                    node.value[:100],
                ))

    return findings


# ---------------------------------------------------------------------------
# Signal: INSTALL_HOOKS (setup.py cmdclass)
# ---------------------------------------------------------------------------

_DANGEROUS_CMDCLASS = {"install", "develop", "egg_info", "sdist", "build_py"}


def _check_install_hooks(tree: ast.AST, source_lines: list[str], filepath: str) -> list[Finding]:
    """Detect cmdclass overrides in setup.py that hook into install/develop."""
    findings: list[Finding] = []

    # Only relevant for setup.py files
    if not filepath.endswith("setup.py"):
        return findings

    for node in ast.walk(tree):
        # Look for cmdclass={...} in setup() or keyword arguments
        if isinstance(node, ast.keyword) and node.arg == "cmdclass":
            # cmdclass is typically a dict with class name mappings
            if isinstance(node.value, ast.Dict):
                for key in node.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if key.value.lower() in _DANGEROUS_CMDCLASS:
                            findings.append(Finding(
                                "INSTALL_HOOKS", "HIGH", filepath,
                                getattr(node, "lineno", 0),
                                f"cmdclass overrides '{key.value}'",
                            ))

        # Also look for classes inheriting from install/develop
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = ""
                if isinstance(base, ast.Name):
                    base_name = base.id
                elif isinstance(base, ast.Attribute):
                    base_name = base.attr
                if base_name.lower() in _DANGEROUS_CMDCLASS:
                    findings.append(Finding(
                        "INSTALL_HOOKS", "HIGH", filepath,
                        node.lineno,
                        f"class {node.name} extends {base_name}",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_file(filepath: str | Path, source: str | None = None) -> list[Finding]:
    """Analyze a single Python file for malicious signals.

    Uses the built-in ``ast`` module — no external dependencies needed.
    """
    filepath = Path(filepath)
    rel_path = str(filepath)

    if source is None:
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

    source_lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return []

    findings: list[Finding] = []
    findings.extend(_check_network(tree, source_lines, rel_path))
    findings.extend(_check_env(tree, source_lines, rel_path))
    findings.extend(_check_file_sensitive(tree, source_lines, rel_path))
    findings.extend(_check_code_execution(tree, source_lines, rel_path))
    findings.extend(_check_obfuscation(tree, source_lines, rel_path))
    findings.extend(_check_install_hooks(tree, source_lines, rel_path))
    return findings


def analyze_directory(directory: str | Path) -> list[Finding]:
    """Analyze all .py files in a directory tree for malicious signals."""
    directory = Path(directory)
    findings: list[Finding] = []

    for py_file in directory.rglob("*.py"):
        findings.extend(analyze_file(py_file))

    return findings
