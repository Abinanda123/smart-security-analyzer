"""Security rule definitions and pattern matchers for Python AST analysis.

Rules are modular: each rule has metadata (ID, category, CWE, severity)
and an inspection method that checks if an AST node triggers a potential finding.
"""

import ast
from typing import List, Optional, Tuple
from parser.models import Rule


# --- Rule Definitions ---

RULES = {
    # 🟢 MVP Category 1: Code Injection
    "PY001": Rule(
        rule_id="PY001",
        name="EvalCodeInjection",
        category="Code Injection",
        cwe="CWE-94",
        severity_hint="HIGH",
        description="Use of eval() detected. Dynamic code execution can allow arbitrary code execution.",
    ),
    "PY002": Rule(
        rule_id="PY002",
        name="ExecCodeInjection",
        category="Code Injection",
        cwe="CWE-95",
        severity_hint="HIGH",
        description="Use of exec() detected. Dynamic code execution can allow arbitrary code execution.",
    ),

    # 🟢 MVP Category 2: Command Injection
    "PY003": Rule(
        rule_id="PY003",
        name="OsSystemCommandInjection",
        category="Command Injection",
        cwe="CWE-78",
        severity_hint="HIGH",
        description="Use of os.system() detected. Can lead to command injection if input is untrusted.",
    ),
    "PY004": Rule(
        rule_id="PY004",
        name="OsPopenCommandInjection",
        category="Command Injection",
        cwe="CWE-78",
        severity_hint="HIGH",
        description="Use of os.popen() detected. Can lead to command injection if input is untrusted.",
    ),
    "PY005": Rule(
        rule_id="PY005",
        name="SubprocessShellTrue",
        category="Command Injection",
        cwe="CWE-78",
        severity_hint="HIGH",
        description="subprocess call with shell=True detected. Vulnerable to shell injection if arguments are unescaped.",
    ),

    # 🟢 MVP Category 3: SQL Injection
    "PY006": Rule(
        rule_id="PY006",
        name="SqlInjectionFormattedQuery",
        category="SQL Injection",
        cwe="CWE-89",
        severity_hint="HIGH",
        description="Dynamic string formatting/concatenation passed to database execution call.",
    ),

    # 🔵 Version 1 Additional Rules
    "PY007": Rule(
        rule_id="PY007",
        name="UnsafeDeserializationPickle",
        category="Unsafe Deserialization",
        cwe="CWE-502",
        severity_hint="HIGH",
        description="Use of pickle.load/loads() detected. Deserializing untrusted data can lead to remote code execution.",
    ),
    "PY008": Rule(
        rule_id="PY008",
        name="WeakCryptographyHash",
        category="Weak Cryptography",
        cwe="CWE-328",
        severity_hint="MEDIUM",
        description="Use of weak hash function (MD5/SHA1) detected. Insecure for cryptographic signatures and password storage.",
    ),
    "PY009": Rule(
        rule_id="PY009",
        name="HardcodedSecret",
        category="Hardcoded Secrets",
        cwe="CWE-798",
        severity_hint="MEDIUM",
        description="Potential hardcoded secret or credential assigned to a suspicious variable name.",
    ),
}


# --- Helper Utilities to Extract Names from AST ---

def get_call_func_name(node: ast.Call) -> str:
    """Extract full callable name (e.g. 'os.system', 'eval', 'subprocess.run')."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        curr: ast.AST = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def get_node_source_repr(node: ast.AST) -> str:
    """Get a representative string for the source argument or expression."""
    try:
        return ast.unparse(node)
    except Exception:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        return "<expr>"


def is_dynamic_sql_expression(node: ast.AST) -> bool:
    """Check if an AST expression represents a dynamically constructed string/query."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call):
        inner_func = get_call_func_name(node)
        if inner_func.endswith(".format") or inner_func == "format":
            return True
    return False


# --- Pattern Matchers ---

def check_eval_call(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if func_name == "eval" and node.args:
        return "PY001", get_node_source_repr(node.args[0]), "eval"
    return None


def check_exec_call(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if func_name == "exec" and node.args:
        return "PY002", get_node_source_repr(node.args[0]), "exec"
    return None


def check_os_system(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if func_name in ("os.system", "system") and node.args:
        return "PY003", get_node_source_repr(node.args[0]), func_name
    return None


def check_os_popen(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if func_name in ("os.popen", "popen") and node.args:
        return "PY004", get_node_source_repr(node.args[0]), func_name
    return None


def check_subprocess_shell(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if any(func_name.startswith(p) for p in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output")):
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                source_arg = get_node_source_repr(node.args[0]) if node.args else "shell=True"
                return "PY005", source_arg, func_name
    return None


def check_sql_injection(node: ast.Call, env: Optional[dict] = None) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    sink_identifiers = ("execute", "executemany", "raw_sql", "rawQuery")
    is_db_call = any(func_name.endswith(f".{ident}") or func_name == ident for ident in sink_identifiers)
    
    if is_db_call and node.args:
        first_arg = node.args[0]
        if is_dynamic_sql_expression(first_arg):
            return "PY006", get_node_source_repr(first_arg), func_name
        if isinstance(first_arg, ast.Name) and env and first_arg.id in env:
            assigned_expr = env[first_arg.id]
            if is_dynamic_sql_expression(assigned_expr):
                source_repr = f"{first_arg.id} = {get_node_source_repr(assigned_expr)}"
                return "PY006", source_repr, func_name
    return None


def check_unsafe_pickle(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load") and node.args:
        return "PY007", get_node_source_repr(node.args[0]), func_name
    return None


def check_weak_hash(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    func_name = get_call_func_name(node)
    if func_name in ("hashlib.md5", "hashlib.sha1"):
        return "PY008", get_node_source_repr(node.args[0]) if node.args else func_name, func_name
    return None


def check_hardcoded_secrets(node: ast.Assign) -> Optional[Tuple[str, str, str]]:
    secret_keywords = ("api_key", "apikey", "secret_key", "auth_token", "password", "passwd", "access_token")
    target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
    for name in target_names:
        if any(sec in name.lower() for sec in secret_keywords):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value.strip()
                if len(val) >= 8 and not val.startswith("YOUR_") and not val.startswith("ENV_"):
                    masked = val[:3] + "..." + val[-3:] if len(val) > 6 else "***"
                    return "PY009", f"{name} = '{masked}'", "variable_assignment"
    return None
