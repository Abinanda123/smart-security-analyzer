"""Security rule definitions and pattern matchers for Python AST analysis.

Rules are modular: each rule has metadata (ID, category, CWE, severity)
and an inspection method that checks if an AST node triggers a potential finding.
"""

import ast
from typing import List, Optional, Tuple
from parser.models import Rule, Finding


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
        # ast.unparse is available in Python 3.9+
        return ast.unparse(node)
    except Exception:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        return "<expr>"


# --- Pattern Matchers ---

def check_eval_call(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY001: eval(expr)"""
    func_name = get_call_func_name(node)
    if func_name == "eval" and node.args:
        source_arg = get_node_source_repr(node.args[0])
        return "PY001", source_arg, "eval"
    return None


def check_exec_call(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY002: exec(expr)"""
    func_name = get_call_func_name(node)
    if func_name == "exec" and node.args:
        source_arg = get_node_source_repr(node.args[0])
        return "PY002", source_arg, "exec"
    return None


def check_os_system(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY003: os.system(cmd)"""
    func_name = get_call_func_name(node)
    if func_name in ("os.system", "system") and node.args:
        source_arg = get_node_source_repr(node.args[0])
        return "PY003", source_arg, func_name
    return None


def check_os_popen(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY004: os.popen(cmd)"""
    func_name = get_call_func_name(node)
    if func_name in ("os.popen", "popen") and node.args:
        source_arg = get_node_source_repr(node.args[0])
        return "PY004", source_arg, func_name
    return None


def check_subprocess_shell(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY005: subprocess.*(..., shell=True)"""
    func_name = get_call_func_name(node)
    if any(func_name.startswith(p) for p in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output")):
        for kw in node.keywords:
            if kw.arg == "shell":
                # Check if shell is True
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    source_arg = get_node_source_repr(node.args[0]) if node.args else "shell=True"
                    return "PY005", source_arg, func_name
    return None


def is_dynamic_sql_expression(node: ast.AST) -> bool:
    """Check if an AST expression represents a dynamically constructed string/query."""
    # Case 1: JoinedStr (f-string: f"SELECT ... {val}")
    if isinstance(node, ast.JoinedStr):
        return True

    # Case 2: BinOp with % or + (e.g. "SELECT..." % val or "SELECT..." + val)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.Mod, ast.Add)):
            return True

    # Case 3: str.format() call (e.g. "SELECT...{}".format(val))
    if isinstance(node, ast.Call):
        inner_func = get_call_func_name(node)
        if inner_func.endswith(".format") or inner_func == "format":
            return True

    return False


def check_sql_injection(node: ast.Call, env: Optional[dict] = None) -> Optional[Tuple[str, str, str]]:
    """Rule PY006: cursor.execute(query) with dynamic string formatting or f-strings.
    Detects patterns like:
      - execute(f"SELECT ... {user_input}")
      - execute("SELECT ... %s" % user_input)
      - execute("SELECT ... " + user_input)
      - execute("SELECT ... {}".format(user_input))
      - query = f"..."; execute(query)
    """
    func_name = get_call_func_name(node)
    sink_identifiers = ("execute", "executemany", "raw_sql", "rawQuery")
    
    is_db_call = any(func_name.endswith(f".{ident}") or func_name == ident for ident in sink_identifiers)
    if is_db_call and node.args:
        first_arg = node.args[0]
        
        # Check direct dynamic expression
        if is_dynamic_sql_expression(first_arg):
            return "PY006", get_node_source_repr(first_arg), func_name

        # Check if first_arg is a variable defined earlier with a dynamic expression
        if isinstance(first_arg, ast.Name) and env and first_arg.id in env:
            assigned_expr = env[first_arg.id]
            if is_dynamic_sql_expression(assigned_expr):
                source_repr = f"{first_arg.id} = {get_node_source_repr(assigned_expr)}"
                return "PY006", source_repr, func_name

    return None


def check_unsafe_pickle(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY007: pickle.loads / pickle.load"""
    func_name = get_call_func_name(node)
    if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load") and node.args:
        source_arg = get_node_source_repr(node.args[0])
        return "PY007", source_arg, func_name
    return None


def check_weak_hash(node: ast.Call) -> Optional[Tuple[str, str, str]]:
    """Rule PY008: hashlib.md5 or hashlib.sha1"""
    func_name = get_call_func_name(node)
    if func_name in ("hashlib.md5", "hashlib.sha1"):
        source_arg = get_node_source_repr(node.args[0]) if node.args else func_name
        return "PY008", source_arg, func_name
    return None


def check_hardcoded_secrets(node: ast.Assign) -> Optional[Tuple[str, str, str]]:
    """Rule PY009: Suspicious assignment like api_key = "..." or password = "..."."""
    secret_keywords = ("api_key", "apikey", "secret_key", "auth_token", "password", "passwd", "access_token")
    
    # Check if target variable name is suspicious
    target_names = []
    for target in node.targets:
        if isinstance(target, ast.Name):
            target_names.append(target.id)
        elif isinstance(target, ast.Attribute):
            target_names.append(target.attr)

    for name in target_names:
        lower_name = name.lower()
        if any(sec in lower_name for sec in secret_keywords):
            # Check if value is a non-empty string literal
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value.strip()
                # Exclude obvious empty/placeholders
                if len(val) >= 8 and not val.startswith("YOUR_") and not val.startswith("ENV_"):
                    # Mask the secret for safety
                    masked = val[:3] + "..." + val[-3:] if len(val) > 6 else "***"
                    return "PY009", f"{name} = '{masked}'", "variable_assignment"
    return None
