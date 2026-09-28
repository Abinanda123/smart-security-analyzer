"""Unit tests for AST static analysis rules and findings."""

import unittest
from pathlib import Path
from parser.ast_parser import parse_code, parse_file
from scanner.project_scanner import scan_project


class TestASTRules(unittest.TestCase):

    def test_eval_detection(self):
        code = "result = eval(user_data)"
        findings = parse_code(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY001")
        self.assertEqual(findings[0].category, "Code Injection")
        self.assertEqual(findings[0].sink, "eval")
        self.assertEqual(findings[0].source, "user_data")

    def test_exec_detection(self):
        code = "exec(payload)"
        findings = parse_code(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY002")
        self.assertEqual(findings[0].category, "Code Injection")
        self.assertEqual(findings[0].sink, "exec")

    def test_os_system_detection(self):
        code = "os.system('rm -rf ' + path)"
        findings = parse_code(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY003")
        self.assertEqual(findings[0].category, "Command Injection")
        self.assertEqual(findings[0].sink, "os.system")

    def test_subprocess_shell_true(self):
        code = "subprocess.run(user_cmd, shell=True)"
        findings = parse_code(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY005")
        self.assertEqual(findings[0].category, "Command Injection")

    def test_subprocess_shell_false_is_ignored(self):
        code = "subprocess.run(['ls', '-l'], shell=False)"
        findings = parse_code(code)
        self.assertEqual(len(findings), 0)

    def test_sql_injection_fstring(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = parse_code(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY006")
        self.assertEqual(findings[0].category, "SQL Injection")

    def test_sql_injection_binop(self):
        code = 'db.execute("SELECT * FROM items WHERE name = %s" % user_query)'
        findings = parse_code(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PY006")

    def test_safe_sql_parameterized_ignored(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = parse_code(code)
        self.assertEqual(len(findings), 0)

    def test_vulnerable_sample_file(self):
        sample_path = Path(__file__).parent / "test_samples" / "vulnerable_sample.py"
        findings = parse_file(str(sample_path))
        rule_ids = {f.rule_id for f in findings}
        # Check that MVP categories are found
        self.assertIn("PY001", rule_ids)  # eval
        self.assertIn("PY002", rule_ids)  # exec
        self.assertIn("PY003", rule_ids)  # os.system
        self.assertIn("PY004", rule_ids)  # os.popen
        self.assertIn("PY005", rule_ids)  # subprocess shell=True
        self.assertIn("PY006", rule_ids)  # SQL injection

    def test_safe_sample_file(self):
        sample_path = Path(__file__).parent / "test_samples" / "safe_sample.py"
        findings = parse_file(str(sample_path))
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
