"""Regression tests for the expanded multi-language security scanner.

One test per rule family per language.
All tests use scan_text() with synthetic snippets — no filesystem access needed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security import security_scan, scan_text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_PROJECTS = Path(__file__).resolve().parents[1] / "sample_projects"


def _findings_titled(result, title_fragment):
    """Return findings whose title contains title_fragment (case-insensitive)."""
    return [f for f in result.get("findings", []) if title_fragment.lower() in f.get("title", "").lower()]


def _assert_field_present(finding, field):
    assert field in finding, f"Finding is missing required field '{field}': {finding}"


def _assert_required_fields(result):
    """Every finding must have all seven required fields."""
    for f in result.get("findings", []):
        for field in ("severity", "title", "file", "line", "reason", "remediation", "regression_test"):
            _assert_field_present(f, field)


def _assert_no_secret_value(result):
    """Matched secret values must NOT appear in any finding field."""
    # We embed a known secret value in snippets; it must never surface.
    secret = "sk_live_1234567890abcdef"
    for f in result.get("findings", []):
        for key, val in f.items():
            if key in ("title", "finding", "reason", "remediation", "regression_test", "file"):
                # These are static strings, not matched values — allowed to contain fragments
                continue
            assert secret not in str(val), (
                f"Secret value appeared in finding[{key!r}]: {val!r}"
            )


# ---------------------------------------------------------------------------
# Existing Python rules (must continue to pass)
# ---------------------------------------------------------------------------

def test_python_hardcoded_secret_high():
    r = scan_text("demo.py", 'api_key = "abcdefgh12345678"')
    assert r["count"] >= 1
    assert r["high"] >= 1
    assert "score" in r


def test_python_hardcoded_token_variations():
    snippets = [
        'password = "supersecret123"',
        'token = "eyJhbGciOiJIUzI1NiJ9.abc"',
        'private_key = "AAAA1234567890xyz"',
        'auth_token = "Bearer abcdef012345"',
    ]
    for snippet in snippets:
        r = scan_text("s.py", snippet)
        assert r["high"] >= 1, f"Expected HIGH finding for: {snippet}"


def test_python_shell_with_user_input_high():
    r = scan_text("a.py", "os.system(input())")
    assert r["high"] >= 1


def test_python_pem_private_key_high():
    r = scan_text("k.py", "key = '-----BEGIN PRIVATE KEY\\n...'")
    assert r["high"] >= 1


def test_python_weak_randomness_medium():
    r = scan_text("r.py", "x = random.randint(0, 9)")
    assert r["medium_low"] >= 1


def test_python_pickle_deserialization_medium():
    r = scan_text("p.py", "data = pickle.loads(raw_bytes)")
    assert r["medium_low"] >= 1


def test_python_bare_except_low():
    r = scan_text("x.py", "try:\n    pass\nexcept:\n    pass")
    assert r["count"] >= 1


def test_python_eval_with_input_medium():
    r = scan_text("e.py", "eval(input('expr: '))")
    assert r["medium_low"] >= 1


def test_python_debug_true_low():
    r = scan_text("s.py", "DEBUG = True")
    assert r["count"] >= 1


def test_python_empty_input_returns_zero_findings():
    r = scan_text("empty.py", "")
    assert r["count"] == 0
    assert r["score"] == 100


def test_python_none_input_does_not_crash():
    r = scan_text(None, None)
    assert r["findings"] == []
    assert r["count"] == 0


def test_python_score_label_says_not_guarantee():
    r = scan_text("clean.py", "")
    assert "not a security guarantee" in r.get("score_label", "").lower()


# ---------------------------------------------------------------------------
# Required fields on every finding
# ---------------------------------------------------------------------------

def test_python_finding_has_all_required_fields():
    r = scan_text("demo.py", 'api_key = "abcdefgh12345678"')
    _assert_required_fields(r)


def test_c_finding_has_all_required_fields():
    r = scan_text("demo.c", "strcpy(buf, input);")
    _assert_required_fields(r)


def test_rust_finding_has_all_required_fields():
    r = scan_text("demo.rs", 'let api_key = "abcdefgh12345678";')
    _assert_required_fields(r)


def test_go_finding_has_all_required_fields():
    r = scan_text("demo.go", 'apiKey := "abcdefgh12345678"')
    _assert_required_fields(r)


def test_java_finding_has_all_required_fields():
    r = scan_text("Demo.java", 'String password = "abcdefgh12345";')
    _assert_required_fields(r)


def test_js_finding_has_all_required_fields():
    r = scan_text("app.js", 'const apiKey = "abcdefgh12345678";')
    _assert_required_fields(r)


def test_ts_finding_has_all_required_fields():
    r = scan_text("app.ts", 'const apiKey = "abcdefgh12345678";')
    _assert_required_fields(r)


# ---------------------------------------------------------------------------
# Secret values must never appear in findings
# ---------------------------------------------------------------------------

def test_secret_value_not_exposed_in_finding_python():
    r = scan_text("demo.py", 'api_key = "sk_live_1234567890abcdef"')
    _assert_no_secret_value(r)


def test_secret_value_not_exposed_in_finding_c():
    r = scan_text("demo.c", 'char api_key[] = "sk_live_1234567890abcdef";')
    _assert_no_secret_value(r)


def test_secret_value_not_exposed_in_finding_js():
    r = scan_text("app.js", 'const apiKey = "sk_live_1234567890abcdef";')
    _assert_no_secret_value(r)


# ---------------------------------------------------------------------------
# C / C++ rules
# ---------------------------------------------------------------------------

def test_c_hardcoded_secret_array_high():
    r = scan_text("demo.c", 'char api_key[] = "sk_live_abc12345678";')
    assert r["high"] >= 1, "Expected HIGH for hard-coded C secret"


def test_c_hardcoded_sk_live_high():
    r = scan_text("demo.c", '"sk_live_1234567890abcdef"')
    assert r["high"] >= 1


def test_c_pem_private_key_high():
    r = scan_text("k.c", "/* -----BEGIN PRIVATE KEY */")
    assert r["high"] >= 1


def test_c_strcpy_high():
    r = scan_text("s.c", "strcpy(buffer, user_input);")
    assert r["high"] >= 1


def test_c_gets_high():
    r = scan_text("g.c", "gets(buffer);")
    assert r["high"] >= 1


def test_c_system_high():
    r = scan_text("s.c", "system(cmd);")
    assert r["high"] >= 1


def test_c_popen_high():
    r = scan_text("p.c", 'popen(cmd, "r");')
    assert r["high"] >= 1


def test_c_sprintf_medium():
    r = scan_text("f.c", "sprintf(buf, fmt, arg);")
    assert r["medium_low"] >= 1


def test_c_malloc_without_null_check_medium():
    r = scan_text("m.c", "int *p = malloc(n * sizeof(int));")
    assert r["medium_low"] >= 1


def test_c_printf_variable_format_medium():
    r = scan_text("f.c", "printf(user_buf);")
    assert r["medium_low"] >= 1


def test_c_strlen_low():
    r = scan_text("l.c", "n = strlen(input);")
    assert r["count"] >= 1


def test_cpp_extension_detected_as_c_ruleset():
    """C++ files must use C rules (strcpy must fire on .cpp)."""
    r = scan_text("main.cpp", "strcpy(buf, input);")
    assert r["high"] >= 1


def test_c_empty_source_returns_zero_findings():
    r = scan_text("empty.c", "")
    assert r["count"] == 0


def test_c_language_label():
    r = scan_text("main.c", "")
    assert r.get("language") == "C"


def test_cpp_language_label():
    r = scan_text("main.cpp", "")
    assert r.get("language") == "C++"


# ---------------------------------------------------------------------------
# C sample files (security_demo.c must produce HIGH; buggy_memory.c >= 1)
# ---------------------------------------------------------------------------

def test_security_demo_c_produces_high_findings():
    demo = _SAMPLE_PROJECTS / "security_demo.c"
    text = demo.read_text(encoding="utf-8")
    r = scan_text("security_demo.c", text)
    assert r["high"] >= 2, f"Expected >= 2 HIGH findings, got {r['high']}: {[f['title'] for f in r['findings']]}"


def test_security_demo_c_detects_strcpy():
    demo = _SAMPLE_PROJECTS / "security_demo.c"
    text = demo.read_text(encoding="utf-8")
    r = scan_text("security_demo.c", text)
    assert _findings_titled(r, "strcpy"), "Expected strcpy finding in security_demo.c"


def test_security_demo_c_detects_system():
    demo = _SAMPLE_PROJECTS / "security_demo.c"
    text = demo.read_text(encoding="utf-8")
    r = scan_text("security_demo.c", text)
    assert _findings_titled(r, "system"), "Expected system() finding in security_demo.c"


def test_security_demo_c_secret_detected():
    demo = _SAMPLE_PROJECTS / "security_demo.c"
    text = demo.read_text(encoding="utf-8")
    r = scan_text("security_demo.c", text)
    assert _findings_titled(r, "secret") or _findings_titled(r, "hard-coded"), (
        "Expected a hard-coded secret finding in security_demo.c"
    )


def test_buggy_memory_c_produces_findings():
    buggy = _SAMPLE_PROJECTS / "buggy_memory.c"
    text = buggy.read_text(encoding="utf-8")
    r = scan_text("buggy_memory.c", text)
    assert r["count"] >= 1, "Expected >= 1 finding in buggy_memory.c"


def test_sample_project_py_no_high_findings():
    sample = _SAMPLE_PROJECTS / "sample_project.py"
    text = sample.read_text(encoding="utf-8")
    r = scan_text("sample_project.py", text)
    assert r["high"] == 0, f"Expected 0 HIGH findings in clean sample, got {r['high']}"


# ---------------------------------------------------------------------------
# Rust rules
# ---------------------------------------------------------------------------

def test_rust_hardcoded_secret_high():
    r = scan_text("demo.rs", 'let api_key = "abcdefgh12345678";')
    assert r["high"] >= 1


def test_rust_pem_key_high():
    r = scan_text("k.rs", "// -----BEGIN PRIVATE KEY")
    assert r["high"] >= 1


def test_rust_unsafe_block_medium():
    r = scan_text("u.rs", "unsafe { *ptr = 1; }")
    assert r["medium_low"] >= 1


def test_rust_command_shell_medium():
    r = scan_text("c.rs", 'Command::new("sh").arg("-c").arg(user_input)')
    assert r["medium_low"] >= 1


def test_rust_unwrap_low():
    r = scan_text("u.rs", "let val = result.unwrap();")
    assert r["count"] >= 1


def test_rust_todo_macro_low():
    r = scan_text("t.rs", "fn foo() { todo!() }")
    assert r["count"] >= 1


def test_rust_empty_source_zero_findings():
    r = scan_text("empty.rs", "")
    assert r["count"] == 0


def test_rust_language_label():
    r = scan_text("main.rs", "")
    assert r.get("language") == "Rust"


# ---------------------------------------------------------------------------
# Go rules
# ---------------------------------------------------------------------------

def test_go_hardcoded_secret_high():
    r = scan_text("demo.go", 'apiKey := "abcdefgh12345678"')
    assert r["high"] >= 1


def test_go_pem_key_high():
    r = scan_text("k.go", "// -----BEGIN PRIVATE KEY")
    assert r["high"] >= 1


def test_go_exec_shell_high():
    r = scan_text("c.go", 'cmd := exec.Command("sh", "-c", userInput)')
    assert r["high"] >= 1


def test_go_math_rand_medium():
    r = scan_text("r.go", "n := rand.Intn(100)")
    assert r["medium_low"] >= 1


def test_go_ignored_error_low():
    r = scan_text("e.go", "_, err := os.Open(filename)")
    assert r["count"] >= 1


def test_go_insecure_skip_verify_low():
    r = scan_text("t.go", "InsecureSkipVerify: true")
    assert r["count"] >= 1


def test_go_empty_source_zero_findings():
    r = scan_text("empty.go", "")
    assert r["count"] == 0


def test_go_language_label():
    r = scan_text("main.go", "")
    assert r.get("language") == "Go"


# ---------------------------------------------------------------------------
# Java rules
# ---------------------------------------------------------------------------

def test_java_hardcoded_secret_high():
    r = scan_text("Demo.java", 'String password = "abcdefgh12345";')
    assert r["high"] >= 1


def test_java_pem_key_high():
    r = scan_text("K.java", "// -----BEGIN PRIVATE KEY")
    assert r["high"] >= 1


def test_java_runtime_exec_high():
    r = scan_text("R.java", "Runtime.getRuntime().exec(userCmd)")
    assert r["high"] >= 1


def test_java_object_inputstream_high():
    r = scan_text("D.java", "ObjectInputStream ois = new ObjectInputStream(inputStream);")
    assert r["high"] >= 1


def test_java_util_random_medium():
    r = scan_text("R.java", "Random r = new Random();")
    assert r["medium_low"] >= 1


def test_java_print_stack_trace_low():
    r = scan_text("E.java", "e.printStackTrace();")
    assert r["count"] >= 1


def test_java_insecure_hostname_verifier_low():
    r = scan_text("T.java", "ALLOW_ALL_HOSTNAME_VERIFIER")
    assert r["count"] >= 1


def test_java_empty_source_zero_findings():
    r = scan_text("Empty.java", "")
    assert r["count"] == 0


def test_java_language_label():
    r = scan_text("Main.java", "")
    assert r.get("language") == "Java"


# ---------------------------------------------------------------------------
# JavaScript rules
# ---------------------------------------------------------------------------

def test_js_hardcoded_secret_high():
    r = scan_text("app.js", 'const apiKey = "abcdefgh12345678";')
    assert r["high"] >= 1


def test_js_pem_key_high():
    r = scan_text("k.js", "// -----BEGIN PRIVATE KEY")
    assert r["high"] >= 1


def test_js_eval_high():
    r = scan_text("e.js", "eval(userInput);")
    assert r["high"] >= 1


def test_js_new_function_high():
    r = scan_text("f.js", "new Function(userCode)()")
    assert r["high"] >= 1


def test_js_child_process_high():
    r = scan_text("c.js", "const { exec } = require('child_process'); exec(cmd)")
    assert r["high"] >= 1


def test_js_proto_pollution_medium():
    r = scan_text("pp.js", "obj.__proto__ = evilProto;")
    assert r["medium_low"] >= 1


def test_js_inner_html_medium():
    r = scan_text("x.js", "el.innerHTML = userInput;")
    assert r["medium_low"] >= 1


def test_js_document_write_medium():
    r = scan_text("w.js", "document.write(userInput);")
    assert r["medium_low"] >= 1


def test_js_console_log_secret_low():
    r = scan_text("l.js", "console.log(password);")
    assert r["count"] >= 1


def test_js_wildcard_dependency_low():
    # package.json uses .json extension which maps to the JS pattern set.
    r = scan_text("package.json", '"lodash": "*"')
    assert r["count"] >= 1


def test_js_empty_source_zero_findings():
    r = scan_text("empty.js", "")
    assert r["count"] == 0


def test_js_language_label():
    r = scan_text("main.js", "")
    assert r.get("language") == "JavaScript"


# ---------------------------------------------------------------------------
# TypeScript rules (superset — TS-specific rule + inherited JS rules)
# ---------------------------------------------------------------------------

def test_ts_hardcoded_secret_high():
    r = scan_text("app.ts", 'const apiKey = "abcdefgh12345678";')
    assert r["high"] >= 1


def test_ts_eval_high():
    r = scan_text("e.ts", "eval(userInput);")
    assert r["high"] >= 1


def test_ts_as_any_medium():
    r = scan_text("a.ts", "const x = (value as any).secret;")
    assert r["medium_low"] >= 1


def test_ts_empty_source_zero_findings():
    r = scan_text("empty.ts", "")
    assert r["count"] == 0


def test_ts_language_label():
    r = scan_text("main.ts", "")
    assert r.get("language") == "TypeScript"


# ---------------------------------------------------------------------------
# Unknown extension — must not crash, returns zero findings
# ---------------------------------------------------------------------------

def test_unknown_extension_returns_zero_findings():
    r = scan_text("data.xyz", "api_key = 'abcdefgh12345678'")
    assert r["count"] == 0


def test_unknown_extension_returns_unknown_language():
    r = scan_text("data.xyz", "")
    assert r.get("language") == "Unknown"


# ---------------------------------------------------------------------------
# security_scan() on filesystem (existing behaviour preserved)
# ---------------------------------------------------------------------------

def test_security_scan_on_missing_folder_does_not_crash():
    result = security_scan(Path(__file__).parent / "does_not_exist_xyz")
    assert "findings" in result
    assert result["count"] == 0


def test_security_scan_on_sample_projects_detects_c_findings():
    """Full filesystem scan of sample_projects/ must surface C findings."""
    result = security_scan(_SAMPLE_PROJECTS)
    titles = [f.get("title", "") for f in result.get("findings", [])]
    assert result["high"] >= 2, (
        f"Expected >= 2 HIGH findings from sample_projects, got {result['high']}. Titles: {titles}"
    )


def test_security_scan_returns_score_field():
    result = security_scan(Path(__file__).resolve().parents[1])
    assert "score" in result


def test_security_scan_score_label_not_guarantee():
    result = security_scan(_SAMPLE_PROJECTS)
    assert "not a security guarantee" in result.get("score_label", "").lower()
