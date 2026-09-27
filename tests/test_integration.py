"""Integration smoke tests — Phase 10.

Exercises the full pipeline on real sample files and the project root.
No Streamlit rendering — pure Python backend calls.

Slow tests (those that spawn subprocesses via run_benchmark) are gated
behind the RUN_INTEGRATION=1 environment variable so the default
  pytest -q
run stays fast.
"""

import os
import sys
import importlib
from pathlib import Path

import pytest

# Make the siliconfit package importable from the tests sub-directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from project_scan import scan_project
from security import security_scan, scan_text
from debugger import debug_scan
from processor_fit import processor_fit, analyse_source, TARGETS, LANGUAGES
from dependencies import dependency_scan
from deployment import deployment_assessment
from release_gate import release_assessment
from report import build_report
from language_tools import language_from_filename, language_advisor, basic_source_stats
from public_security_db import get_all as db_get_all, search as db_search
from developer_chat import answer as chat_answer
from commit_message import generate as gen_commit
from test_scaffold import generate_test_template
from result_utils import safe_get
from recommendations import recommend_stack
from workflow import build_workflow

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parents[1]
_SAMPLES = _ROOT / "sample_projects"
_SAMPLE_PY = _SAMPLES / "sample_project.py"
_SECURITY_DEMO = _SAMPLES / "security_demo.c"
_BUGGY_MEMORY = _SAMPLES / "buggy_memory.c"

RUN_INTEGRATION = os.environ.get("RUN_INTEGRATION", "0") == "1"
integration = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="Set RUN_INTEGRATION=1 to run subprocess-heavy integration tests",
)


# ══════════════════════════════════════════════════════════════════════════════
# Full pipeline — clean Python file
# ══════════════════════════════════════════════════════════════════════════════

def test_full_pipeline_clean_python_file():
    """sample_project.py: scan → language → debug → security → report."""
    text = _SAMPLE_PY.read_text(encoding="utf-8")
    filename = _SAMPLE_PY.name

    # Language detection
    lang = language_from_filename(filename)
    assert lang == "Python"

    # Stats
    stats = basic_source_stats(text)
    assert stats["total_lines"] > 0
    assert isinstance(stats["non_blank_lines"], int)

    # Security — clean file should have zero HIGH findings
    sec = scan_text(filename, text)
    assert sec["high"] == 0, f"Expected 0 HIGH sec findings, got {sec['high']}"
    assert "findings" in sec
    assert isinstance(sec["findings"], list)

    # Debug — clean file should have few or no HIGH findings
    dbg = debug_scan(filename, text)
    assert "findings" in dbg
    assert isinstance(dbg["findings"], list)
    assert dbg["advisory"] is True

    # Report on the siliconfit root (not the sample file)
    report = build_report(_ROOT)
    assert "SiliconFit Secure Engineering Report" in report
    assert "## Security" in report


def test_full_pipeline_security_demo_c():
    """security_demo.c: scan → security should produce HIGH findings."""
    text = _SECURITY_DEMO.read_text(encoding="utf-8")
    filename = _SECURITY_DEMO.name

    sec = scan_text(filename, text)
    assert sec["high"] > 0, (
        f"security_demo.c should produce HIGH findings; got high={sec['high']}, "
        f"findings={[f['title'] for f in sec['findings']]}"
    )


def test_full_pipeline_security_demo_c_project_scan():
    """Project scan of sample_projects/ should detect C language."""
    r = scan_project(_SAMPLES)
    assert r["file_count"] > 0
    assert "C" in r["languages"]


def test_full_pipeline_buggy_memory_c():
    """buggy_memory.c: debug scan should detect off-by-one and malloc findings."""
    text = _BUGGY_MEMORY.read_text(encoding="utf-8")
    filename = _BUGGY_MEMORY.name

    dbg = debug_scan(filename, text)
    assert dbg["count"] > 0, "Expected at least one debug finding in buggy_memory.c"
    assert dbg["advisory"] is True
    # should have either off-by-one or malloc finding
    titles = [f["title"].lower() for f in dbg["findings"]]
    assert any("off-by-one" in t or "malloc" in t or "memory" in t or "loop" in t for t in titles), (
        f"Expected off-by-one/malloc/memory/loop finding; got: {titles}"
    )


def test_full_pipeline_buggy_memory_security():
    """buggy_memory.c: security scan should not crash; result has required fields."""
    text = _BUGGY_MEMORY.read_text(encoding="utf-8")
    sec = scan_text(_BUGGY_MEMORY.name, text)
    # malloc without free is a debug finding; security may or may not fire — just check it doesn't crash
    assert isinstance(sec["findings"], list)
    assert "count" in sec
    assert "score" in sec


# ══════════════════════════════════════════════════════════════════════════════
# Report sections
# ══════════════════════════════════════════════════════════════════════════════

_EXPECTED_SECTIONS = [
    "SiliconFit Secure Engineering Report",
    "## Project",
    "## Security",
    "## Tests",
    "## Debug Findings",
    "## Benchmark",
    "## Processor Fit",
    "## Dependencies",
    "## Deployment",
    "## Release Gate",
]


def test_report_contains_all_sections():
    """build_report must contain every documented section heading."""
    report = build_report(_ROOT)
    for section in _EXPECTED_SECTIONS:
        assert section in report, f"Report missing section: {section!r}"


def test_report_not_run_for_missing_context():
    """Sections without session context must say NOT RUN, not raise."""
    report = build_report(_ROOT, context={})
    assert "NOT RUN" in report


def test_report_with_full_context_contains_data():
    """When context has all keys, report should include actual numbers."""
    ctx = {
        "last_test_run": {
            "execution_status": "PASS",
            "passed": 42,
            "failed": 0,
            "errors": 0,
            "skipped": 1,
            "duration": 3.14,
        },
        "last_benchmark": {
            "status": "ok",
            "median": 0.0023,
            "p95": 0.003,
            "cv": 5.1,
            "baseline_status": "UNAVAILABLE",
        },
        "last_debug_scan": {
            "count": 3,
            "high": 1,
            "medium": 2,
            "low": 0,
        },
        "last_processor_fit": {
            "language": "C",
            "target": "ARM64",
            "fit": "STRONG",
            "reason": "C compiles to native ARM64.",
        },
    }
    report = build_report(_ROOT, context=ctx)
    assert "42" in report          # passed tests
    assert "STRONG" in report      # processor fit
    assert "0.0023" in report      # benchmark median
    assert "ARM64" in report


# ══════════════════════════════════════════════════════════════════════════════
# No-network guarantee
# ══════════════════════════════════════════════════════════════════════════════

def test_no_module_calls_network():
    """Core modules must not import the socket module at the top level.

    We check the actual module source for a top-level `import socket`.
    This is a defensive, advisory check — not a runtime network trace.
    """
    import ast
    import re

    core_modules = [
        "security",
        "debugger",
        "processor_fit",
        "public_security_db",
        "developer_chat",
        "commit_message",
        "report",
        "release_gate",
        "benchmark",
        "project_scan",
        "recommendations",
        "workflow",
        "language_tools",
        "result_utils",
        "dependencies",
        "deployment",
        "test_runner",
        "test_scaffold",
    ]
    network_imports = re.compile(r"^\s*(import|from)\s+(socket|urllib|requests|http\.client|httpx|aiohttp|boto3|ibm_watson)\b", re.MULTILINE)
    for mod_name in core_modules:
        src_path = _ROOT / f"{mod_name}.py"
        if not src_path.exists():
            continue
        src = src_path.read_text(encoding="utf-8")
        m = network_imports.search(src)
        assert m is None, (
            f"Module {mod_name}.py imports a network-related module: {m.group(0).strip()!r}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Processor Fit
# ══════════════════════════════════════════════════════════════════════════════

def test_processor_fit_c_arm64_is_strong():
    r = processor_fit("C", "ARM64")
    assert r["fit"] == "STRONG"
    assert r["advisory"] is True


def test_processor_fit_unknown_target_does_not_raise():
    r = processor_fit("Python", "ZX Spectrum")
    assert r["fit"] == "UNKNOWN"
    assert "advisory" in r


def test_processor_fit_all_languages_all_targets_no_raise():
    for lang in LANGUAGES:
        for tgt in TARGETS:
            r = processor_fit(lang, tgt)
            assert "fit" in r
            assert "advisory" in r


def test_analyse_source_security_demo_c_no_raise():
    text = _SECURITY_DEMO.read_text(encoding="utf-8")
    r = analyse_source(_SECURITY_DEMO.name, text, "Generic x86-64")
    assert "advisory" in r
    assert isinstance(r.get("observations", []), list)


# ══════════════════════════════════════════════════════════════════════════════
# Public Security DB
# ══════════════════════════════════════════════════════════════════════════════

def test_db_get_all_returns_list():
    entries = db_get_all()
    assert isinstance(entries, list)
    assert len(entries) > 0


def test_db_search_by_language():
    # search() uses substring matching so "C" matches "C", "C++", "C#" etc.
    c_entries = db_search(language="C")
    # Every returned entry must have at least one language containing "c" (case-insensitive)
    assert all(
        any("c" in lang.lower() for lang in e.get("languages", []))
        for e in c_entries
    )


def test_db_search_by_severity():
    high = db_search(severity="HIGH")
    assert all(e["severity"] == "HIGH" for e in high)


def test_db_search_no_filters_returns_all():
    all_entries = db_search()
    assert len(all_entries) == len(db_get_all())


def test_db_search_keyword_returns_subset():
    results = db_search(keyword="injection")
    assert len(results) <= len(db_get_all())
    # all results should contain "injection" somewhere
    for e in results:
        searchable = " ".join([
            e.get("vuln_class", ""),
            e.get("description", ""),
            e.get("remediation", ""),
        ]).lower()
        assert "inject" in searchable or "sql" in searchable


def test_db_entries_have_required_fields():
    for e in db_get_all():
        assert "id" in e
        assert "vuln_class" in e
        assert "severity" in e
        assert "languages" in e
        assert isinstance(e["languages"], list)
        assert "remediation" in e


# ══════════════════════════════════════════════════════════════════════════════
# Developer Chat
# ══════════════════════════════════════════════════════════════════════════════

def test_chat_answer_with_no_context_returns_insufficient_evidence():
    r = chat_answer("Are there security issues?", {})
    assert "answer" in r
    assert "advisory" in r
    # With empty context, expect an "insufficient" or "not run" response
    assert isinstance(r["answer"], str)
    assert len(r["answer"]) > 0


def test_chat_answer_with_security_context():
    ctx = {
        "last_security_scan": {
            "count": 3,
            "high": 1,
            "medium_low": 2,
        }
    }
    r = chat_answer("What are the security issues?", ctx)
    assert isinstance(r["answer"], str)
    assert r["advisory"] is True


def test_chat_answer_empty_question_does_not_raise():
    r = chat_answer("", {})
    assert isinstance(r, dict)
    assert "answer" in r


def test_chat_answer_none_context_does_not_raise():
    r = chat_answer("test", None)
    assert isinstance(r, dict)


# ══════════════════════════════════════════════════════════════════════════════
# Commit Message
# ══════════════════════════════════════════════════════════════════════════════

def test_commit_message_generates_conventional_format():
    r = gen_commit("feat", "security", "add OWASP pattern checks")
    assert r["message"].startswith("feat(security): add OWASP pattern checks")
    assert r["advisory"] is True


def test_commit_message_empty_description_returns_error():
    r = gen_commit("fix", "core", "")
    assert "error" in r
    assert r.get("message", "") == ""


def test_commit_message_breaking_change():
    r = gen_commit("feat", "api", "rename endpoint", breaking=True)
    assert "!" in r["message"]
    assert "BREAKING CHANGE" in r["message"]


def test_commit_message_unknown_type_defaults_to_chore():
    r = gen_commit("foobar", "", "update config")
    assert r["message"].startswith("chore: ")


# ══════════════════════════════════════════════════════════════════════════════
# Test Scaffold
# ══════════════════════════════════════════════════════════════════════════════

def test_scaffold_for_python_file_returns_template():
    text = _SAMPLE_PY.read_text(encoding="utf-8")
    r = generate_test_template(_SAMPLE_PY.name, text)
    assert "template" in r
    assert "def test_" in r["template"]


def test_scaffold_for_c_file_returns_template():
    text = _SECURITY_DEMO.read_text(encoding="utf-8")
    r = generate_test_template(_SECURITY_DEMO.name, text)
    assert "template" in r
    assert isinstance(r["template"], str)


def test_scaffold_for_empty_text_does_not_raise():
    r = generate_test_template("nothing.py", "")
    assert "template" in r


# ══════════════════════════════════════════════════════════════════════════════
# Language Tools
# ══════════════════════════════════════════════════════════════════════════════

def test_language_from_filename_python():
    assert language_from_filename("main.py") == "Python"


def test_language_from_filename_c():
    assert language_from_filename("prog.c") == "C"


def test_language_from_filename_unknown():
    lang = language_from_filename("archive.tar.gz")
    assert isinstance(lang, str)


def test_language_advisor_well_suited():
    r = language_advisor("ai/ml", "Python")
    assert r.get("well_suited") is True


def test_language_advisor_returns_advisory_dict():
    r = language_advisor("embedded firmware", "JavaScript")
    assert "well_suited" in r
    assert "current_language" in r


# ══════════════════════════════════════════════════════════════════════════════
# Recommendations (Bob 2.0)
# ══════════════════════════════════════════════════════════════════════════════

def test_recommend_stack_returns_list():
    recs = recommend_stack("I need a fast web API", "Web/API", ["Performance"], "Linux")
    assert isinstance(recs, list)


def test_recommend_stack_each_has_required_fields():
    recs = recommend_stack("embedded firmware", "Embedded/IoT", ["Performance"], "Linux")
    for r in recs:
        assert "name" in r
        assert "fit" in r
        assert "why" in r


# ══════════════════════════════════════════════════════════════════════════════
# Workflow
# ══════════════════════════════════════════════════════════════════════════════

def test_build_workflow_returns_steps():
    steps = build_workflow("web backend", _ROOT)
    assert isinstance(steps, list)
    assert len(steps) > 0
    for step in steps:
        assert "title" in step
        assert "action" in step


def test_build_workflow_empty_goal_does_not_raise():
    steps = build_workflow("", _ROOT)
    assert isinstance(steps, list)


# ══════════════════════════════════════════════════════════════════════════════
# Release Gate
# ══════════════════════════════════════════════════════════════════════════════

def test_release_gate_on_siliconfit_root_returns_valid_state():
    """Release gate on the actual project root must return a valid state."""
    r = release_assessment(_ROOT)
    assert r["state"] in {"READY FOR REVIEW", "BLOCKED", "WARN", "REVIEW"}
    assert "evidence" in r
    assert "reasons" in r
    assert "disclaimer" in r


def test_release_gate_evidence_rows_have_note_field():
    r = release_assessment(_ROOT)
    for row in r["evidence"]:
        assert "note" in row, f"Evidence row missing 'note': {row}"


def test_release_gate_missing_folder_is_blocked():
    r = release_assessment(_ROOT / "does_not_exist_xyz_integration")
    assert r["state"] == "BLOCKED"


# ══════════════════════════════════════════════════════════════════════════════
# app.py importability (no Streamlit rendering needed)
# ══════════════════════════════════════════════════════════════════════════════

def test_app_imports_are_available():
    """All modules imported by app.py must be importable without error."""
    modules = [
        "project_scan",
        "recommendations",
        "workflow",
        "test_runner",
        "benchmark",
        "security",
        "debugger",
        "processor_fit",
        "dependencies",
        "deployment",
        "release_gate",
        "report",
        "language_tools",
        "public_security_db",
        "developer_chat",
        "commit_message",
        "test_scaffold",
        "result_utils",
    ]
    for mod in modules:
        importlib.import_module(mod)


# ══════════════════════════════════════════════════════════════════════════════
# Subprocess-heavy tests (gated behind RUN_INTEGRATION=1)
# ══════════════════════════════════════════════════════════════════════════════

@integration
def test_benchmark_integration_real_command():
    from benchmark import run_benchmark
    r = run_benchmark(_ROOT, 'python -c "pass"', runs=3)
    assert r["status"] == "ok"
    assert r["median"] >= 0
    assert "samples" in r


@integration
def test_test_runner_integration_real_command():
    from test_runner import run_tests
    r = run_tests(_ROOT, "python -m pytest tests/ -q --tb=no")
    assert isinstance(r.get("passed"), int)
    assert isinstance(r.get("failed"), int)
