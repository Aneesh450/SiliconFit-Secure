import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from result_utils import safe_get, normalise_status, clamp


# ---------------------------------------------------------------------------
# safe_get
# ---------------------------------------------------------------------------

def test_safe_get_returns_value_for_existing_key():
    assert safe_get({"a": 1}, "a") == 1


def test_safe_get_returns_default_for_missing_key():
    assert safe_get({"a": 1}, "b", 99) == 99


def test_safe_get_returns_default_when_dict_is_none():
    assert safe_get(None, "key", "fallback") == "fallback"


def test_safe_get_returns_default_when_dict_is_not_a_dict():
    assert safe_get("not a dict", "key", 0) == 0


def test_safe_get_default_is_none_when_not_specified():
    assert safe_get({}, "missing") is None


# ---------------------------------------------------------------------------
# normalise_status
# ---------------------------------------------------------------------------

def test_normalise_status_pass_variants():
    assert normalise_status("PASS") == "PASS"
    assert normalise_status("PASSED") == "PASS"
    assert normalise_status("OK") == "PASS"
    assert normalise_status("XPASS") == "PASS"
    assert normalise_status("ready for review") == "PASS"


def test_normalise_status_fail_variants():
    assert normalise_status("FAIL") == "FAIL"
    assert normalise_status("FAILED") == "FAIL"
    assert normalise_status("BLOCKED") == "FAIL"
    assert normalise_status("BLOCK") == "FAIL"


def test_normalise_status_warn_variants():
    assert normalise_status("WARN") == "WARN"
    assert normalise_status("WARNING") == "WARN"
    assert normalise_status("REVIEW") == "WARN"


def test_normalise_status_skip_variants():
    assert normalise_status("SKIP") == "SKIP"
    assert normalise_status("SKIPPED") == "SKIP"
    assert normalise_status("XFAIL") == "SKIP"


def test_normalise_status_not_run_variants():
    assert normalise_status("NOT_RUN") == "NOT_RUN"
    assert normalise_status("NOT RUN") == "NOT_RUN"
    assert normalise_status("NOTRUN") == "NOT_RUN"


def test_normalise_status_unknown_input():
    assert normalise_status("BANANA") == "UNKNOWN"
    assert normalise_status("") == "UNKNOWN"
    assert normalise_status(None) == "UNKNOWN"
    assert normalise_status(42) == "UNKNOWN"


def test_normalise_status_case_insensitive():
    assert normalise_status("pass") == "PASS"
    assert normalise_status("Warn") == "WARN"
    assert normalise_status("error") == "ERROR"


# ---------------------------------------------------------------------------
# clamp
# ---------------------------------------------------------------------------

def test_clamp_within_range():
    assert clamp(5, 1, 10) == 5


def test_clamp_at_lower_bound():
    assert clamp(0, 1, 10) == 1


def test_clamp_at_upper_bound():
    assert clamp(20, 1, 10) == 10


def test_clamp_with_float():
    result = clamp(0.5, 0.0, 1.0)
    assert result == 0.5


def test_clamp_none_returns_lo():
    assert clamp(None, 0, 100) == 0


def test_clamp_non_numeric_returns_lo():
    assert clamp("bad", 0, 100) == 0
