import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from language_tools import language_from_filename, language_advisor, basic_source_stats


def test_language_from_filename_known_extensions():
    assert language_from_filename("main.c") == "C"
    assert language_from_filename("app.py") == "Python"
    assert language_from_filename("server.go") == "Go"
    assert language_from_filename("index.tsx") == "TypeScript"


def test_language_from_filename_unknown_extension():
    assert language_from_filename("data.xyz") == "Unknown"


def test_language_from_filename_handles_none():
    assert language_from_filename(None) == "Unknown"


def test_language_advisor_returns_safe_defaults_for_unknown_goal():
    result = language_advisor("underwater basket weaving", "Python")
    assert result["current_language"] == "Python"
    assert isinstance(result["suggested_alternatives"], list)
    assert result["reason"]


def test_language_advisor_flags_good_fit():
    result = language_advisor("embedded firmware", "C")
    assert result["well_suited"] is True


def test_basic_source_stats_on_empty_text():
    stats = basic_source_stats("")
    assert stats["total_lines"] == 0
    assert stats["todo_fixme_count"] == 0
