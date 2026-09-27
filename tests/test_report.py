import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from report import build_report


_EXPECTED_SECTIONS = [
    "SiliconFit Secure Engineering Report",
    "## Project",
    "## Security",
    "## Dependencies",
    "## Deployment",
    "## Release Gate",
]


def test_build_report_on_real_project_root():
    root = Path(__file__).resolve().parents[1]
    report = build_report(root)
    assert "SiliconFit Secure Engineering Report" in report
    assert "Release Gate" in report


def test_build_report_on_missing_folder_does_not_crash():
    report = build_report(Path(__file__).parent / "does_not_exist_xyz")
    assert isinstance(report, str)
    assert "Release Gate" in report


def test_build_report_contains_all_sections():
    """All expected section headings must appear even on a missing folder."""
    report = build_report(Path(__file__).parent / "does_not_exist_xyz")
    for section in _EXPECTED_SECTIONS:
        assert section in report, f"Expected section missing: {section!r}"


def test_build_report_safe_on_missing_folder_no_key_error():
    """build_report must never raise KeyError on a missing project folder."""
    try:
        build_report(Path(__file__).parent / "absolutely_does_not_exist_xyz_abc")
    except KeyError as e:
        raise AssertionError(f"KeyError raised in build_report: {e}") from e
