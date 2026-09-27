import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from project_scan import scan_project
from dependencies import dependency_scan
from deployment import deployment_assessment
from release_gate import release_assessment
from benchmark import run_benchmark


ROOT = Path(__file__).resolve().parents[1]


def test_scan_project_on_real_root():
    result = scan_project(ROOT)
    assert result["file_count"] > 0
    assert "Python" in result["languages"]


def test_scan_project_on_missing_folder():
    result = scan_project(ROOT / "does_not_exist_xyz")
    assert result["file_count"] == 0
    assert result["languages"] == []


def test_dependency_scan_finds_requirements_file():
    result = dependency_scan(ROOT)
    names = [item["file"] for item in result["items"]]
    assert any("requirements.txt" in n for n in names)


def test_deployment_assessment_returns_checks():
    result = deployment_assessment(ROOT)
    assert len(result["checks"]) > 0
    assert "suggested_path" in result


def test_release_assessment_on_missing_folder_is_blocked():
    result = release_assessment(ROOT / "does_not_exist_xyz")
    assert result["state"] == "BLOCKED"


def test_release_assessment_evidence_has_note_field():
    """Every evidence row must carry a 'note' field (may be empty string)."""
    result = release_assessment(ROOT)
    assert "evidence" in result
    for row in result["evidence"]:
        assert "note" in row, f"Evidence row missing 'note': {row}"


def test_run_benchmark_handles_failing_command():
    result = run_benchmark(ROOT, "python -c \"import sys; sys.exit(1)\"", runs=2)
    assert result["status"] == "failed"
    assert "message" in result


def test_run_benchmark_handles_successful_command():
    result = run_benchmark(ROOT, "python -c \"pass\"", runs=2)
    assert result["status"] == "ok"
    assert result["median"] >= 0


def test_run_benchmark_p95_gte_median():
    """p95 must never be less than the median."""
    result = run_benchmark(ROOT, "python -c \"pass\"", runs=3)
    assert result["status"] == "ok"
    assert result["p95"] >= result["median"], (
        f"p95 {result['p95']} < median {result['median']}"
    )


def test_run_benchmark_p95_lte_max():
    """p95 must never exceed the maximum observed value."""
    result = run_benchmark(ROOT, "python -c \"pass\"", runs=3)
    assert result["status"] == "ok"
    assert result["p95"] <= result["max"], (
        f"p95 {result['p95']} > max {result['max']}"
    )


def test_run_benchmark_single_sample_p95_equals_only_value():
    """With exactly one successful run p95 must equal that single measurement."""
    result = run_benchmark(ROOT, "python -c \"pass\"", runs=1)
    assert result["status"] == "ok"
    assert result["p95"] == result["samples"][0]
