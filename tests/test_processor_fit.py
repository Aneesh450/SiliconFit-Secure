"""Regression tests for processor_fit.py.

Tests cover:
- Static fit matrix: all languages × all targets
- Target and language normalisation (aliases, case, unknown values)
- Required fields in every response
- advisory flag always True
- analysis_type always STATIC_ANALYSIS
- Source heuristic analysis: each signal family
- Empty / None / malformed source handling
- Disclaimer presence
- No invented specs or benchmark claims
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from processor_fit import (
    processor_fit,
    processor_fit_all_targets,
    analyse_source,
    TARGETS,
    LANGUAGES,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_fit_fields(result):
    """Every processor_fit() result must have these fields."""
    for field in ("language", "target", "fit", "reason", "notes", "advisory",
                  "analysis_type", "disclaimer"):
        assert field in result, f"Missing field '{field}' in: {result}"


def _assert_analyse_fields(result):
    """Every analyse_source() result must have these fields."""
    for field in ("file", "target", "observations", "recommendations",
                  "observation_count", "recommendation_count",
                  "advisory", "analysis_type", "disclaimer"):
        assert field in result, f"Missing field '{field}' in: {result}"


def _assert_recommendation_fields(rec):
    """Every recommendation must have all required fields."""
    for field in ("target", "category", "signal", "file", "first_line",
                  "current_implementation", "potential_issue",
                  "proposed_optimization", "expected_benefit",
                  "risk", "verification_method", "advisory",
                  "analysis_type", "disclaimer"):
        assert field in rec, f"Missing field '{field!r}' in recommendation: {rec}"


def _recs_for_signal(result, signal_name):
    return [r for r in result["recommendations"] if r["signal"] == signal_name]


def _obs_for_signal(result, signal_name):
    return [o for o in result["observations"] if o["signal"] == signal_name]


# ---------------------------------------------------------------------------
# TARGETS list
# ---------------------------------------------------------------------------

def test_targets_list_contains_all_six():
    assert len(TARGETS) == 6
    expected = {
        "Generic x86-64", "Intel x86-64", "AMD x86-64",
        "ARM64", "RISC-V 64", "ESP32-class MCU",
    }
    assert set(TARGETS) == expected


def test_languages_list_contains_all_supported():
    for lang in ("C", "C++", "Python", "Rust", "Go", "Java",
                 "JavaScript", "TypeScript", "Custom"):
        assert lang in LANGUAGES, f"Missing language: {lang}"


# ---------------------------------------------------------------------------
# processor_fit() — required fields and advisory flag
# ---------------------------------------------------------------------------

def test_fit_returns_all_required_fields():
    result = processor_fit("C", "Generic x86-64")
    _assert_fit_fields(result)


def test_fit_advisory_always_true():
    for lang in LANGUAGES:
        for tgt in TARGETS:
            r = processor_fit(lang, tgt)
            assert r["advisory"] is True, f"advisory not True for ({lang}, {tgt})"


def test_fit_analysis_type_always_static():
    for lang in LANGUAGES:
        for tgt in TARGETS:
            r = processor_fit(lang, tgt)
            assert r["analysis_type"] == "STATIC_ANALYSIS", (
                f"analysis_type wrong for ({lang}, {tgt}): {r['analysis_type']}"
            )


def test_fit_disclaimer_present_and_nonempty():
    for lang in LANGUAGES:
        for tgt in TARGETS:
            r = processor_fit(lang, tgt)
            assert r.get("disclaimer"), f"Empty disclaimer for ({lang}, {tgt})"


def test_fit_reason_nonempty_for_all_combinations():
    for lang in LANGUAGES:
        for tgt in TARGETS:
            r = processor_fit(lang, tgt)
            assert r.get("reason"), f"Empty reason for ({lang}, {tgt})"


def test_fit_notes_is_list():
    for lang in LANGUAGES:
        for tgt in TARGETS:
            r = processor_fit(lang, tgt)
            assert isinstance(r["notes"], list), f"notes is not a list for ({lang}, {tgt})"


# ---------------------------------------------------------------------------
# processor_fit() — C fits all targets
# ---------------------------------------------------------------------------

def test_c_strong_fit_generic_x86_64():
    r = processor_fit("C", "Generic x86-64")
    assert r["fit"] == "STRONG"


def test_c_strong_fit_intel_x86_64():
    assert processor_fit("C", "Intel x86-64")["fit"] == "STRONG"


def test_c_strong_fit_amd_x86_64():
    assert processor_fit("C", "AMD x86-64")["fit"] == "STRONG"


def test_c_strong_fit_arm64():
    assert processor_fit("C", "ARM64")["fit"] == "STRONG"


def test_c_strong_fit_riscv64():
    assert processor_fit("C", "RISC-V 64")["fit"] == "STRONG"


def test_c_strong_fit_esp32():
    assert processor_fit("C", "ESP32-class MCU")["fit"] == "STRONG"


# ---------------------------------------------------------------------------
# processor_fit() — Python unsupported on ESP32
# ---------------------------------------------------------------------------

def test_python_unsupported_on_esp32():
    r = processor_fit("Python", "ESP32-class MCU")
    assert r["fit"] == "UNSUPPORTED"


def test_python_strong_on_x86_64():
    r = processor_fit("Python", "Generic x86-64")
    assert r["fit"] == "STRONG"


def test_python_partial_on_riscv64():
    r = processor_fit("Python", "RISC-V 64")
    assert r["fit"] == "PARTIAL"


# ---------------------------------------------------------------------------
# processor_fit() — Java unsupported on ESP32
# ---------------------------------------------------------------------------

def test_java_unsupported_on_esp32():
    r = processor_fit("Java", "ESP32-class MCU")
    assert r["fit"] == "UNSUPPORTED"


def test_java_strong_on_arm64():
    r = processor_fit("Java", "ARM64")
    assert r["fit"] == "STRONG"


def test_java_partial_on_riscv64():
    r = processor_fit("Java", "RISC-V 64")
    assert r["fit"] == "PARTIAL"


# ---------------------------------------------------------------------------
# processor_fit() — Go unsupported on ESP32
# ---------------------------------------------------------------------------

def test_go_unsupported_on_esp32():
    r = processor_fit("Go", "ESP32-class MCU")
    assert r["fit"] == "UNSUPPORTED"


def test_go_strong_on_arm64():
    r = processor_fit("Go", "ARM64")
    assert r["fit"] == "STRONG"


# ---------------------------------------------------------------------------
# processor_fit() — JavaScript / TypeScript unsupported on ESP32
# ---------------------------------------------------------------------------

def test_javascript_unsupported_on_esp32():
    r = processor_fit("JavaScript", "ESP32-class MCU")
    assert r["fit"] == "UNSUPPORTED"


def test_typescript_unsupported_on_esp32():
    r = processor_fit("TypeScript", "ESP32-class MCU")
    assert r["fit"] == "UNSUPPORTED"


# ---------------------------------------------------------------------------
# processor_fit() — C++ partial on ESP32
# ---------------------------------------------------------------------------

def test_cpp_partial_on_esp32():
    r = processor_fit("C++", "ESP32-class MCU")
    assert r["fit"] == "PARTIAL"


def test_cpp_strong_on_x86_64():
    r = processor_fit("C++", "Generic x86-64")
    assert r["fit"] == "STRONG"


# ---------------------------------------------------------------------------
# processor_fit() — Rust
# ---------------------------------------------------------------------------

def test_rust_strong_on_arm64():
    r = processor_fit("Rust", "ARM64")
    assert r["fit"] == "STRONG"


def test_rust_strong_on_riscv64():
    r = processor_fit("Rust", "RISC-V 64")
    assert r["fit"] == "STRONG"


def test_rust_partial_on_esp32():
    r = processor_fit("Rust", "ESP32-class MCU")
    assert r["fit"] == "PARTIAL"


# ---------------------------------------------------------------------------
# processor_fit() — Custom language always UNKNOWN
# ---------------------------------------------------------------------------

def test_custom_language_returns_unknown_fit():
    for tgt in TARGETS:
        r = processor_fit("Custom", tgt)
        assert r["fit"] == "UNKNOWN", f"Expected UNKNOWN for Custom/{tgt}, got {r['fit']}"


# ---------------------------------------------------------------------------
# processor_fit() — Unknown language falls back to Custom
# ---------------------------------------------------------------------------

def test_unknown_language_normalises_to_custom():
    r = processor_fit("COBOL", "Generic x86-64")
    assert r["fit"] == "UNKNOWN"
    assert r["advisory"] is True


# ---------------------------------------------------------------------------
# processor_fit() — Unknown target returns UNKNOWN + advisory
# ---------------------------------------------------------------------------

def test_unknown_target_returns_unknown():
    r = processor_fit("C", "IBM Z16 mainframe")
    assert r["fit"] == "UNKNOWN"
    assert r["advisory"] is True


def test_none_target_returns_unknown():
    r = processor_fit("C", None)
    assert r["fit"] == "UNKNOWN"
    assert r["advisory"] is True


def test_none_language_normalises_gracefully():
    r = processor_fit(None, "Generic x86-64")
    assert r["advisory"] is True
    assert r["fit"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# processor_fit() — Target aliases
# ---------------------------------------------------------------------------

def test_target_alias_arm():
    r = processor_fit("C", "arm64")
    assert r["target"] == "ARM64"
    assert r["fit"] == "STRONG"


def test_target_alias_x86_64():
    r = processor_fit("C", "x86-64")
    assert r["target"] == "Generic x86-64"
    assert r["fit"] == "STRONG"


def test_target_alias_riscv():
    r = processor_fit("C", "riscv64")
    assert r["target"] == "RISC-V 64"
    assert r["fit"] == "STRONG"


def test_target_alias_esp32():
    r = processor_fit("C", "esp32")
    assert r["target"] == "ESP32-class MCU"
    assert r["fit"] == "STRONG"


# ---------------------------------------------------------------------------
# processor_fit() — Case-insensitive language
# ---------------------------------------------------------------------------

def test_language_case_insensitive_python():
    r = processor_fit("python", "Generic x86-64")
    assert r["fit"] == "STRONG"


def test_language_case_insensitive_rust():
    r = processor_fit("RUST", "ARM64")
    assert r["fit"] == "STRONG"


# ---------------------------------------------------------------------------
# processor_fit_all_targets() — returns all 6 targets
# ---------------------------------------------------------------------------

def test_all_targets_returns_six_results():
    results = processor_fit_all_targets("C")
    assert len(results) == 6


def test_all_targets_each_has_required_fields():
    for result in processor_fit_all_targets("Python"):
        _assert_fit_fields(result)


def test_all_targets_advisory_all_true():
    for result in processor_fit_all_targets("Rust"):
        assert result["advisory"] is True


# ---------------------------------------------------------------------------
# analyse_source() — required fields
# ---------------------------------------------------------------------------

def test_analyse_source_returns_required_fields():
    result = analyse_source("main.c", "strcpy(buf, input);", "Generic x86-64")
    _assert_analyse_fields(result)


def test_analyse_source_advisory_always_true():
    result = analyse_source("main.c", "for(i=0;i<n;i++){for(j=0;j<m;j++){}}", "Generic x86-64")
    assert result["advisory"] is True
    for obs in result["observations"]:
        assert obs.get("advisory") is True
    for rec in result["recommendations"]:
        assert rec.get("advisory") is True


def test_analyse_source_analysis_type_always_static():
    result = analyse_source("main.py", "import threading", "Generic x86-64")
    assert result["analysis_type"] == "STATIC_ANALYSIS"
    for rec in result["recommendations"]:
        assert rec["analysis_type"] == "STATIC_ANALYSIS"


def test_analyse_source_disclaimer_present():
    result = analyse_source("main.c", "", None)
    assert result.get("disclaimer")


# ---------------------------------------------------------------------------
# analyse_source() — empty and None inputs
# ---------------------------------------------------------------------------

def test_analyse_source_empty_text_returns_zero_observations():
    result = analyse_source("main.c", "", "Generic x86-64")
    assert result["observation_count"] == 0
    assert result["recommendation_count"] == 0


def test_analyse_source_none_text_does_not_crash():
    result = analyse_source("main.c", None, "Generic x86-64")
    assert result["observation_count"] == 0


def test_analyse_source_none_filename_does_not_crash():
    result = analyse_source(None, "", None)
    assert "file" in result


def test_analyse_source_none_target_returns_all_targets():
    result = analyse_source(None, "", None)
    assert result["target"] == "All targets"


# ---------------------------------------------------------------------------
# analyse_source() — CPU intensity signals
# ---------------------------------------------------------------------------

def test_nested_loops_detected():
    src = "for (i=0; i<n; i++) {\n    for (j=0; j<m; j++) {\n    }\n}"
    result = analyse_source("main.c", src, None)
    assert _obs_for_signal(result, "nested_loops"), "Expected nested_loop observation"


def test_while_loop_detected():
    src = "while (x > 0) { x--; }"
    result = analyse_source("main.c", src, None)
    assert _obs_for_signal(result, "while_loop"), "Expected while_loop observation"


# ---------------------------------------------------------------------------
# analyse_source() — Vectorization signals
# ---------------------------------------------------------------------------

def test_numpy_op_detected():
    src = "result = np.dot(a, b)"
    result = analyse_source("model.py", src, "Generic x86-64")
    assert _obs_for_signal(result, "numpy_op"), "Expected numpy_op observation"


def test_simd_intrinsic_detected():
    src = "#include <immintrin.h>\n__m256 v = _mm256_load_ps(ptr);"
    result = analyse_source("simd.c", src, None)
    assert _obs_for_signal(result, "simd_intrinsic") or _obs_for_signal(result, "arch_specific_include"), (
        "Expected SIMD-related observation"
    )


def test_array_arithmetic_detected_on_x86():
    src = "float buffer[256];\nfor(int i=0;i<256;i++) buffer[i] *= 2.0f;"
    result = analyse_source("dsp.c", src, "Generic x86-64")
    assert _obs_for_signal(result, "array_arithmetic_c"), "Expected array_arithmetic_c"


# ---------------------------------------------------------------------------
# analyse_source() — Threading signals
# ---------------------------------------------------------------------------

def test_python_threading_detected():
    src = "import threading\nt = threading.Thread(target=worker)\nt.start()"
    result = analyse_source("server.py", src, "Generic x86-64")
    assert _obs_for_signal(result, "python_threading"), "Expected python_threading"


def test_posix_thread_detected_on_esp32():
    src = "pthread_create(&tid, NULL, worker, arg);"
    result = analyse_source("task.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "posix_thread"), "Expected posix_thread"


def test_posix_thread_not_reported_for_x86():
    # pthreads are fine on x86-64; the pattern is only relevant for ESP32
    src = "pthread_create(&tid, NULL, worker, arg);"
    result = analyse_source("task.c", src, "Generic x86-64")
    assert not _obs_for_signal(result, "posix_thread"), (
        "posix_thread observation should not appear for x86-64 target"
    )


def test_rust_thread_spawn_detected_on_esp32():
    src = "let handle = thread::spawn(|| { worker(); });"
    result = analyse_source("main.rs", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "rust_thread"), "Expected rust_thread"


def test_go_goroutine_detected_on_esp32():
    src = "go handleRequest(conn)"
    result = analyse_source("server.go", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "go_goroutine"), "Expected go_goroutine"


def test_openmp_detected_on_esp32():
    src = "#pragma omp parallel for\nfor (i=0; i<n; i++) {}"
    result = analyse_source("parallel.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "openmp"), "Expected openmp"


# ---------------------------------------------------------------------------
# analyse_source() — Memory signals
# ---------------------------------------------------------------------------

def test_malloc_detected_on_esp32():
    src = "uint8_t *buf = malloc(1024);"
    result = analyse_source("alloc.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "dynamic_alloc_c"), "Expected dynamic_alloc_c"


def test_large_stack_array_detected_on_esp32():
    src = "void process() { int buf[4096]; process_data(buf); }"
    result = analyse_source("proc.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "large_stack_array_c"), "Expected large_stack_array_c"


def test_python_list_comprehension_detected():
    src = "squares = [x*x for x in range(1000000)]"
    result = analyse_source("data.py", src, "Generic x86-64")
    assert _obs_for_signal(result, "python_list_comprehension"), "Expected list_comprehension"


def test_java_gc_pressure_detected():
    src = "List<String> items = new ArrayList<>();\nfor (int i=0; i<n; i++) { items.add(new String(\"item\")); }"
    result = analyse_source("Proc.java", src, "Generic x86-64")
    assert _obs_for_signal(result, "java_gc_pressure"), "Expected java_gc_pressure"


# ---------------------------------------------------------------------------
# analyse_source() — I/O signals
# ---------------------------------------------------------------------------

def test_file_io_c_detected():
    src = 'FILE *fp = fopen("data.bin", "rb");\nfread(buf, 1, size, fp);\nfclose(fp);'
    result = analyse_source("io.c", src, None)
    assert _obs_for_signal(result, "file_io_c"), "Expected file_io_c"


def test_python_open_detected():
    src = "with open('data.csv', 'r') as f:\n    content = f.read()"
    result = analyse_source("reader.py", src, None)
    assert _obs_for_signal(result, "python_open"), "Expected python_open"


def test_blocking_sleep_detected_on_esp32():
    src = "vTaskDelay(pdMS_TO_TICKS(100));"
    result = analyse_source("main.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "blocking_sleep"), "Expected blocking_sleep"


# ---------------------------------------------------------------------------
# analyse_source() — Portability signals
# ---------------------------------------------------------------------------

def test_x86_inline_asm_detected_on_arm64():
    src = "__asm__ volatile (\"cpuid\" : : : \"eax\");"
    result = analyse_source("asm.c", src, "ARM64")
    assert _obs_for_signal(result, "x86_asm_inline"), "Expected x86_asm_inline"


def test_x86_intrinsic_header_detected_on_arm64():
    src = "#include <immintrin.h>"
    result = analyse_source("simd.c", src, "ARM64")
    assert _obs_for_signal(result, "arch_specific_include"), "Expected arch_specific_include"


def test_arm_neon_header_detected_on_x86():
    src = "#include <arm_neon.h>"
    result = analyse_source("neon.c", src, "Generic x86-64")
    assert _obs_for_signal(result, "arm_neon_include"), "Expected arm_neon_include"


def test_windows_api_detected_on_esp32():
    src = "HANDLE hThread = CreateThread(NULL, 0, worker, NULL, 0, &tid);"
    result = analyse_source("win.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "windows_api"), "Expected windows_api"


# ---------------------------------------------------------------------------
# analyse_source() — Compiler / toolchain signals
# ---------------------------------------------------------------------------

def test_pragma_once_detected_on_riscv():
    src = "#pragma once\n#define MY_HEADER_H"
    result = analyse_source("header.h", src, "RISC-V 64")
    assert _obs_for_signal(result, "pragma_once"), "Expected pragma_once"


def test_gcc_attribute_detected():
    src = "void __attribute__((packed)) my_struct_func(void);"
    result = analyse_source("packed.c", src, None)
    assert _obs_for_signal(result, "attribute_gcc"), "Expected attribute_gcc"


# ---------------------------------------------------------------------------
# analyse_source() — Embedded signals
# ---------------------------------------------------------------------------

def test_float_detected_on_esp32():
    src = "float temperature = read_sensor();"
    result = analyse_source("sensor.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "floating_point"), "Expected floating_point"


def test_printf_detected_on_esp32():
    src = 'printf("Value: %d\\n", val);'
    result = analyse_source("main.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "printf_usage"), "Expected printf_usage"


def test_esp_heap_check_detected_on_esp32():
    src = "size_t free = esp_get_free_heap_size();"
    result = analyse_source("diag.c", src, "ESP32-class MCU")
    assert _obs_for_signal(result, "heap_check"), "Expected heap_check"


# ---------------------------------------------------------------------------
# analyse_source() — Recommendation fields
# ---------------------------------------------------------------------------

def test_recommendation_has_all_required_fields():
    src = "pthread_create(&tid, NULL, worker, arg);"
    result = analyse_source("task.c", src, "ESP32-class MCU")
    for rec in result["recommendations"]:
        _assert_recommendation_fields(rec)


def test_recommendation_expected_benefit_is_hypothesis():
    """expected_benefit must contain the word HYPOTHESIS to prevent false performance claims."""
    src = "for (i=0; i<n; i++) {\n    for (j=0; j<m; j++) {\n    }\n}"
    result = analyse_source("main.c", src, "Generic x86-64")
    for rec in result["recommendations"]:
        assert "HYPOTHESIS" in rec["expected_benefit"], (
            f"expected_benefit must be labelled as a HYPOTHESIS: {rec['expected_benefit']}"
        )


def test_recommendation_disclaimer_present():
    src = "pthread_create(&tid, NULL, worker, arg);"
    result = analyse_source("task.c", src, "ESP32-class MCU")
    for rec in result["recommendations"]:
        assert rec.get("disclaimer"), "Recommendation missing disclaimer"


# ---------------------------------------------------------------------------
# analyse_source() — Target filtering
# ---------------------------------------------------------------------------

def test_target_filter_restricts_recommendations():
    """Recommendations for ESP32-only signals must not appear when target is Generic x86-64."""
    src = "pthread_create(&tid, NULL, worker, arg);"
    result_esp32 = analyse_source("task.c", src, "ESP32-class MCU")
    result_x86 = analyse_source("task.c", src, "Generic x86-64")
    assert result_esp32["recommendation_count"] > 0, "Expected recommendations for ESP32"
    assert result_x86["recommendation_count"] == 0, (
        f"Expected 0 recommendations for x86-64, got {result_x86['recommendation_count']}"
    )


def test_none_target_collects_all_applicable_recommendations():
    src = "pthread_create(&tid, NULL, worker, arg);"
    result = analyse_source("task.c", src, None)
    # pthreads signal targets ["ESP32-class MCU"] so at most 1 target recommendation
    assert result["recommendation_count"] >= 1


# ---------------------------------------------------------------------------
# analyse_source() — counts are consistent
# ---------------------------------------------------------------------------

def test_observation_count_matches_list_length():
    src = "for (i=0;i<n;i++){for(j=0;j<m;j++){}} while(x){}"
    result = analyse_source("main.c", src, None)
    assert result["observation_count"] == len(result["observations"])


def test_recommendation_count_matches_list_length():
    src = "for (i=0;i<n;i++){for(j=0;j<m;j++){}} while(x){}"
    result = analyse_source("main.c", src, None)
    assert result["recommendation_count"] == len(result["recommendations"])


# ---------------------------------------------------------------------------
# analyse_source() — sample project files
# ---------------------------------------------------------------------------

_SAMPLE_PROJECTS = Path(__file__).resolve().parents[1] / "sample_projects"


def test_sample_project_py_returns_valid_result():
    text = (_SAMPLE_PROJECTS / "sample_project.py").read_text(encoding="utf-8")
    result = analyse_source("sample_project.py", text, None)
    _assert_analyse_fields(result)
    assert result["advisory"] is True


def test_security_demo_c_returns_valid_result():
    text = (_SAMPLE_PROJECTS / "security_demo.c").read_text(encoding="utf-8")
    result = analyse_source("security_demo.c", text, "ESP32-class MCU")
    _assert_analyse_fields(result)
    assert result["advisory"] is True


def test_buggy_memory_c_malloc_detected_on_esp32():
    text = (_SAMPLE_PROJECTS / "buggy_memory.c").read_text(encoding="utf-8")
    result = analyse_source("buggy_memory.c", text, "ESP32-class MCU")
    assert _obs_for_signal(result, "dynamic_alloc_c"), (
        "Expected malloc detection in buggy_memory.c for ESP32 target"
    )
