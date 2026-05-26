from pathlib import Path

from secure_code_bench.suites import load_suite
from secure_code_bench.validation import validate_suite, validate_suite_set


def test_validate_suite_accepts_clean_suite(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("print('ok')\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: clean
cases:
  - id: case-1
    prompt: "Review this:\\n{file:sample.py}"
    code_files:
      - sample.py
    scorers:
      - type: regex
        pattern: ok
""",
        encoding="utf-8",
    )

    findings = validate_suite(load_suite(suite_path))

    assert findings == []


def test_validate_suite_reports_pre_run_quality_findings(tmp_path: Path) -> None:
    (tmp_path / "empty.py").write_text("\n", encoding="utf-8")
    (tmp_path / "leaky.py").write_text("# CVE-2020-0002\nsafe()\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: risky
cases:
  - id: duplicate
    prompt: "Review CVE-2020-0001 from https://github.com/example/repo:\\n{file:missing.py}"
    code_files:
      - missing.py
    scorers:
      - type: regex
        pattern: "["
    metadata:
      rubric_quality: weak
  - id: duplicate
    prompt: "{file:empty.py}"
    code_files:
      - empty.py
    scorers:
      - type: contains
  - id: rendered-leak
    prompt: "{file:leaky.py}"
    code_files:
      - leaky.py
    scorers: []
""",
        encoding="utf-8",
    )

    findings = validate_suite(load_suite(suite_path))
    codes = {finding.code for finding in findings}

    assert "duplicate_case_id" in codes
    assert "missing_code_file" in codes
    assert "prompt_render_error" in codes
    assert "invalid_regex_scorer" in codes
    assert "invalid_contains_scorer" in codes
    assert "weak_rubric" in codes
    assert "prompt_leakage" in codes
    assert "empty_code_file" in codes


def test_validate_suite_set_reports_paired_kev_mismatch(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("b()\n", encoding="utf-8")
    may_be_safe_path = tmp_path / "kev-may-be-safe.yml"
    known_vulnerable_path = tmp_path / "kev-known-vulnerable.yml"
    may_be_safe_path.write_text(
        """
name: KEV code samples (accepted, may-be-safe)
cases:
  - id: kev-sample-0001
    prompt: "{file:a.py}"
    code_files:
      - a.py
    scorers: []
""",
        encoding="utf-8",
    )
    known_vulnerable_path.write_text(
        """
name: KEV code samples (accepted, known-vulnerable)
cases:
  - id: kev-sample-0001
    prompt: "{file:b.py}"
    code_files:
      - b.py
    scorers: []
""",
        encoding="utf-8",
    )

    findings = validate_suite_set([load_suite(may_be_safe_path), load_suite(known_vulnerable_path)])

    assert any(finding.code == "paired_suite_mismatch" for finding in findings)
