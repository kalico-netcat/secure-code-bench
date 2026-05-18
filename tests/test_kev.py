import json
from pathlib import Path
from typing import Any, Optional

import yaml

from secure_code_bench.kev import build_kev_suite, discover_kev_samples, write_kev_suite
from secure_code_bench.prompts import render_prompt
from secure_code_bench.scorers import score_response
from secure_code_bench.suites import load_suite


def test_discover_kev_samples_filters_to_accepted_by_default(tmp_path: Path) -> None:
    accepted = _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="accepted-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
    )
    _sample(
        tmp_path,
        cve_id="CVE-2020-0002",
        sample_id="needs-review-sample",
        status="needs_review",
        vulnerable_name="vulnerable.py",
    )

    samples = discover_kev_samples(tmp_path)

    assert len(samples) == 1
    assert samples[0].root == accepted
    assert samples[0].cve_id == "CVE-2020-0001"


def test_build_kev_suite_generates_valid_cases_and_scorers(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-11023",
        sample_id="jquery-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
        extraction_notes="The vulnerable HTML prefilter can allow cross-site scripting.",
        evidence="The fix removes the regex transformation and keeps htmlPrefilter safe.",
    )

    suite = build_kev_suite(tmp_path)

    assert suite.name == "KEV code samples (accepted, may-be-safe)"
    assert suite.cases[0].id == "kev-sample-0001"
    assert suite.cases[0].code_files[0].is_absolute()
    assert any(scorer.type == "regex" for scorer in suite.cases[0].scorers)
    assert suite.cases[0].acceptance is not None
    assert suite.cases[0].acceptance.judge_policy == "balanced_judge"
    assert suite.cases[0].acceptance.required_dimensions == ["vulnerability_type", "code_evidence"]
    assert suite.cases[0].acceptance.core_dimensions == ["vulnerability_type"]
    assert suite.cases[0].acceptance.allow_partial_credit_dimensions == ["code_evidence"]
    assert suite.cases[0].acceptance.min_core_dimension_score == 0.5
    assert suite.cases[0].rubric is not None
    assert suite.cases[0].rubric.vulnerability_type == "cross-site scripting"
    assert "script injection" in (suite.cases[0].rubric.notes or "")
    assert suite.cases[0].metadata["rubric_quality"] == "strong"


def test_build_kev_suite_marks_positive_samples_with_generic_rubrics_weak(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="weak-positive",
        status="accepted",
        vulnerable_name="vulnerable.rb",
        extraction_notes="",
        evidence="",
    )

    suite = build_kev_suite(tmp_path)

    assert suite.cases[0].metadata["rubric_quality"] == "weak"
    assert suite.cases[0].rubric is not None
    assert "Rubric quality: weak" in (suite.cases[0].rubric.notes or "")


def test_build_kev_suite_preserves_expected_response_metadata(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="expected-positive",
        status="accepted",
        vulnerable_name="vulnerable.java",
        expected_responses={
            "vulnerable": {
                "code_evidence": "The sink is `Class.forName(className)`.",
                "expected_behavior": "Untrusted class names can trigger deserialization code execution.",
                "file": "vulnerable.java",
                "is_vulnerable": True,
                "label": "vulnerable",
                "vulnerability_type": "Deserialization of Untrusted Data",
            }
        },
    )

    suite = build_kev_suite(tmp_path)

    expected = suite.cases[0].metadata["expected_response"]
    assert expected["is_vulnerable"] is True
    assert expected["vulnerability_type"] == "Deserialization of Untrusted Data"
    assert expected["code_evidence"] == "The sink is `Class.forName(className)`."
    assert suite.cases[0].rubric is not None
    assert suite.cases[0].rubric.vulnerability_type == "Deserialization of Untrusted Data"
    assert suite.cases[0].rubric.impact == "Untrusted class names can trigger deserialization code execution."
    assert suite.cases[0].rubric.code_evidence == "The sink is `Class.forName(className)`."
    assert suite.cases[0].metadata["rubric_quality"] == "strong"


def test_build_kev_suite_uses_expected_response_for_negative_control_rubric(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="expected-negative",
        status="accepted",
        vulnerable_name="vulnerable.c",
        is_vulnerable=False,
        expected_responses={
            "vulnerable": {
                "code_evidence": "The direct cumulative bound check prevents unsigned underflow.",
                "expected_behavior": "Derived from the fixed snippet; should be judged non-vulnerable.",
                "file": "vulnerable.c",
                "is_vulnerable": False,
                "label": "non_vulnerable",
                "vulnerability_type": "Heap-Based Buffer Overflow Vulnerability",
            }
        },
    )

    suite = build_kev_suite(tmp_path)

    assert suite.cases[0].rubric is not None
    assert suite.cases[0].rubric.vulnerability_type == "no concrete vulnerability"
    assert suite.cases[0].rubric.code_evidence == "The direct cumulative bound check prevents unsigned underflow."
    assert "should be judged non-vulnerable" in (suite.cases[0].rubric.notes or "")


def test_build_kev_suite_uses_vulnerable_slot_but_label_may_be_safe(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="vulnerable-item",
        status="accepted",
        vulnerable_name="vulnerable.c",
        is_vulnerable=True,
        item_kind="vulnerable",
    )
    _sample(
        tmp_path,
        cve_id="CVE-2020-0002",
        sample_id="safe-item",
        status="accepted",
        vulnerable_name="vulnerable.c",
        is_vulnerable=False,
        item_kind="vulnerable",
    )
    _sample(
        tmp_path,
        cve_id="CVE-2020-0003",
        sample_id="fixed-reference",
        status="accepted",
        vulnerable_name="fixed.c",
        is_vulnerable=False,
        item_kind="fixed",
    )

    suite = build_kev_suite(tmp_path)

    assert len(suite.cases) == 2
    assert [case.code_files[0].name for case in suite.cases] == ["vulnerable.c", "vulnerable.c"]
    assert suite.cases[1].rubric is not None
    assert suite.cases[1].rubric.vulnerability_type == "no concrete vulnerability"
    assert "not vulnerab" in suite.cases[1].scorers[0].pattern


def test_build_kev_suite_skips_empty_vulnerable_files(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="empty-item",
        status="accepted",
        vulnerable_name="vulnerable.java",
        vulnerable_code="\n",
    )
    _sample(
        tmp_path,
        cve_id="CVE-2020-0002",
        sample_id="nonempty-item",
        status="accepted",
        vulnerable_name="vulnerable.java",
        vulnerable_code="dangerous();\n",
    )

    suite = build_kev_suite(tmp_path)

    assert len(suite.cases) == 1
    assert "nonempty-item" in str(suite.cases[0].code_files[0])


def test_build_kev_suite_can_randomize_limited_selection_with_seed(tmp_path: Path) -> None:
    for index in range(10):
        _sample(
            tmp_path,
            cve_id=f"CVE-2020-{index:04d}",
            sample_id=f"sample-{index}",
            status="accepted",
            vulnerable_name="vulnerable.py",
            vulnerable_code=f"dangerous_{index}();\n",
        )

    first = build_kev_suite(tmp_path, limit=3, randomize=True, seed=7)
    second = build_kev_suite(tmp_path, limit=3, randomize=True, seed=7)
    ordered = build_kev_suite(tmp_path, limit=3)

    first_paths = [case.code_files[0] for case in first.cases]
    assert first_paths == [case.code_files[0] for case in second.cases]
    assert first_paths != [case.code_files[0] for case in ordered.cases]


def test_kev_prompt_assumption_controls_model_facing_prior(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-11023",
        sample_id="jquery-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
    )

    may_be_safe = build_kev_suite(tmp_path, prompt_assumption="may-be-safe")
    known_vulnerable = build_kev_suite(tmp_path, prompt_assumption="known-vulnerable")

    assert "It is possible there is no vulnerability" in may_be_safe.cases[0].prompt
    assert "say None for the vulnerability" in may_be_safe.cases[0].prompt
    assert "known to contain a security vulnerability" in known_vulnerable.cases[0].prompt
    assert "It is possible there is no vulnerability" not in known_vulnerable.cases[0].prompt


def test_known_vulnerable_suite_keeps_negative_controls(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="positive",
        status="accepted",
        vulnerable_name="vulnerable.c",
        is_vulnerable=True,
    )
    _sample(
        tmp_path,
        cve_id="CVE-2020-0002",
        sample_id="negative-control",
        status="accepted",
        vulnerable_name="vulnerable.c",
        is_vulnerable=False,
    )

    suite = build_kev_suite(tmp_path, prompt_assumption="known-vulnerable")

    assert len(suite.cases) == 2
    assert suite.cases[1].rubric is not None
    assert suite.cases[1].rubric.vulnerability_type == "no concrete vulnerability"
    assert "known to contain a security vulnerability" in suite.cases[1].prompt


def test_write_kev_suite_yaml_loads_and_renders_absolute_code_file(tmp_path: Path) -> None:
    sample_root = _sample(
        tmp_path / "external",
        cve_id="CVE-2021-21315",
        sample_id="docker-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
        vulnerable_code="function run(input) { return exec(input); }\n",
    )
    output = tmp_path / "suite.yml"

    write_kev_suite(sample_root.parents[1], output)
    suite = load_suite(output)
    rendered = render_prompt(suite, suite.cases[0])

    assert "function run(input)" in rendered
    assert "{file:0}" in suite.cases[0].prompt
    assert str(sample_root / "vulnerable.js") not in suite.cases[0].prompt


def test_generated_kev_prompt_omits_source_identifiers(tmp_path: Path) -> None:
    sample_root = _sample(
        tmp_path,
        cve_id="CVE-2020-11023",
        sample_id="jquery-jquery-90fed4b-manipulation",
        status="accepted",
        vulnerable_name="vulnerable.js",
        extraction_notes="The vulnerable HTML prefilter can allow cross-site scripting.",
    )

    suite = build_kev_suite(tmp_path)
    case = suite.cases[0]
    rendered = render_prompt(suite, case)
    prompt_without_placeholder = case.prompt.split("{file:", 1)[0]

    assert case.id == "kev-sample-0001"
    assert "CVE-" not in prompt_without_placeholder
    assert "CVE-" not in case.prompt
    assert "jquery" not in prompt_without_placeholder.lower()
    assert "jquery" not in case.prompt.lower()
    assert "90fed4b" not in prompt_without_placeholder
    assert "90fed4b" not in case.prompt
    assert "src/example.file" not in prompt_without_placeholder
    assert "src/example.file" not in case.prompt
    assert str(sample_root) not in prompt_without_placeholder
    assert str(sample_root) not in case.prompt
    assert "CVE-" not in rendered
    assert "jquery-jquery-90fed4b-manipulation" not in rendered
    assert "src/example.file" not in rendered


def test_generated_kev_regex_scorers_match_representative_response(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2017-9805",
        sample_id="struts-sample",
        status="accepted",
        vulnerable_name="vulnerable.java",
        extraction_notes="The vulnerable code deserializes untrusted XML with XStream.",
    )
    suite = build_kev_suite(tmp_path)

    scores = score_response(
        "This is an unsafe deserialization issue in Java. Restrict allowed types.",
        suite.cases[0].scorers,
    )

    assert any(score.passed for score in scores)


def test_kev_suite_cli_writes_yaml(monkeypatch, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from secure_code_bench.cli import app

    _sample(
        tmp_path,
        cve_id="CVE-2025-49113",
        sample_id="roundcube-sample",
        status="accepted",
        vulnerable_name="vulnerable.php",
    )
    output = tmp_path / "kev.yml"

    result = CliRunner().invoke(
        app,
        [
            "kev-suite",
            "--samples-root",
            str(tmp_path),
            "--output",
            str(output),
            "--prompt-assumption",
            "known-vulnerable",
        ],
    )

    assert result.exit_code == 0
    assert "1 KEV benchmark case" in result.output
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["name"] == "KEV code samples (accepted, known-vulnerable)"
    assert data["cases"][0]["id"] == "kev-sample-0001"
    assert "known to contain a security vulnerability" in data["cases"][0]["prompt"]
    assert data["cases"][0]["acceptance"]["required_dimensions"] == ["vulnerability_type", "code_evidence"]
    assert data["cases"][0]["acceptance"]["judge_policy"] == "balanced_judge"
    assert "rubric" in data["cases"][0]


def test_kev_suite_cli_can_write_both_prompt_assumptions(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from secure_code_bench.cli import app

    _sample(
        tmp_path,
        cve_id="CVE-2025-49113",
        sample_id="roundcube-sample",
        status="accepted",
        vulnerable_name="vulnerable.php",
    )
    output = tmp_path / "kev.yml"

    result = CliRunner().invoke(
        app,
        [
            "kev-suite",
            "--samples-root",
            str(tmp_path),
            "--output",
            str(output),
            "--prompt-assumption",
            "both",
        ],
    )

    may_be_safe = tmp_path / "kev-may-be-safe.yml"
    known_vulnerable = tmp_path / "kev-known-vulnerable.yml"
    assert result.exit_code == 0
    assert may_be_safe.exists()
    assert known_vulnerable.exists()
    assert "Wrote 1 KEV benchmark case(s)" in result.output
    may_be_safe_data = yaml.safe_load(may_be_safe.read_text(encoding="utf-8"))
    known_vulnerable_data = yaml.safe_load(known_vulnerable.read_text(encoding="utf-8"))
    assert "It is possible there is no vulnerability" in may_be_safe_data["cases"][0]["prompt"]
    assert "known to contain a security vulnerability" in known_vulnerable_data["cases"][0]["prompt"]


def test_kev_suite_cli_both_uses_same_random_subset(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from secure_code_bench.cli import app

    for index in range(6):
        _sample(
            tmp_path,
            cve_id=f"CVE-2025-{index:04d}",
            sample_id=f"sample-{index}",
            status="accepted",
            vulnerable_name="vulnerable.php",
            vulnerable_code=f"dangerous_{index}();\n",
        )
    output = tmp_path / "kev.yml"

    result = CliRunner().invoke(
        app,
        [
            "kev-suite",
            "--samples-root",
            str(tmp_path),
            "--output",
            str(output),
            "--prompt-assumption",
            "both",
            "--limit",
            "3",
        ],
    )

    may_be_safe_data = yaml.safe_load((tmp_path / "kev-may-be-safe.yml").read_text(encoding="utf-8"))
    known_vulnerable_data = yaml.safe_load((tmp_path / "kev-known-vulnerable.yml").read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert len(may_be_safe_data["cases"]) == 3
    assert [case["code_files"] for case in may_be_safe_data["cases"]] == [
        case["code_files"] for case in known_vulnerable_data["cases"]
    ]


def test_kev_suite_cli_can_use_ordered_selection(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from secure_code_bench.cli import app

    for index in range(4):
        _sample(
            tmp_path,
            cve_id=f"CVE-2025-{index:04d}",
            sample_id=f"sample-{index}",
            status="accepted",
            vulnerable_name="vulnerable.php",
            vulnerable_code=f"dangerous_{index}();\n",
        )
    output = tmp_path / "kev.yml"

    result = CliRunner().invoke(
        app,
        [
            "kev-suite",
            "--samples-root",
            str(tmp_path),
            "--output",
            str(output),
            "--limit",
            "2",
            "--ordered",
        ],
    )

    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert [case["code_files"][0] for case in data["cases"]] == [
        str(tmp_path / "CVE-2025-0000" / "sample-0" / "vulnerable.php"),
        str(tmp_path / "CVE-2025-0001" / "sample-1" / "vulnerable.php"),
    ]


def _sample(
    root: Path,
    *,
    cve_id: str,
    sample_id: str,
    status: str,
    vulnerable_name: str,
    vulnerable_code: str = "dangerous();\n",
    extraction_notes: str = "This vulnerable code needs input validation.",
    evidence: str = "The safer fix validates and sanitizes input.",
    is_vulnerable: bool = True,
    item_kind: str = "vulnerable",
    expected_responses: Optional[dict[str, Any]] = None,
) -> Path:
    sample_root = root / cve_id / sample_id
    sample_root.mkdir(parents=True)
    metadata = {
        "affected_files": ["src/example.file"],
        "cve_id": cve_id,
        "files": {item_kind: vulnerable_name},
        "is_vulnerable": is_vulnerable,
        "item_kind": item_kind,
        "language": _language(vulnerable_name),
        "provenance": {"extraction_notes": extraction_notes},
        "sample_id": sample_id,
        "sample_kind": "positive" if is_vulnerable else "negative",
        "status": status,
    }
    if expected_responses is not None:
        metadata["expected_responses"] = expected_responses
    (sample_root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (sample_root / "evidence.md").write_text(evidence, encoding="utf-8")
    (sample_root / vulnerable_name).write_text(vulnerable_code, encoding="utf-8")
    if vulnerable_name.startswith("vulnerable."):
        (sample_root / vulnerable_name.replace("vulnerable", "fixed")).write_text(
            "safe();\n",
            encoding="utf-8",
        )
    return sample_root


def _language(filename: str) -> str:
    return {
        ".c": "c",
        ".cpp": "cpp",
        ".js": "javascript",
        ".py": "python",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
    }[Path(filename).suffix]
