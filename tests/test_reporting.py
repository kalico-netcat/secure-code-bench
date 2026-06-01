import json
from pathlib import Path
from typing import Optional

from secure_code_bench.reporting import build_report, format_report, load_jsonl_records


def test_build_report_groups_key_benchmark_dimensions() -> None:
    records = [
        _record(
            model="model-a",
            suite="KEV code samples (accepted, may-be-safe)",
            passed=True,
            rubric_quality="strong",
            is_vulnerable=True,
            guardrails=1,
            dimensions={
                "vulnerability_type": 1,
                "impact": 1,
                "code_evidence": 1,
                "fix_direction": 1,
            },
        ),
        _record(
            model="model-a",
            suite="KEV code samples (accepted, may-be-safe)",
            passed=False,
            rubric_quality="control",
            is_vulnerable=False,
            guardrails=0,
            acceptance_reason="Missing required dimension(s): code_evidence",
            dimensions={
                "vulnerability_type": 1,
                "impact": 0.5,
                "code_evidence": 0,
                "fix_direction": 0.5,
            },
        ),
        _record(
            model="model-b",
            suite="KEV code samples (accepted, known-vulnerable)",
            passed=False,
            status="judge_error",
            rubric_quality="weak",
            is_vulnerable=True,
            guardrails=2,
        ),
    ]

    report = build_report(records)

    assert report["overall"]["records"] == 3
    assert report["overall"]["completed"] == 2
    assert report["overall"]["passed"] == 1
    assert report["overall"]["errors"] == 1
    assert report["overall"]["guardrail_count"] == 3
    assert report["overall"]["failure_buckets"] == {
        "judge_error": 1,
        "missing_code_evidence": 1,
        "passed": 1,
    }
    assert report["overall"]["dimension_histograms"]["code_evidence"]["counts"] == {
        "0.0": 1,
        "0.5": 0,
        "1.0": 1,
    }
    assert report["overall"]["dimension_histograms"]["impact"]["average"] == 0.75
    assert report["by_model"]["model-a"]["completed"] == 2
    assert report["by_model"]["model-b"]["status_counts"] == {"judge_error": 1}
    assert report["by_prompt_assumption"]["may-be-safe"]["records"] == 2
    assert report["by_prompt_assumption"]["known-vulnerable"]["records"] == 1
    assert report["by_prompt_assumption_model"]["may-be-safe"]["model-a"]["records"] == 2
    assert report["by_prompt_assumption_model"]["known-vulnerable"]["model-b"]["records"] == 1
    assert report["by_rubric_quality"]["strong"]["passed"] == 1
    assert report["by_rubric_quality"]["control"]["failed"] == 1
    assert report["by_vulnerability_label"]["vulnerable"]["records"] == 2
    assert report["by_vulnerability_label"]["control"]["records"] == 1
    assert report["by_status"]["judge_error"]["errors"] == 1


def test_build_report_failure_buckets_prioritize_guardrails_and_errors() -> None:
    records = [
        _record(
            model="model-a",
            suite="suite",
            passed=False,
            guardrails=1,
            acceptance_reason="Missing required dimension(s): vulnerability_type",
        ),
        _record(model="model-a", suite="suite", passed=False, status="model_error"),
        _record(
            model="model-a",
            suite="suite",
            passed=False,
            acceptance_reason="Overall score 0.50 is below required 0.75.",
        ),
        _record(model="model-a", suite="suite", passed=False),
    ]

    report = build_report(records)

    assert report["overall"]["failure_buckets"] == {
        "failed_other": 1,
        "model_error": 1,
        "overall_too_low": 1,
        "polarity_conflict": 1,
    }


def test_load_jsonl_records_reads_multiple_files(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_text(json.dumps({"suite": "a", "model": "m1"}) + "\n", encoding="utf-8")
    second.write_text(json.dumps({"suite": "b", "model": "m2"}) + "\n", encoding="utf-8")

    records = load_jsonl_records([first, second])

    assert [record["suite"] for record in records] == ["a", "b"]


def test_format_report_includes_requested_sections() -> None:
    report = build_report([_record(model="model-a", suite="suite", passed=True)])

    text = format_report(report)

    assert "By model" in text
    assert "By suite" in text
    assert "By prompt assumption" in text
    assert "By rubric quality" in text
    assert "By vulnerable/control label" in text
    assert "By status" in text
    assert "guardrails=0" in text
    assert "failures[passed=1]" in text
    assert "dims[vulnerability_type:avg=n/a,n=0" in text


def _record(
    model: str,
    suite: str,
    passed: bool,
    status: str = "completed",
    rubric_quality: Optional[str] = None,
    is_vulnerable: Optional[bool] = None,
    guardrails: int = 0,
    acceptance_reason: str = "",
    dimensions: Optional[dict] = None,
) -> dict:
    metadata = {}
    if rubric_quality is not None:
        metadata["rubric_quality"] = rubric_quality
    if is_vulnerable is not None:
        metadata["expected_response"] = {"is_vulnerable": is_vulnerable}
    return {
        "suite": suite,
        "case_id": "case",
        "model": model,
        "status": status,
        "prompt": "prompt",
        "response": "response",
        "scores": [
            {
                "name": "llm_judge",
                "passed": passed,
                "details": {
                    "guardrails": [{} for _ in range(guardrails)],
                    **({"dimensions": dimensions} if dimensions is not None else {}),
                },
            }
        ],
        "passed": passed,
        "acceptance": {
            "mode": "judge",
            "passed": passed,
            "reason": acceptance_reason,
        },
        "metadata": metadata,
    }
