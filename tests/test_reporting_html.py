from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_bench.reporting import build_report
from secure_code_bench.reporting_html import HtmlReportError, report_chart_data, write_html_report


def test_report_chart_data_prepares_plotly_series() -> None:
    report = build_report(
        [
            _record(
                model="model-a",
                suite="KEV code samples (accepted, may-be-safe)",
                passed=True,
                rubric_quality="strong",
                dimensions={
                    "vulnerability_type": 1,
                    "impact": 1,
                    "code_evidence": 1,
                    "fix_direction": 0.5,
                },
            ),
            _record(
                model="model-b",
                suite="KEV code samples (accepted, may-be-safe)",
                passed=False,
                rubric_quality="weak",
                guardrails=[
                    {"expected": "vulnerability", "observed": "no_finding"},
                    {"expected": "no_vulnerability", "observed": "asserted_vulnerability"},
                ],
                dimensions={
                    "vulnerability_type": 0,
                    "impact": 0.5,
                    "code_evidence": 0,
                    "fix_direction": 0,
                },
            ),
            _record(
                model="model-a",
                suite="KEV code samples (accepted, known-vulnerable)",
                passed=False,
                rubric_quality="weak",
                dimensions={
                    "vulnerability_type": 0.5,
                    "impact": 0.5,
                    "code_evidence": 0,
                    "fix_direction": 0,
                },
            ),
            _record(
                model="model-b",
                suite="KEV code samples (accepted, known-vulnerable)",
                passed=True,
                rubric_quality="weak",
                dimensions={
                    "vulnerability_type": 1,
                    "impact": 1,
                    "code_evidence": 1,
                    "fix_direction": 1,
                },
            ),
        ]
    )

    data = report_chart_data(report)

    assert data["pass_rate_by_model"] == [
        {"model": "model-a", "pass_rate": 50.0, "completed": 2, "records": 2},
        {"model": "model-b", "pass_rate": 50.0, "completed": 2, "records": 2},
    ]
    assert data["pass_rate_by_prompt_assumption_model"] == {
        "may-be-safe": [
            {"model": "model-a", "pass_rate": 100.0, "completed": 1, "records": 1},
            {"model": "model-b", "pass_rate": 0.0, "completed": 1, "records": 1},
        ],
        "known-vulnerable": [
            {"model": "model-a", "pass_rate": 0.0, "completed": 1, "records": 1},
            {"model": "model-b", "pass_rate": 100.0, "completed": 1, "records": 1},
        ],
    }
    assert data["failure_buckets_by_model"]["model-b"] == {
        "passed": 1,
        "polarity_conflict": 1,
    }
    assert data["dimension_averages_by_model"]["model-a"]["fix_direction"] == 0.25
    assert data["dimension_histograms"]["vulnerability_type"] == {
        "0.0": 1,
        "0.5": 1,
        "1.0": 2,
    }
    assert data["guardrails_by_model"] == [
        {
            "model": "model-a",
            "missed_vulnerability": 0,
            "hallucinated_vulnerability": 0,
            "unknown": 0,
        },
        {
            "model": "model-b",
            "missed_vulnerability": 1,
            "hallucinated_vulnerability": 1,
            "unknown": 0,
        },
    ]
    assert "strong_vs_all_pass_rate" not in data


def test_write_html_report_explains_missing_plotly(monkeypatch, tmp_path: Path) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("plotly"):
            raise ImportError("missing plotly")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(HtmlReportError, match=r'python -m pip install -e "\.\[report\]"'):
        write_html_report(build_report([]), tmp_path / "report.html")


def test_prompt_assumption_model_series_keeps_missing_models_visible() -> None:
    report = build_report(
        [
            _record(
                model="model-a",
                suite="KEV code samples (accepted, may-be-safe)",
                passed=True,
                rubric_quality="strong",
                dimensions={
                    "vulnerability_type": 1,
                    "impact": 1,
                    "code_evidence": 1,
                    "fix_direction": 1,
                },
            ),
            _record(
                model="model-b",
                suite="KEV code samples (accepted, known-vulnerable)",
                passed=False,
                rubric_quality="strong",
                dimensions={
                    "vulnerability_type": 0,
                    "impact": 0,
                    "code_evidence": 0,
                    "fix_direction": 0,
                },
            ),
        ]
    )

    data = report_chart_data(report)

    assert data["pass_rate_by_prompt_assumption_model"] == {
        "may-be-safe": [
            {"model": "model-a", "pass_rate": 100.0, "completed": 1, "records": 1},
            {"model": "model-b", "pass_rate": None, "completed": 0, "records": 0},
        ],
        "known-vulnerable": [
            {"model": "model-a", "pass_rate": None, "completed": 0, "records": 0},
            {"model": "model-b", "pass_rate": 0.0, "completed": 1, "records": 1},
        ],
    }


def _record(
    model: str,
    suite: str,
    passed: bool,
    rubric_quality: str,
    dimensions: dict,
    guardrails: int | list[dict[str, str]] = 0,
) -> dict:
    guardrail_details = [{} for _ in range(guardrails)] if isinstance(guardrails, int) else guardrails
    return {
        "suite": suite,
        "case_id": "case",
        "model": model,
        "status": "completed",
        "prompt": "prompt",
        "response": "response",
        "scores": [
            {
                "name": "llm_judge",
                "passed": passed,
                "details": {
                    "dimensions": dimensions,
                    "guardrails": guardrail_details,
                },
            }
        ],
        "passed": passed,
        "metadata": {"rubric_quality": rubric_quality},
    }
