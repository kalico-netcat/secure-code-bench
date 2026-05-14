import pytest

from secure_code_bench.judge import _build_judge_prompt, _dimension_score, _parse_judge_json
from secure_code_bench.models import BenchmarkCase, JudgeRubric


def test_parse_judge_json_accepts_plain_json() -> None:
    data = _parse_judge_json(
        '{"vulnerability_type":1,"impact":1,"code_evidence":0,"fix_direction":1,"overall":0.75,"reason":"ok"}'
    )

    assert data["overall"] == 0.75


def test_parse_judge_json_extracts_json_object() -> None:
    data = _parse_judge_json(
        'Here is the grade:\n{"vulnerability_type":1,"impact":0,"code_evidence":1,"fix_direction":1,"overall":0.75,"reason":"ok"}'
    )

    assert data["impact"] == 0


def test_parse_judge_json_rejects_missing_json() -> None:
    with pytest.raises(ValueError):
        _parse_judge_json("not json")


def test_dimension_score_accepts_partial_credit() -> None:
    assert _dimension_score(0) == 0.0
    assert _dimension_score(0.5) == 0.5
    assert _dimension_score(1) == 1.0


def test_judge_prompt_allows_no_vulnerability_rubrics() -> None:
    case = BenchmarkCase(
        id="safe-case",
        prompt="Review this code.",
        rubric=JudgeRubric(
            vulnerability_type="no concrete vulnerability",
            impact="no demonstrated security impact",
            code_evidence="input is validated before use",
            fix_direction="no security fix is required",
        ),
    )

    prompt = _build_judge_prompt(case, "No vulnerability is present.")

    assert "no concrete vulnerability is present" in prompt
    assert "penalize invented" in prompt
    assert "vulnerabilities in that case" in prompt
    assert "For no-vulnerability rubrics" in prompt
    assert "Do not over-penalize partial wording" in prompt


def test_judge_prompt_allows_related_vulnerability_classes() -> None:
    case = BenchmarkCase(
        id="vuln-case",
        prompt="Review this code.",
        rubric=JudgeRubric(
            vulnerability_type="remote code execution",
            impact="attacker input can lead to code execution",
            code_evidence="user input reaches shell execution",
            fix_direction="disable dangerous parsing",
            notes="Related labels such as command injection are acceptable.",
        ),
    )

    prompt = _build_judge_prompt(case, "This is command injection that leads to code execution.")

    assert "Accept semantically related vulnerability classes" in prompt
    assert "less exact label" in prompt
    assert "Award full code_evidence credit" in prompt
