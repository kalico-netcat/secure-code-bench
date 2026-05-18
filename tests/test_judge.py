import pytest

from secure_code_bench.judge import _build_judge_prompt, _dimension_score, _parse_judge_json, score_with_judge
from secure_code_bench.models import BenchmarkCase, JudgeRubric, ModelResponse, RunOptions


class StaticProvider:
    def __init__(self, text: str) -> None:
        self.text = text

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        return ModelResponse(text=self.text)


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


def test_judge_prompt_rejects_polarity_conflicts_and_wrong_evidence() -> None:
    case = BenchmarkCase(
        id="vuln-case",
        prompt="Review this code.",
        rubric=JudgeRubric(
            vulnerability_type="remote code execution",
            impact="attacker can execute code",
            code_evidence="attacker-controlled input reaches eval",
            fix_direction="disable dangerous parsing",
        ),
    )

    prompt = _build_judge_prompt(case, "Vulnerability: None")

    assert "A no-finding answer cannot satisfy a vulnerable rubric" in prompt
    assert "An invented vulnerability cannot" in prompt
    assert "satisfy a no-vulnerability rubric" in prompt
    assert "wrong conclusion" in prompt


def test_judge_prompt_includes_expected_response_metadata() -> None:
    case = BenchmarkCase(
        id="vuln-case",
        prompt="Review this code.",
        rubric=JudgeRubric(
            vulnerability_type="remote code execution",
            impact="attacker can execute code",
            code_evidence="attacker-controlled input reaches eval",
            fix_direction="disable dangerous parsing",
        ),
        metadata={
            "expected_response": {
                "is_vulnerable": True,
                "vulnerability_type": "deserialization",
                "expected_behavior": "Untrusted class names can instantiate dangerous classes.",
                "code_evidence": "Class.forName(className) reaches constructor.newInstance().",
            }
        },
    )

    prompt = _build_judge_prompt(case, "Vulnerability: unsafe reflection")

    assert "Expected response guidance from sample metadata" in prompt
    assert "Expected vulnerable: True" in prompt
    assert "Untrusted class names can instantiate dangerous classes" in prompt
    assert "resolve ambiguous generic rubrics" in prompt


def test_judge_computes_overall_from_dimensions() -> None:
    case = _vulnerable_case()
    score = score_with_judge(
        provider=StaticProvider(
            '{"vulnerability_type":1,"impact":0,"code_evidence":0,'
            '"fix_direction":0,"overall":1.0,"reason":"bad aggregate"}'
        ),
        judge_model="judge",
        case=case,
        response="Vulnerability: Command injection\nImpact: code execution",
        options=RunOptions(),
    )

    assert score.details["overall_raw"] == 1.0
    assert score.details["overall"] == 0.25
    assert score.passed is False


def test_judge_guardrail_rejects_no_finding_for_vulnerable_rubric() -> None:
    score = score_with_judge(
        provider=StaticProvider(
            '{"vulnerability_type":1,"impact":1,"code_evidence":1,'
            '"fix_direction":1,"overall":1.0,"reason":"incorrectly accepted"}'
        ),
        judge_model="judge",
        case=_vulnerable_case(),
        response=(
            "Vulnerability: None\n"
            "Impact: No demonstrated security impact.\n"
            "Evidence in code: input appears validated before use.\n"
            "Fix direction: No security fix required."
        ),
        options=RunOptions(),
    )

    assert score.details["dimensions"]["vulnerability_type"] == 0.0
    assert score.details["dimensions"]["code_evidence"] == 0.0
    assert score.details["guardrails"][0]["observed"] == "no_finding"
    assert score.passed is False


def test_judge_guardrail_rejects_invented_vulnerability_for_safe_rubric() -> None:
    score = score_with_judge(
        provider=StaticProvider(
            '{"vulnerability_type":1,"impact":1,"code_evidence":1,'
            '"fix_direction":1,"overall":1.0,"reason":"incorrectly accepted"}'
        ),
        judge_model="judge",
        case=_safe_case(),
        response=(
            "Vulnerability: SQL injection\n"
            "Impact: attacker can read rows.\n"
            "Evidence in code: query uses a variable.\n"
            "Fix direction: parameterize the query."
        ),
        options=RunOptions(),
    )

    assert score.details["dimensions"]["vulnerability_type"] == 0.0
    assert score.details["dimensions"]["code_evidence"] == 0.0
    assert score.details["guardrails"][0]["observed"] == "asserted_vulnerability"
    assert score.passed is False


def test_judge_guardrail_uses_expected_response_polarity() -> None:
    case = _vulnerable_case().model_copy(
        update={
            "metadata": {
                "expected_response": {
                    "is_vulnerable": False,
                    "expected_behavior": "Fixed code should be judged non-vulnerable.",
                    "code_evidence": "The added chain check prevents stale cross-chain rule matches.",
                }
            }
        }
    )

    score = score_with_judge(
        provider=StaticProvider(
            '{"vulnerability_type":1,"impact":1,"code_evidence":1,'
            '"fix_direction":1,"overall":1.0,"reason":"incorrectly accepted"}'
        ),
        judge_model="judge",
        case=case,
        response=(
            "Vulnerability: NULL pointer dereference\n"
            "Impact: attacker can crash the kernel.\n"
            "Evidence in code: rule is returned without checking NULL.\n"
            "Fix direction: add a NULL check."
        ),
        options=RunOptions(),
    )

    assert score.details["expected_response_used"] is True
    assert score.details["dimensions"]["vulnerability_type"] == 0.0
    assert score.details["dimensions"]["impact"] == 0.0
    assert score.details["dimensions"]["code_evidence"] == 0.0
    assert score.details["guardrails"][0]["expected"] == "no_vulnerability"


def test_judge_guardrail_preserves_related_vulnerability_class() -> None:
    score = score_with_judge(
        provider=StaticProvider(
            '{"vulnerability_type":0.5,"impact":1,"code_evidence":1,'
            '"fix_direction":1,"overall":0.88,"reason":"related class"}'
        ),
        judge_model="judge",
        case=_vulnerable_case(),
        response=(
            "Vulnerability: Command injection leading to RCE\n"
            "Impact: attacker can execute code.\n"
            "Evidence in code: user input reaches eval.\n"
            "Fix direction: remove dangerous parsing."
        ),
        options=RunOptions(),
    )

    assert "guardrails" not in score.details
    assert score.details["dimensions"]["vulnerability_type"] == 0.5
    assert score.details["overall"] == 0.875


def _vulnerable_case() -> BenchmarkCase:
    return BenchmarkCase(
        id="vuln-case",
        prompt="Review this code.",
        rubric=JudgeRubric(
            vulnerability_type="remote code execution",
            impact="attacker can execute code",
            code_evidence="attacker-controlled input reaches eval",
            fix_direction="disable dangerous parsing",
        ),
    )


def _safe_case() -> BenchmarkCase:
    return BenchmarkCase(
        id="safe-case",
        prompt="Review this code.",
        rubric=JudgeRubric(
            vulnerability_type="no concrete vulnerability",
            impact="no demonstrated security impact",
            code_evidence="input is validated before use",
            fix_direction="no security fix is required",
        ),
    )
