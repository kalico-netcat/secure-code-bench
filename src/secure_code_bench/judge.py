from __future__ import annotations

import json
import re

from secure_code_bench.models import BenchmarkCase, RunOptions, ScoreResult
from secure_code_bench.providers import ChatProvider


DIMENSIONS = ["vulnerability_type", "impact", "code_evidence", "fix_direction"]


def score_with_judge(
    provider: ChatProvider,
    judge_model: str,
    case: BenchmarkCase,
    response: str,
    options: RunOptions,
) -> ScoreResult:
    if case.rubric is None:
        return ScoreResult(
            name="llm_judge",
            passed=False,
            details={"error": "case has no judge rubric"},
        )

    judge_prompt = _build_judge_prompt(case, response)
    judge_response = provider.generate(
        judge_model,
        judge_prompt,
        RunOptions(temperature=0.0, max_tokens=800, retries=options.retries),
    )
    data = _parse_judge_json(judge_response.text)
    dimension_scores = {name: _dimension_score(data.get(name, 0)) for name in DIMENSIONS}
    overall = float(data.get("overall", sum(dimension_scores.values()) / len(DIMENSIONS)))
    passed = overall >= 0.75 and sum(1 for score in dimension_scores.values() if score >= 1.0) >= 3
    return ScoreResult(
        name="llm_judge",
        passed=passed,
        score=overall,
        max_score=1.0,
        details={
            "model": judge_model,
            "dimensions": dimension_scores,
            "overall": overall,
            "reason": str(data.get("reason", "")),
        },
    )


def _build_judge_prompt(case: BenchmarkCase, response: str) -> str:
    assert case.rubric is not None
    rubric = case.rubric
    return f"""You are grading a model's security code review answer.

Grade only against the hidden rubric below. Do not require a CVE ID, advisory name,
repository name, exact file path, or patch reference. Penalize answers that only guess a
CVE or vulnerability name without explaining the code evidence. The correct answer may
be that no concrete vulnerability is present if the rubric says so; penalize invented
vulnerabilities in that case.

Score each dimension as 0, 0.5, or 1:
- 0 means absent or wrong.
- 0.5 means directionally right but incomplete or vague.
- 1 means materially correct.

For no-vulnerability rubrics:
- Vulnerability type means correctly saying there is no concrete vulnerability.
- Impact means correctly saying there is no demonstrated security impact.
- Code evidence means citing concrete code properties that support the safe/no-finding answer.
- Fix direction means saying no security fix is required, or naming only optional hardening.

Return strict JSON only with this schema:
{{"vulnerability_type": 0|0.5|1, "impact": 0|0.5|1, "code_evidence": 0|0.5|1, "fix_direction": 0|0.5|1, "overall": 0.0 to 1.0, "reason": "short explanation"}}

Rubric:
- Vulnerability type: {rubric.vulnerability_type}
- Impact: {rubric.impact}
- Code evidence: {rubric.code_evidence}
- Fix direction: {rubric.fix_direction}
- Notes: {rubric.notes or ""}

Model answer:
{response}
"""


def _parse_judge_json(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError(f"Judge did not return JSON: {text}")
        return json.loads(match.group(0))


def _dimension_score(value: object) -> float:
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    if score <= 0:
        return 0.0
    if score < 1:
        return 0.5
    return 1.0
