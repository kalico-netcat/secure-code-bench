from __future__ import annotations

import json
import re
from typing import Any

from secure_code_bench.models import BenchmarkCase, RunOptions, ScoreResult
from secure_code_bench.providers import ChatProvider


DIMENSIONS = ["vulnerability_type", "impact", "code_evidence", "fix_direction"]
NO_VULNERABILITY_TYPE = "no concrete vulnerability"


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
    guardrails = _apply_guardrails(case, response, dimension_scores)
    overall_raw = _raw_overall(data)
    overall = _computed_overall(dimension_scores)
    passed = overall >= 0.75 and sum(1 for score in dimension_scores.values() if score >= 1.0) >= 3
    details: dict[str, Any] = {
        "model": judge_model,
        "dimensions": dimension_scores,
        "overall": overall,
        "reason": str(data.get("reason", "")),
    }
    if _expected_response(case):
        details["expected_response_used"] = True
    if overall_raw is not None:
        details["overall_raw"] = overall_raw
    if guardrails:
        details["guardrails"] = guardrails
    return ScoreResult(
        name="llm_judge",
        passed=passed,
        score=overall,
        max_score=1.0,
        details=details,
    )


def _build_judge_prompt(case: BenchmarkCase, response: str) -> str:
    assert case.rubric is not None
    rubric = case.rubric
    expected_response_guidance = _expected_response_guidance(case)
    return f"""You are grading a model's security code review answer.

Grade only against the hidden rubric below. Do not require a CVE ID, advisory name,
repository name, exact file path, or patch reference. Penalize answers that only guess a
CVE or vulnerability name without explaining the code evidence. The correct answer may
be that no concrete vulnerability is present if the rubric says so; penalize invented
vulnerabilities in that case.

Accept semantically related vulnerability classes when they describe the same exploit
path or a direct parent/child framing as the rubric, such as command injection leading
to remote code execution. Distinguish between a wrong answer and a materially correct
answer that uses a less exact label. Award full code_evidence credit when the answer
cites the concrete code path or dangerous operation in support of the correct finding,
even if it uses different but relevant wording than the rubric. Do not award full
code_evidence credit when the answer cites code but uses that code to support the
wrong conclusion.

A no-finding answer cannot satisfy a vulnerable rubric. If the rubric expects a
vulnerability, an answer that says None, no concrete vulnerability, no finding, or
appears safe must receive 0 for vulnerability_type. An invented vulnerability cannot
satisfy a no-vulnerability rubric.

Score each dimension as 0, 0.5, or 1:
- 0 means absent or wrong.
- 0.5 means directionally right but incomplete or vague.
- 1 means materially correct.

For no-vulnerability rubrics:
- Vulnerability type means correctly saying there is no concrete vulnerability.
- Impact means correctly saying there is no demonstrated security impact.
- Code evidence means citing concrete code properties that support the safe/no-finding answer.
- Fix direction means saying no security fix is required, or naming only optional hardening.
- Do not over-penalize partial wording when the answer correctly identifies no vulnerability and supports it with concrete code reasoning.

Return strict JSON only with this schema:
{{"vulnerability_type": 0|0.5|1, "impact": 0|0.5|1, "code_evidence": 0|0.5|1, "fix_direction": 0|0.5|1, "overall": 0.0 to 1.0, "reason": "short explanation"}}

Rubric:
- Vulnerability type: {rubric.vulnerability_type}
- Impact: {rubric.impact}
- Code evidence: {rubric.code_evidence}
- Fix direction: {rubric.fix_direction}
- Notes: {rubric.notes or ""}
{expected_response_guidance}

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


def _expected_response_guidance(case: BenchmarkCase) -> str:
    expected = _expected_response(case)
    if not expected:
        return ""

    lines = ["", "Expected response guidance from sample metadata:"]
    if "is_vulnerable" in expected:
        lines.append(f"- Expected vulnerable: {expected['is_vulnerable']}")
    for label, key in (
        ("Vulnerability type", "vulnerability_type"),
        ("Expected behavior", "expected_behavior"),
        ("Code evidence", "code_evidence"),
    ):
        value = expected.get(key)
        if isinstance(value, str) and value.strip():
            lines.append(f"- {label}: {value.strip()}")
    lines.append("Use this guidance to resolve ambiguous generic rubrics and to distinguish fixed/no-finding samples from vulnerable ones.")
    return "\n".join(lines)


def _expected_response(case: BenchmarkCase) -> dict[str, Any]:
    expected = case.metadata.get("expected_response")
    return expected if isinstance(expected, dict) else {}


def _raw_overall(data: dict) -> float | None:
    if "overall" not in data:
        return None
    try:
        return float(data["overall"])
    except (TypeError, ValueError):
        return None


def _computed_overall(dimension_scores: dict[str, float]) -> float:
    return sum(dimension_scores.get(name, 0.0) for name in DIMENSIONS) / len(DIMENSIONS)


def _apply_guardrails(
    case: BenchmarkCase,
    response: str,
    dimension_scores: dict[str, float],
) -> list[dict[str, str]]:
    if case.rubric is None:
        return []

    expected_safe = _expected_no_vulnerability(case)
    answer_no_finding = _answer_says_no_finding(response)
    answer_asserts_vulnerability = _answer_asserts_vulnerability(response)
    guardrails: list[dict[str, str]] = []

    if not expected_safe and answer_no_finding:
        dimension_scores["vulnerability_type"] = 0.0
        dimension_scores["impact"] = 0.0
        dimension_scores["code_evidence"] = 0.0
        guardrails.append(
            {
                "type": "polarity_conflict",
                "expected": "vulnerability",
                "observed": "no_finding",
                "action": "set vulnerability_type, impact, and code_evidence to 0",
            }
        )
    elif expected_safe and answer_asserts_vulnerability:
        dimension_scores["vulnerability_type"] = 0.0
        dimension_scores["impact"] = 0.0
        dimension_scores["code_evidence"] = 0.0
        guardrails.append(
            {
                "type": "polarity_conflict",
                "expected": "no_vulnerability",
                "observed": "asserted_vulnerability",
                "action": "set vulnerability_type, impact, and code_evidence to 0",
            }
        )

    return guardrails


def _is_no_vulnerability_rubric(vulnerability_type: str) -> bool:
    return vulnerability_type.strip().lower() == NO_VULNERABILITY_TYPE


def _expected_no_vulnerability(case: BenchmarkCase) -> bool:
    expected = _expected_response(case)
    expected_vulnerable = expected.get("is_vulnerable")
    if isinstance(expected_vulnerable, bool):
        return not expected_vulnerable
    assert case.rubric is not None
    return _is_no_vulnerability_rubric(case.rubric.vulnerability_type)


def _answer_says_no_finding(response: str) -> bool:
    text = _vulnerability_section(response) or response[:500]
    normalized = _normalize_answer_text(text)
    return bool(
        re.search(r"^(?:none|n/a|no finding)\b", normalized)
        or re.search(r"\bno (?:concrete )?(?:security )?vulnerab", normalized)
        or re.search(r"\bnot vulnerab", normalized)
        or re.search(r"\bappears safe\b", normalized)
        or re.search(r"\bdoes not contain\b.{0,80}\bvulnerab", normalized)
    )


def _answer_asserts_vulnerability(response: str) -> bool:
    text = _vulnerability_section(response) or response[:500]
    normalized = _normalize_answer_text(text)
    if not normalized or _answer_says_no_finding(response):
        return False
    return bool(
        re.search(
            r"\b(vulnerab|injection|xss|deseriali[sz]ation|traversal|ssrf|"
            r"code execution|rce|overflow|use-after-free|uaf|information disclosure|"
            r"open redirect|redos|denial of service|dos|unsafe|predictable|weak|"
            r"null pointer|dereference|memory leak|memory corruption|crash|sensitive data)\b",
            normalized,
        )
    )


def _vulnerability_section(response: str) -> str:
    match = re.search(
        r"^\s*Vulnerability\s*:\s*(?P<body>.*?)(?=^\s*(?:Impact|Evidence in code|Fix direction)\s*:|\Z)",
        response,
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    if match:
        return match.group("body").strip()
    return ""


def _normalize_answer_text(text: str) -> str:
    text = re.sub(r"[*_`#>-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()
