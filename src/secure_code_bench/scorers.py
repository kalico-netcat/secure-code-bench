from __future__ import annotations

import re

from secure_code_bench.models import ScoreResult, ScorerConfig


class ScorerError(ValueError):
    """Raised for invalid scorer configuration."""


def score_response(response: str, scorers: list[ScorerConfig]) -> list[ScoreResult]:
    return [_score_one(response, scorer) for scorer in scorers]


def _score_one(response: str, scorer: ScorerConfig) -> ScoreResult:
    if scorer.type == "contains":
        if scorer.value is None:
            raise ScorerError("contains scorer requires 'value'.")
        haystack = response if scorer.case_sensitive else response.lower()
        needle = scorer.value if scorer.case_sensitive else scorer.value.lower()
        passed = needle in haystack
        return ScoreResult(
            name="contains",
            passed=passed,
            score=1.0 if passed else 0.0,
            max_score=1.0,
            details={"value": scorer.value, "case_sensitive": scorer.case_sensitive},
        )

    if scorer.type == "regex":
        if scorer.pattern is None:
            raise ScorerError("regex scorer requires 'pattern'.")
        flags = 0 if scorer.case_sensitive else re.IGNORECASE
        match = re.search(scorer.pattern, response, flags=flags)
        return ScoreResult(
            name="regex",
            passed=match is not None,
            score=1.0 if match is not None else 0.0,
            max_score=1.0,
            details={"pattern": scorer.pattern, "case_sensitive": scorer.case_sensitive},
        )

    raise ScorerError(f"Unsupported scorer type: {scorer.type}")
