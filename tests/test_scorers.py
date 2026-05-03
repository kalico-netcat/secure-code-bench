import pytest

from secure_code_bench.models import ScorerConfig
from secure_code_bench.scorers import ScorerError, score_response


def test_contains_scorer_is_case_insensitive_by_default() -> None:
    scores = score_response("This has SQL Injection risk.", [ScorerConfig(type="contains", value="sql injection")])

    assert scores[0].passed is True


def test_regex_scorer_matches_response() -> None:
    scores = score_response(
        "Use parameterized queries.",
        [ScorerConfig(type="regex", pattern=r"parameteri[sz]ed")],
    )

    assert scores[0].passed is True


def test_contains_scorer_requires_value() -> None:
    with pytest.raises(ScorerError):
        score_response("anything", [ScorerConfig(type="contains")])

