from __future__ import annotations

from secure_code_bench.models import AcceptanceConfig, AcceptanceResult, ScoreResult


DEFAULT_JUDGE_ACCEPTANCE = AcceptanceConfig()


def accept_deterministic(scores: list[ScoreResult]) -> AcceptanceResult:
    passed = bool(scores) and all(score.passed for score in scores)
    if not scores:
        overall = 0.0
        reason = "No deterministic scorers were configured."
    else:
        passed_count = sum(1 for score in scores if score.passed)
        overall = passed_count / len(scores)
        reason = f"{passed_count}/{len(scores)} deterministic scorers passed."

    return AcceptanceResult(
        mode="deterministic",
        passed=passed,
        overall=overall,
        required_dimensions_met=None,
        reason=reason,
    )


def accept_judge(score: ScoreResult, config: AcceptanceConfig | None = None) -> AcceptanceResult:
    policy = config or DEFAULT_JUDGE_ACCEPTANCE
    if not score.passed and "error" in score.details:
        return AcceptanceResult(
            mode="judge",
            passed=False,
            overall=0.0,
            required_dimensions_met=False,
            reason=str(score.details.get("error", "Judge scoring failed.")),
        )

    dimensions = score.details.get("dimensions", {})
    if not isinstance(dimensions, dict):
        dimensions = {}

    overall = _float_or_default(score.details.get("overall"), score.score or 0.0)
    missing = [
        dimension
        for dimension in policy.required_dimensions
        if _float_or_default(dimensions.get(dimension), 0.0) < policy.min_dimension_score
    ]
    required_dimensions_met = not missing
    passed = overall >= policy.min_overall and required_dimensions_met
    if passed:
        reason = str(score.details.get("reason") or "Judge acceptance policy passed.")
    elif missing:
        reason = "Missing required dimension(s): " + ", ".join(missing)
    else:
        reason = f"Overall score {overall:.2f} is below required {policy.min_overall:.2f}."

    return AcceptanceResult(
        mode="judge",
        passed=passed,
        overall=overall,
        required_dimensions_met=required_dimensions_met,
        reason=reason,
    )


def _float_or_default(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
