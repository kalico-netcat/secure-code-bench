from __future__ import annotations

from collections.abc import Sequence
import time
from typing import Callable, Optional

from secure_code_bench.models import BenchmarkSuite, RunOptions, RunResult, ScoreResult
from secure_code_bench.prompts import render_prompt
from secure_code_bench.providers import ChatProvider
from secure_code_bench.scorers import score_response
from secure_code_bench.judge import score_with_judge
from secure_code_bench.acceptance import accept_deterministic, accept_judge


def run_suite(
    suite: BenchmarkSuite,
    models: Sequence[str],
    provider: ChatProvider,
    options: Optional[RunOptions] = None,
    progress: Optional[Callable[[str, str, int, int], None]] = None,
) -> list[RunResult]:
    run_options = options or RunOptions()
    results: list[RunResult] = []
    cases = suite.cases[: run_options.limit] if run_options.limit is not None else suite.cases
    total = len(models) * len(cases)
    current = 0

    for model in models:
        for case in cases:
            current += 1
            if progress is not None:
                progress("start", model, current, total)
            prompt = render_prompt(suite, case)
            try:
                model_response = _generate_with_retries(provider, model, prompt, run_options)
            except Exception as exc:
                if progress is not None:
                    progress("error", model, current, total)
                results.append(
                    RunResult(
                        suite=suite.name,
                        case_id=case.id,
                        model=model,
                        status="model_error",
                        prompt=prompt,
                        response="",
                        scores=[],
                        passed=False,
                        acceptance=accept_deterministic([]),
                        metadata={
                            **case.metadata,
                            "error": str(exc),
                            "error_type": type(exc).__name__,
                            "score_count": 0,
                        },
                    )
                )
                continue
            try:
                scores = score_response(model_response.text, case.scorers)
            except Exception as exc:
                if progress is not None:
                    progress("error", model, current, total)
                results.append(
                    RunResult(
                        suite=suite.name,
                        case_id=case.id,
                        model=model,
                        status="scorer_error",
                        prompt=prompt,
                        response=model_response.text,
                        scores=[],
                        passed=False,
                        acceptance=accept_deterministic([]),
                        metadata={
                            **case.metadata,
                            "error": str(exc),
                            "error_type": type(exc).__name__,
                            "score_count": 0,
                        },
                    )
                )
                continue
            judge_score: Optional[ScoreResult] = None
            status = "completed"
            if run_options.judge:
                try:
                    judge_score = score_with_judge(
                        provider=provider,
                        judge_model=run_options.judge_model,
                        case=case,
                        response=model_response.text,
                        options=run_options,
                    )
                except Exception as exc:
                    status = "judge_error"
                    judge_score = ScoreResult(
                        name="llm_judge",
                        passed=False,
                        score=0.0,
                        max_score=1.0,
                        details={"error": str(exc), "error_type": type(exc).__name__},
                    )
                scores.append(judge_score)
            acceptance = (
                accept_judge(judge_score, case.acceptance)
                if judge_score is not None
                else accept_deterministic(scores)
            )
            results.append(
                RunResult(
                    suite=suite.name,
                    case_id=case.id,
                    model=model,
                    status=status,
                    prompt=prompt,
                    response=model_response.text,
                    scores=scores,
                    passed=acceptance.passed,
                    acceptance=acceptance,
                    metadata={**case.metadata, "score_count": len(scores)},
                )
            )
            if progress is not None:
                progress("finish", model, current, total)

    return results


def _generate_with_retries(
    provider: ChatProvider,
    model: str,
    prompt: str,
    options: RunOptions,
):
    attempts = max(0, options.retries) + 1
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return provider.generate(model, prompt, options)
        except Exception as exc:
            last_exc = exc
            if attempt == attempts:
                break
            time.sleep(min(2 ** (attempt - 1), 8))

    assert last_exc is not None
    raise last_exc
