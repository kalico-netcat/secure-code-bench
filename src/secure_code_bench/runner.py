from __future__ import annotations

from collections.abc import Sequence
import time
from typing import Callable, Optional

from secure_code_bench.models import BenchmarkSuite, RunOptions, RunResult
from secure_code_bench.prompts import render_prompt
from secure_code_bench.providers import ChatProvider
from secure_code_bench.scorers import score_response


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
                if run_options.continue_on_error:
                    results.append(
                        RunResult(
                            suite=suite.name,
                            case_id=case.id,
                            model=model,
                            prompt=prompt,
                            response="",
                            scores=[],
                            passed=False,
                            metadata={
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                                "score_count": 0,
                            },
                        )
                    )
                    continue
                raise
            scores = score_response(model_response.text, case.scorers)
            passed = bool(scores) and all(score.passed for score in scores)
            results.append(
                RunResult(
                    suite=suite.name,
                    case_id=case.id,
                    model=model,
                    prompt=prompt,
                    response=model_response.text,
                    scores=scores,
                    passed=passed,
                    metadata={"score_count": len(scores)},
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
