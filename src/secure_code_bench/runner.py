from __future__ import annotations

from collections.abc import Sequence
from typing import Optional

from secure_code_bench.models import BenchmarkSuite, RunOptions, RunResult
from secure_code_bench.prompts import render_prompt
from secure_code_bench.providers import ChatProvider
from secure_code_bench.scorers import score_response


def run_suite(
    suite: BenchmarkSuite,
    models: Sequence[str],
    provider: ChatProvider,
    options: Optional[RunOptions] = None,
) -> list[RunResult]:
    run_options = options or RunOptions()
    results: list[RunResult] = []

    for model in models:
        for case in suite.cases:
            prompt = render_prompt(suite, case)
            model_response = provider.generate(model, prompt, run_options)
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

    return results
