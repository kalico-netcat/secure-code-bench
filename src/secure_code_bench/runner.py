from __future__ import annotations

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import time
from typing import Callable, Optional

from secure_code_bench.models import BenchmarkCase, BenchmarkSuite, RunOptions, RunResult, ScoreResult
from secure_code_bench.prompts import render_prompt
from secure_code_bench.providers import ChatProvider
from secure_code_bench.scorers import score_response
from secure_code_bench.judge import score_with_judge
from secure_code_bench.acceptance import accept_deterministic, accept_judge

ProgressCallback = Callable[[str, str, int, int], None]
ResultCallback = Callable[[int, RunResult], None]


@dataclass(frozen=True)
class _RunTask:
    ordinal: int
    model: str
    case: BenchmarkCase
    prompt: str


def run_suite(
    suite: BenchmarkSuite,
    models: Sequence[str],
    provider: ChatProvider,
    options: Optional[RunOptions] = None,
    progress: Optional[ProgressCallback] = None,
    result_callback: Optional[ResultCallback] = None,
) -> list[RunResult]:
    run_options = options or RunOptions()
    cases = suite.cases[: run_options.limit] if run_options.limit is not None else suite.cases
    tasks = [
        _RunTask(
            ordinal=ordinal,
            model=model,
            case=case,
            prompt=render_prompt(suite, case),
        )
        for ordinal, (model, case) in enumerate(
            ((model, case) for model in models for case in cases),
            start=1,
        )
    ]
    total = len(tasks)
    workers = max(1, run_options.workers)

    if workers == 1:
        results: list[tuple[int, RunResult]] = []
        for task in tasks:
            if progress is not None:
                progress("start", task.model, task.ordinal, total)
            result = _run_task(suite, provider, run_options, task)
            if result_callback is not None:
                result_callback(task.ordinal, result)
            if progress is not None:
                progress(_progress_event(result), task.model, task.ordinal, total)
            results.append((task.ordinal, result))
        return [result for _, result in results]

    results_by_ordinal: dict[int, RunResult] = {}
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {}
        for task in tasks:
            if progress is not None:
                progress("start", task.model, task.ordinal, total)
            future = executor.submit(_run_task, suite, provider, run_options, task)
            futures[future] = task

        for future in as_completed(futures):
            task = futures[future]
            result = future.result()
            results_by_ordinal[task.ordinal] = result
            if result_callback is not None:
                result_callback(task.ordinal, result)
            if progress is not None:
                progress(_progress_event(result), task.model, task.ordinal, total)
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)

    return [results_by_ordinal[ordinal] for ordinal in range(1, total + 1)]


def _run_task(
    suite: BenchmarkSuite,
    provider: ChatProvider,
    run_options: RunOptions,
    task: _RunTask,
) -> RunResult:
    try:
        model_response = _generate_with_retries(provider, task.model, task.prompt, run_options)
    except Exception as exc:
        return RunResult(
            suite=suite.name,
            case_id=task.case.id,
            model=task.model,
            status="model_error",
            prompt=task.prompt,
            response="",
            scores=[],
            passed=False,
            acceptance=accept_deterministic([]),
            metadata={
                **task.case.metadata,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "score_count": 0,
            },
        )
    try:
        scores = score_response(model_response.text, task.case.scorers)
    except Exception as exc:
        return RunResult(
            suite=suite.name,
            case_id=task.case.id,
            model=task.model,
            status="scorer_error",
            prompt=task.prompt,
            response=model_response.text,
            scores=[],
            passed=False,
            acceptance=accept_deterministic([]),
            metadata={
                **task.case.metadata,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "score_count": 0,
            },
        )
    judge_score: Optional[ScoreResult] = None
    status = "completed"
    if run_options.judge:
        try:
            judge_score = score_with_judge(
                provider=provider,
                judge_model=run_options.judge_model,
                case=task.case,
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
        accept_judge(judge_score, task.case.acceptance)
        if judge_score is not None
        else accept_deterministic(scores)
    )
    return RunResult(
        suite=suite.name,
        case_id=task.case.id,
        model=task.model,
        status=status,
        prompt=task.prompt,
        response=model_response.text,
        scores=scores,
        passed=acceptance.passed,
        acceptance=acceptance,
        metadata={**task.case.metadata, "score_count": len(scores)},
    )


def _progress_event(result: RunResult) -> str:
    if result.status in {"model_error", "scorer_error"}:
        return "error"
    return "finish"


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
