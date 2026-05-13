from __future__ import annotations

import random
from pathlib import Path
from typing import Literal, Optional

import typer

from secure_code_bench.env import load_dotenv
from secure_code_bench.kev import write_kev_suite
from secure_code_bench.models import RunOptions
from secure_code_bench.providers import OpenRouterProvider
from secure_code_bench.results import write_jsonl
from secure_code_bench.runner import run_suite
from secure_code_bench.suites import load_suite

app = typer.Typer(help="Run simple LLM benchmark suites.")


@app.callback()
def main() -> None:
    """Run simple LLM benchmark suites."""


@app.command()
def run(
    suite: Path = typer.Argument(..., help="Path to a benchmark suite YAML file."),
    model: list[str] = typer.Option(
        ...,
        "--model",
        "-m",
        help="Model ID to run. Pass multiple times to compare models.",
    ),
    output: Path = typer.Option(
        Path("results/benchmark-results.jsonl"),
        "--output",
        "-o",
        help="Where to write JSONL run records.",
    ),
    temperature: float = typer.Option(0.0, help="Sampling temperature for model calls."),
    max_tokens: Optional[int] = typer.Option(None, help="Optional response token limit."),
    timeout: float = typer.Option(600.0, help="HTTP timeout in seconds for each model request."),
    retries: int = typer.Option(3, help="Retries per model/case request after the first attempt."),
    limit: Optional[int] = typer.Option(None, help="Maximum number of suite cases to run per model."),
    judge: bool = typer.Option(False, "--judge", help="Use a hidden rubric and judge model for scoring."),
    judge_model: str = typer.Option(
        "openai/gpt-mini-latest",
        help="Model to use when --judge is enabled.",
    ),
) -> None:
    load_dotenv()
    benchmark_suite = load_suite(suite)
    provider = OpenRouterProvider(timeout=timeout)
    results = run_suite(
        benchmark_suite,
        models=model,
        provider=provider,
        options=RunOptions(
            temperature=temperature,
            max_tokens=max_tokens,
            retries=retries,
            limit=limit,
            judge=judge,
            judge_model=judge_model,
        ),
        progress=_progress_callback(benchmark_suite, limit=limit),
    )
    output_path = write_jsonl(output, results)
    _print_summary(results, output_path)


@app.command("kev-suite")
def kev_suite(
    samples_root: Path = typer.Option(
        ...,
        "--samples-root",
        help="Path to the KEV collector samples directory.",
    ),
    output: Path = typer.Option(
        Path("examples/kev.yml"),
        "--output",
        "-o",
        help="Where to write the generated benchmark suite YAML.",
    ),
    status: str = typer.Option("accepted", help="Sample metadata status to include, or 'all'."),
    limit: Optional[int] = typer.Option(None, help="Optional maximum number of samples to include."),
    anonymize: bool = typer.Option(
        True,
        "--anonymize",
        help="Use neutral case IDs and omit source identifiers from generated prompts.",
    ),
    prompt_assumption: Literal["may-be-safe", "known-vulnerable", "both"] = typer.Option(
        "may-be-safe",
        "--prompt-assumption",
        help="Prompt prior to give models, or 'both' to write paired suites.",
    ),
    randomize: bool = typer.Option(
        True,
        "--randomize/--ordered",
        help="Shuffle discovered samples before applying --limit, or use --ordered for filesystem order.",
    ),
    seed: Optional[int] = typer.Option(
        None,
        "--seed",
        help="Optional random seed for reproducible --randomize selection.",
    ),
) -> None:
    if prompt_assumption == "both":
        effective_seed = seed
        if randomize and effective_seed is None:
            effective_seed = random.SystemRandom().randrange(0, 2**32)
        for assumption in ("may-be-safe", "known-vulnerable"):
            output_path, suite = write_kev_suite(
                samples_root=samples_root,
                output=_paired_output_path(output, assumption),
                status=status,
                limit=limit,
                anonymize=anonymize,
                prompt_assumption=assumption,
                randomize=randomize,
                seed=effective_seed,
            )
            typer.echo(f"Wrote {len(suite.cases)} KEV benchmark case(s) to {output_path}")
        return

    output_path, suite = write_kev_suite(
        samples_root=samples_root,
        output=output,
        status=status,
        limit=limit,
        anonymize=anonymize,
        prompt_assumption=prompt_assumption,
        randomize=randomize,
        seed=seed,
    )
    typer.echo(f"Wrote {len(suite.cases)} KEV benchmark case(s) to {output_path}")


def _paired_output_path(output: Path, assumption: str) -> Path:
    return output.with_name(f"{output.stem}-{assumption}{output.suffix or '.yml'}")


def _print_summary(results: list, output_path: Path) -> None:
    by_model: dict[str, list] = {}
    for result in results:
        by_model.setdefault(result.model, []).append(result)

    typer.echo(f"\nWrote {len(results)} result(s) to {output_path}")
    typer.echo("Summary")
    typer.echo("-------")
    for model, model_results in by_model.items():
        passed = sum(1 for result in model_results if result.passed)
        total = len(model_results)
        typer.echo(f"{model}: {passed}/{total} passed")


def _progress_callback(benchmark_suite, limit: Optional[int] = None):
    ordered_cases = benchmark_suite.cases[:limit] if limit is not None else benchmark_suite.cases

    def callback(event: str, model: str, current: int, total: int) -> None:
        case = ordered_cases[(current - 1) % len(ordered_cases)]
        prefix = f"[{current}/{total}] {model} :: {case.id}"
        if event == "start":
            typer.echo(f"{prefix} ...", nl=False)
        elif event == "finish":
            typer.echo(" done")
        elif event == "error":
            typer.echo(" failed")

    return callback
