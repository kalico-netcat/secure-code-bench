from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from secure_code_bench.env import load_dotenv
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
) -> None:
    load_dotenv()
    benchmark_suite = load_suite(suite)
    provider = OpenRouterProvider()
    results = run_suite(
        benchmark_suite,
        models=model,
        provider=provider,
        options=RunOptions(temperature=temperature, max_tokens=max_tokens),
    )
    output_path = write_jsonl(output, results)
    _print_summary(results, output_path)


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
