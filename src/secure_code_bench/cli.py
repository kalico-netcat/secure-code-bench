from __future__ import annotations

from pathlib import Path
from typing import Optional

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
) -> None:
    load_dotenv()
    benchmark_suite = load_suite(suite)
    provider = OpenRouterProvider()
    results = run_suite(
        benchmark_suite,
        models=model,
        provider=provider,
        options=RunOptions(temperature=temperature, max_tokens=max_tokens),
        progress=_progress_callback(benchmark_suite),
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
) -> None:
    output_path, suite = write_kev_suite(
        samples_root=samples_root,
        output=output,
        status=status,
        limit=limit,
        anonymize=anonymize,
    )
    typer.echo(f"Wrote {len(suite.cases)} KEV benchmark case(s) to {output_path}")


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


def _progress_callback(benchmark_suite):
    ordered_cases = benchmark_suite.cases

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
