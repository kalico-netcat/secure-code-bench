from __future__ import annotations

import random
from pathlib import Path
from typing import Literal, Optional

import typer

from secure_code_bench.env import load_dotenv
from secure_code_bench.kev import write_kev_suite
from secure_code_bench.manifests import write_run_manifest
from secure_code_bench.models import RunOptions
from secure_code_bench.providers import RoutingProvider
from secure_code_bench.reporting import build_report, format_report, load_jsonl_records
from secure_code_bench.reporting_html import HtmlReportError, write_html_report
from secure_code_bench.results import write_jsonl
from secure_code_bench.runner import run_suite
from secure_code_bench.suites import SuiteLoadError, load_suite
from secure_code_bench.validation import ValidationFinding, validate_suite_set

app = typer.Typer(help="Run simple LLM benchmark suites.")


@app.callback()
def main() -> None:
    """Run simple LLM benchmark suites."""


@app.command()
def run(
    suites: list[Path] = typer.Argument(
        ...,
        help=(
            "Path to one or more benchmark suite YAML files. Pair each with an --output "
            "to write its results to a separate file."
        ),
    ),
    model: list[str] = typer.Option(
        ...,
        "--model",
        "-m",
        help="Model ID to run. Pass multiple times to compare models.",
    ),
    outputs: list[Path] = typer.Option(
        [],
        "--output",
        "-o",
        help=(
            "Where to write JSONL run records. Pass once per suite (paired by order). "
            "If omitted, defaults to results/<suite-stem>.jsonl for each suite."
        ),
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
    if outputs and len(outputs) != len(suites):
        raise typer.BadParameter(
            f"--output count ({len(outputs)}) must match suite count ({len(suites)}), "
            "or be omitted to use defaults."
        )
    if not outputs:
        outputs = [Path("results") / f"{suite.stem}.jsonl" for suite in suites]

    load_dotenv()
    provider = RoutingProvider(timeout=timeout)
    run_options = RunOptions(
        temperature=temperature,
        max_tokens=max_tokens,
        retries=retries,
        limit=limit,
        judge=judge,
        judge_model=judge_model,
    )

    for suite_path, output in zip(suites, outputs):
        benchmark_suite = load_suite(suite_path)
        results = run_suite(
            benchmark_suite,
            models=model,
            provider=provider,
            options=run_options,
            progress=_progress_callback(benchmark_suite, limit=limit),
        )
        output_path = write_jsonl(output, results)
        manifest_path = write_run_manifest(
            output_path=output_path,
            suite=benchmark_suite,
            models=model,
            options=run_options,
            timeout=timeout,
            results=results,
        )
        _print_summary(results, output_path)
        typer.echo(f"Manifest: {manifest_path}")


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


@app.command()
def validate(
    suites: list[Path] = typer.Argument(..., help="Path to one or more suite YAML files."),
) -> None:
    loaded_suites = []
    findings: list[ValidationFinding] = []
    for suite_path in suites:
        try:
            loaded_suites.append(load_suite(suite_path))
        except SuiteLoadError as exc:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="suite_load_error",
                    message=str(exc),
                    suite_path=suite_path,
                )
            )

    findings.extend(validate_suite_set(loaded_suites))
    _print_validation_findings(findings)
    if any(finding.severity == "error" for finding in findings):
        raise typer.Exit(code=1)


@app.command()
def report(
    results: list[Path] = typer.Argument(..., help="Path to one or more result JSONL files."),
    json_output: bool = typer.Option(False, "--json", help="Print the report as JSON."),
    html: Optional[Path] = typer.Option(None, "--html", help="Write an interactive HTML report."),
) -> None:
    records = load_jsonl_records(results)
    report_data = build_report(records)
    if html is not None:
        try:
            html_path = write_html_report(report_data, html)
        except HtmlReportError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(f"Wrote HTML report to {html_path}", err=json_output)
    if json_output:
        import json

        typer.echo(json.dumps(report_data, indent=2, sort_keys=True))
    else:
        typer.echo(format_report(report_data))


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
        completed = [result for result in model_results if result.status == "completed"]
        passed = sum(1 for result in completed if result.passed)
        errors = len(model_results) - len(completed)
        summary = f"{model}: {passed}/{len(completed)} completed passed"
        if errors:
            summary += f" ({errors} error record(s))"
        typer.echo(summary)


def _print_validation_findings(findings: list[ValidationFinding]) -> None:
    errors = sum(1 for finding in findings if finding.severity == "error")
    warnings = sum(1 for finding in findings if finding.severity == "warning")
    if not findings:
        typer.echo("Validation passed: no findings.")
        return

    for finding in findings:
        location = _finding_location(finding)
        typer.echo(
            f"{finding.severity.upper()} [{finding.code}]"
            f"{f' {location}' if location else ''}: {finding.message}"
        )
    typer.echo(f"\nValidation completed with {errors} error(s) and {warnings} warning(s).")


def _finding_location(finding: ValidationFinding) -> str:
    parts = []
    if finding.suite_path is not None:
        parts.append(str(finding.suite_path))
    if finding.case_id is not None:
        parts.append(f"case {finding.case_id}")
    return " :: ".join(parts)


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
