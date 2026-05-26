from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Literal

from secure_code_bench.models import BenchmarkCase, BenchmarkSuite
from secure_code_bench.prompts import PromptRenderError, render_prompt


FindingSeverity = Literal["error", "warning"]


@dataclass(frozen=True)
class ValidationFinding:
    severity: FindingSeverity
    code: str
    message: str
    suite_path: Path | None = None
    case_id: str | None = None


def validate_suite(suite: BenchmarkSuite) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    seen_case_ids: set[str] = set()
    duplicate_case_ids: set[str] = set()

    for case in suite.cases:
        if case.id in seen_case_ids:
            duplicate_case_ids.add(case.id)
        seen_case_ids.add(case.id)

        findings.extend(_validate_case(suite, case))

    for case_id in sorted(duplicate_case_ids):
        findings.append(
            ValidationFinding(
                severity="error",
                code="duplicate_case_id",
                message=f"Duplicate case id: {case_id}",
                suite_path=suite.path,
                case_id=case_id,
            )
        )

    return findings


def validate_suite_set(suites: list[BenchmarkSuite]) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    for suite in suites:
        findings.extend(validate_suite(suite))

    findings.extend(_validate_kev_prompt_assumption_pairs(suites))
    return findings


def _validate_case(suite: BenchmarkSuite, case: BenchmarkCase) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    suite_dir = suite.path.parent if suite.path else Path.cwd()
    rendered_prompt = ""

    if not case.prompt.strip():
        findings.append(
            _case_finding("error", "empty_prompt", "Prompt is empty.", suite, case)
        )

    for code_file in case.code_files:
        path = code_file if code_file.is_absolute() else suite_dir / code_file
        path = path.resolve()
        if not path.exists():
            findings.append(
                _case_finding(
                    "error",
                    "missing_code_file",
                    f"Code file does not exist: {path}",
                    suite,
                    case,
                )
            )
            continue
        if not path.is_file():
            findings.append(
                _case_finding(
                    "error",
                    "missing_code_file",
                    f"Code file is not a regular file: {path}",
                    suite,
                    case,
                )
            )
            continue
        try:
            if not path.read_text(encoding="utf-8").strip():
                findings.append(
                    _case_finding(
                        "warning",
                        "empty_code_file",
                        f"Code file is empty: {path}",
                        suite,
                        case,
                    )
                )
        except UnicodeDecodeError:
            findings.append(
                _case_finding(
                    "warning",
                    "non_utf8_code_file",
                    f"Code file is not UTF-8 text: {path}",
                    suite,
                    case,
                )
            )

    try:
        rendered_prompt = render_prompt(suite, case)
    except PromptRenderError as exc:
        findings.append(_case_finding("error", "prompt_render_error", str(exc), suite, case))
    else:
        if not rendered_prompt.strip():
            findings.append(
                _case_finding(
                    "error",
                    "empty_rendered_prompt",
                    "Rendered prompt is empty.",
                    suite,
                    case,
                )
            )

    for index, scorer in enumerate(case.scorers, start=1):
        if scorer.type == "regex":
            if scorer.pattern is None:
                findings.append(
                    _case_finding(
                        "error",
                        "invalid_regex_scorer",
                        f"Regex scorer #{index} is missing a pattern.",
                        suite,
                        case,
                    )
                )
            else:
                try:
                    re.compile(scorer.pattern)
                except re.error as exc:
                    findings.append(
                        _case_finding(
                            "error",
                            "invalid_regex_scorer",
                            f"Regex scorer #{index} has invalid pattern: {exc}",
                            suite,
                            case,
                        )
                    )
        elif scorer.type == "contains" and scorer.value is None:
            findings.append(
                _case_finding(
                    "error",
                    "invalid_contains_scorer",
                    f"Contains scorer #{index} is missing a value.",
                    suite,
                    case,
                )
            )

    if case.metadata.get("rubric_quality") == "weak":
        findings.append(
            _case_finding(
                "warning",
                "weak_rubric",
                "Positive KEV case has weak rubric metadata.",
                suite,
                case,
            )
        )

    prompt_text_for_leakage = rendered_prompt or case.prompt
    if _has_prompt_leakage(prompt_text_for_leakage):
        findings.append(
            _case_finding(
                "warning",
                "prompt_leakage",
                "Prompt may reveal source identifiers such as CVE IDs, URLs, repositories, or sample paths.",
                suite,
                case,
            )
        )

    return findings


def _validate_kev_prompt_assumption_pairs(
    suites: list[BenchmarkSuite],
) -> list[ValidationFinding]:
    by_stem: dict[str, dict[str, BenchmarkSuite]] = {}
    for suite in suites:
        if suite.path is None:
            continue
        assumption = _prompt_assumption_for(suite)
        if assumption is None:
            continue
        by_stem.setdefault(_paired_stem(suite.path.stem), {})[assumption] = suite

    findings: list[ValidationFinding] = []
    for paired in by_stem.values():
        may_be_safe = paired.get("may-be-safe")
        known_vulnerable = paired.get("known-vulnerable")
        if may_be_safe is None or known_vulnerable is None:
            continue
        findings.extend(_compare_prompt_assumption_pair(may_be_safe, known_vulnerable))
    return findings


def _compare_prompt_assumption_pair(
    may_be_safe: BenchmarkSuite,
    known_vulnerable: BenchmarkSuite,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    if len(may_be_safe.cases) != len(known_vulnerable.cases):
        findings.append(
            ValidationFinding(
                severity="error",
                code="paired_suite_mismatch",
                message=(
                    "Paired KEV prompt-assumption suites have different case counts: "
                    f"{len(may_be_safe.cases)} vs {len(known_vulnerable.cases)}"
                ),
                suite_path=known_vulnerable.path,
            )
        )
        return findings

    for index, (left, right) in enumerate(
        zip(may_be_safe.cases, known_vulnerable.cases), start=1
    ):
        if _case_pair_signature(left) != _case_pair_signature(right):
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="paired_suite_mismatch",
                    message=(
                        "Paired KEV prompt-assumption suites differ at case "
                        f"{index}: {left.id} vs {right.id}"
                    ),
                    suite_path=known_vulnerable.path,
                    case_id=right.id,
                )
            )
    return findings


def _case_finding(
    severity: FindingSeverity,
    code: str,
    message: str,
    suite: BenchmarkSuite,
    case: BenchmarkCase,
) -> ValidationFinding:
    return ValidationFinding(
        severity=severity,
        code=code,
        message=message,
        suite_path=suite.path,
        case_id=case.id,
    )


def _has_prompt_leakage(prompt: str) -> bool:
    return bool(
        re.search(r"CVE-\d{4}-\d{4,}", prompt, flags=re.IGNORECASE)
        or re.search(r"https?://", prompt, flags=re.IGNORECASE)
        or re.search(r"\bgithub\.com\b", prompt, flags=re.IGNORECASE)
        or re.search(r"\b(?:sample_id|repository|repo_name)\b", prompt, flags=re.IGNORECASE)
        or re.search(r"/(?:samples|repos|repositories)/", prompt, flags=re.IGNORECASE)
    )


def _prompt_assumption_for(suite: BenchmarkSuite) -> str | None:
    text = " ".join(
        part
        for part in (
            suite.name,
            suite.path.stem if suite.path is not None else "",
        )
        if part
    ).lower()
    if "may-be-safe" in text:
        return "may-be-safe"
    if "known-vulnerable" in text:
        return "known-vulnerable"
    return None


def _paired_stem(stem: str) -> str:
    return stem.removesuffix("-may-be-safe").removesuffix("-known-vulnerable")


def _case_pair_signature(case: BenchmarkCase) -> tuple[str, tuple[str, ...], object]:
    return (
        case.id,
        tuple(str(path) for path in case.code_files),
        case.metadata.get("expected_response"),
    )
