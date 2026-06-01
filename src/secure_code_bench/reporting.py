from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable, Iterator


ReportRow = dict[str, Any]
DIMENSIONS = ["vulnerability_type", "impact", "code_evidence", "fix_direction"]
DIMENSION_BUCKETS = ["0.0", "0.5", "1.0"]


def load_jsonl_records(paths: Iterable[Path]) -> list[ReportRow]:
    records: list[ReportRow] = []
    for path in paths:
        records.extend(_load_one_jsonl(path))
    return records


def build_report(records: list[ReportRow]) -> dict[str, Any]:
    return {
        "total_records": len(records),
        "overall": _summarize(records),
        "by_model": _group(records, "model"),
        "by_suite": _group(records, "suite"),
        "by_prompt_assumption": _group(records, _prompt_assumption),
        "by_prompt_assumption_model": _nested_group(records, _prompt_assumption, "model"),
        "by_rubric_quality": _group(records, _rubric_quality),
        "by_vulnerability_label": _group(records, _vulnerability_label),
        "by_status": _group(records, _status),
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"Total records: {report['total_records']}",
        _format_summary("Overall", report["overall"]),
    ]
    for title, key in (
        ("By model", "by_model"),
        ("By suite", "by_suite"),
        ("By prompt assumption", "by_prompt_assumption"),
        ("By rubric quality", "by_rubric_quality"),
        ("By vulnerable/control label", "by_vulnerability_label"),
        ("By status", "by_status"),
    ):
        lines.append("")
        lines.append(title)
        lines.append("-" * len(title))
        groups = report[key]
        if not groups:
            lines.append("(none)")
            continue
        for name in sorted(groups):
            lines.append(_format_summary(str(name), groups[name]))
    return "\n".join(lines)


def _load_one_jsonl(path: Path) -> Iterator[ReportRow]:
    with path.expanduser().open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL record in {path}:{line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"JSONL record must be an object in {path}:{line_number}")
            yield record


def _group(records: list[ReportRow], key: str | Any) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[ReportRow]] = {}
    for record in records:
        group_key = key(record) if callable(key) else record.get(key)
        grouped.setdefault(str(group_key or "unknown"), []).append(record)
    return {name: _summarize(group_records) for name, group_records in grouped.items()}


def _nested_group(
    records: list[ReportRow], outer_key: str | Any, inner_key: str | Any
) -> dict[str, dict[str, dict[str, Any]]]:
    grouped: dict[str, list[ReportRow]] = {}
    for record in records:
        group_key = outer_key(record) if callable(outer_key) else record.get(outer_key)
        grouped.setdefault(str(group_key or "unknown"), []).append(record)
    return {
        name: _group(group_records, inner_key)
        for name, group_records in sorted(grouped.items())
    }


def _summarize(records: list[ReportRow]) -> dict[str, Any]:
    completed = [record for record in records if _status(record) == "completed"]
    passed = sum(1 for record in completed if bool(record.get("passed")))
    return {
        "records": len(records),
        "completed": len(completed),
        "passed": passed,
        "failed": len(completed) - passed,
        "errors": len(records) - len(completed),
        "pass_rate": passed / len(completed) if completed else None,
        "guardrail_count": sum(_guardrail_count(record) for record in records),
        "status_counts": dict(sorted(Counter(_status(record) for record in records).items())),
        "failure_buckets": _failure_buckets(records),
        "dimension_histograms": _dimension_histograms(records),
    }


def _format_summary(name: str, summary: dict[str, Any]) -> str:
    pass_rate = summary["pass_rate"]
    pass_rate_text = "n/a" if pass_rate is None else f"{pass_rate:.1%}"
    status_text = ", ".join(
        f"{status}={count}" for status, count in summary["status_counts"].items()
    )
    failure_text = ", ".join(
        f"{bucket}={count}" for bucket, count in summary["failure_buckets"].items()
    )
    dims_text = _format_dimension_histograms(summary["dimension_histograms"])
    return (
        f"{name}: records={summary['records']} completed={summary['completed']} "
        f"passed={summary['passed']} failed={summary['failed']} errors={summary['errors']} "
        f"pass_rate={pass_rate_text} guardrails={summary['guardrail_count']} "
        f"statuses[{status_text}] failures[{failure_text}] dims[{dims_text}]"
    )


def _status(record: ReportRow) -> str:
    status = record.get("status")
    if isinstance(status, str) and status:
        return status
    metadata = record.get("metadata")
    if isinstance(metadata, dict) and metadata.get("error_type"):
        return "model_error"
    return "completed"


def _prompt_assumption(record: ReportRow) -> str:
    suite = str(record.get("suite") or "").lower()
    if "may-be-safe" in suite:
        return "may-be-safe"
    if "known-vulnerable" in suite:
        return "known-vulnerable"
    return "unknown"


def _rubric_quality(record: ReportRow) -> str:
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        value = metadata.get("rubric_quality")
        if value:
            return str(value)
    return "unspecified"


def _vulnerability_label(record: ReportRow) -> str:
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        return "unknown"
    expected = metadata.get("expected_response")
    if isinstance(expected, dict) and isinstance(expected.get("is_vulnerable"), bool):
        return "vulnerable" if expected["is_vulnerable"] else "control"
    rubric_quality = metadata.get("rubric_quality")
    if rubric_quality in {"strong", "weak"}:
        return "vulnerable"
    if rubric_quality == "control":
        return "control"
    return "unknown"


def _guardrail_count(record: ReportRow) -> int:
    scores = record.get("scores")
    if not isinstance(scores, list):
        return 0
    count = 0
    for score in scores:
        if not isinstance(score, dict):
            continue
        details = score.get("details")
        if not isinstance(details, dict):
            continue
        guardrails = details.get("guardrails")
        if isinstance(guardrails, list):
            count += len(guardrails)
    return count


def _failure_buckets(records: list[ReportRow]) -> dict[str, int]:
    counter = Counter(_failure_bucket(record) for record in records)
    return dict(sorted(counter.items()))


def _failure_bucket(record: ReportRow) -> str:
    status = _status(record)
    if status != "completed":
        return status
    if bool(record.get("passed")):
        return "passed"
    if _guardrail_count(record):
        return "polarity_conflict"

    reason = _acceptance_reason(record).lower()
    for dimension in DIMENSIONS:
        if dimension in reason and "missing" in reason:
            return f"missing_{dimension}"
    if "below required" in reason or "below threshold" in reason:
        return "overall_too_low"
    return "failed_other"


def _acceptance_reason(record: ReportRow) -> str:
    acceptance = record.get("acceptance")
    if isinstance(acceptance, dict):
        reason = acceptance.get("reason")
        if isinstance(reason, str):
            return reason
    return ""


def _dimension_histograms(records: list[ReportRow]) -> dict[str, dict[str, Any]]:
    histograms = {
        dimension: {"counts": {bucket: 0 for bucket in DIMENSION_BUCKETS}, "average": None}
        for dimension in DIMENSIONS
    }
    totals = {dimension: 0.0 for dimension in DIMENSIONS}
    seen = {dimension: 0 for dimension in DIMENSIONS}

    for record in records:
        dimensions = _judge_dimensions(record)
        for dimension in DIMENSIONS:
            if dimension not in dimensions:
                continue
            score = _normalized_dimension_score(dimensions[dimension])
            if score is None:
                continue
            bucket = f"{score:.1f}"
            histograms[dimension]["counts"][bucket] += 1
            totals[dimension] += score
            seen[dimension] += 1

    for dimension in DIMENSIONS:
        if seen[dimension]:
            histograms[dimension]["average"] = totals[dimension] / seen[dimension]
    return histograms


def _judge_dimensions(record: ReportRow) -> dict[str, Any]:
    scores = record.get("scores")
    if not isinstance(scores, list):
        return {}
    for score in scores:
        if not isinstance(score, dict):
            continue
        details = score.get("details")
        if not isinstance(details, dict):
            continue
        dimensions = details.get("dimensions")
        if isinstance(dimensions, dict):
            return dimensions
    return {}


def _normalized_dimension_score(value: object) -> float | None:
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if score <= 0:
        return 0.0
    if score < 1:
        return 0.5
    return 1.0


def _format_dimension_histograms(histograms: dict[str, dict[str, Any]]) -> str:
    parts = []
    for dimension in DIMENSIONS:
        data = histograms.get(dimension, {})
        counts = data.get("counts", {})
        total = sum(int(counts.get(bucket, 0)) for bucket in DIMENSION_BUCKETS)
        average = data.get("average")
        average_text = "n/a" if average is None else f"{average:.2f}"
        parts.append(f"{dimension}:avg={average_text},n={total}")
    return "; ".join(parts)
