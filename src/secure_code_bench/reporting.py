from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any, Iterable, Iterator


ReportRow = dict[str, Any]


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
    }


def _format_summary(name: str, summary: dict[str, Any]) -> str:
    pass_rate = summary["pass_rate"]
    pass_rate_text = "n/a" if pass_rate is None else f"{pass_rate:.1%}"
    status_text = ", ".join(
        f"{status}={count}" for status, count in summary["status_counts"].items()
    )
    return (
        f"{name}: records={summary['records']} completed={summary['completed']} "
        f"passed={summary['passed']} failed={summary['failed']} errors={summary['errors']} "
        f"pass_rate={pass_rate_text} guardrails={summary['guardrail_count']} "
        f"statuses[{status_text}]"
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
