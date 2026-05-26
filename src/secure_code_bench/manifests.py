from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Optional, Sequence

from secure_code_bench.models import BenchmarkSuite, RunOptions, RunResult


def manifest_path_for(output_path: Path) -> Path:
    return output_path.with_suffix(".manifest.json")


def write_run_manifest(
    output_path: Path,
    suite: BenchmarkSuite,
    models: Sequence[str],
    options: RunOptions,
    timeout: float,
    results: list[RunResult],
) -> Path:
    manifest_path = manifest_path_for(output_path)
    manifest = build_run_manifest(
        output_path=output_path,
        suite=suite,
        models=models,
        options=options,
        timeout=timeout,
        results=results,
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def build_run_manifest(
    output_path: Path,
    suite: BenchmarkSuite,
    models: Sequence[str],
    options: RunOptions,
    timeout: float,
    results: list[RunResult],
) -> dict[str, Any]:
    selected_case_count = _selected_case_count(suite, options.limit)
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "suite": {
            "name": suite.name,
            "path": str(suite.path) if suite.path is not None else None,
            "sha256": _suite_hash(suite.path),
            "case_count": len(suite.cases),
            "selected_case_count": selected_case_count,
            "rubric_quality_counts": _rubric_quality_counts(suite),
            "metadata": suite.metadata,
        },
        "models": list(models),
        "options": {
            **options.model_dump(),
            "timeout": timeout,
        },
        "routing": {
            "openai_prefix": "first-party-with-openrouter-fallback",
            "anthropic_prefix": "first-party-with-openrouter-fallback",
            "slash_ids": "openrouter",
            "openrouter_latest_aliases": "prefixed-with-tilde-on-request",
        },
        "judge": {
            "enabled": options.judge,
            "model": options.judge_model if options.judge else None,
        },
        "kev_generation": _kev_generation_metadata(suite),
        "git": _git_metadata(Path.cwd()),
        "output": {
            "path": str(output_path),
            "manifest_path": str(manifest_path_for(output_path)),
            "format": "jsonl",
            "record_count": len(results),
            "record_count_expected": len(models) * selected_case_count,
        },
    }


def _selected_case_count(suite: BenchmarkSuite, limit: Optional[int]) -> int:
    if limit is None:
        return len(suite.cases)
    return len(suite.cases[:limit])


def _suite_hash(path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _rubric_quality_counts(suite: BenchmarkSuite) -> dict[str, int]:
    counter = Counter(
        str(case.metadata.get("rubric_quality") or "unspecified") for case in suite.cases
    )
    return dict(sorted(counter.items()))


def _kev_generation_metadata(suite: BenchmarkSuite) -> dict[str, Any]:
    metadata = suite.metadata.get("kev_generation")
    return metadata if isinstance(metadata, dict) else {}


def _git_metadata(cwd: Path) -> dict[str, Any]:
    return {
        "commit": _git_output(cwd, "rev-parse", "HEAD"),
        "branch": _git_output(cwd, "rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(_git_output(cwd, "status", "--porcelain")),
    }


def _git_output(cwd: Path, *args: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()
