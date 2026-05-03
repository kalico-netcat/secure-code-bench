from __future__ import annotations

from pathlib import Path
from typing import Union

import yaml
from pydantic import ValidationError

from secure_code_bench.models import BenchmarkSuite


class SuiteLoadError(ValueError):
    """Raised when a benchmark suite cannot be loaded or validated."""


def load_suite(path: Union[str, Path]) -> BenchmarkSuite:
    suite_path = Path(path).expanduser().resolve()
    try:
        raw = yaml.safe_load(suite_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SuiteLoadError(f"Suite file not found: {suite_path}") from exc
    except yaml.YAMLError as exc:
        raise SuiteLoadError(f"Invalid YAML in suite file {suite_path}: {exc}") from exc

    if raw is None:
        raise SuiteLoadError(f"Suite file is empty: {suite_path}")

    try:
        suite = BenchmarkSuite.model_validate(raw)
    except ValidationError as exc:
        raise SuiteLoadError(f"Invalid suite file {suite_path}: {exc}") from exc

    return suite.model_copy(update={"path": suite_path})
