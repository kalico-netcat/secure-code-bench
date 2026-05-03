from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from secure_code_bench.models import RunResult


def write_jsonl(path: Union[str, Path], results: list[RunResult]) -> Path:
    output_path = Path(path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        for result in results:
            file.write(json.dumps(result.model_dump(), default=str) + "\n")
    return output_path
