import json
from pathlib import Path

from secure_code_bench.models import RunResult, ScoreResult
from secure_code_bench.results import write_jsonl


def test_write_jsonl_writes_one_record_per_result(tmp_path: Path) -> None:
    output = tmp_path / "results.jsonl"
    result = RunResult(
        suite="suite",
        case_id="case",
        model="model",
        prompt="prompt",
        response="response",
        scores=[ScoreResult(name="contains", passed=True)],
        passed=True,
    )

    write_jsonl(output, [result])

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["case_id"] == "case"

