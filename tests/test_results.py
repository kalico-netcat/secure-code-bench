import json
from pathlib import Path

from secure_code_bench.models import AcceptanceResult, RunResult, ScoreResult
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
        acceptance=AcceptanceResult(
            mode="deterministic",
            passed=True,
            overall=1.0,
            reason="1/1 deterministic scorers passed.",
        ),
    )

    write_jsonl(output, [result])

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["case_id"] == "case"
    assert record["acceptance"]["passed"] is True
