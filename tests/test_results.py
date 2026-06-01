import json
from pathlib import Path

from secure_code_bench.models import AcceptanceResult, RunResult, ScoreResult
from secure_code_bench.results import append_jsonl, reset_jsonl, write_jsonl


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
    assert record["status"] == "completed"
    assert record["acceptance"]["passed"] is True


def test_append_jsonl_preserves_completed_records(tmp_path: Path) -> None:
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

    reset_jsonl(output)
    append_jsonl(output, result)
    append_jsonl(output, result.model_copy(update={"case_id": "case-2"}))

    lines = output.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["case_id"] for line in lines] == ["case", "case-2"]
