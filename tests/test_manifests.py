import json
from pathlib import Path

from secure_code_bench.manifests import build_run_manifest, manifest_path_for, write_run_manifest
from secure_code_bench.models import AcceptanceResult, RunOptions, RunResult, ScoreResult
from secure_code_bench.suites import load_suite


def test_write_run_manifest_records_run_provenance(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("print('ok')\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
metadata:
  kev_generation:
    prompt_assumption: may-be-safe
    randomize: true
    seed: 42
cases:
  - id: case-1
    prompt: "{file:sample.py}"
    code_files:
      - sample.py
    scorers: []
    metadata:
      rubric_quality: strong
  - id: case-2
    prompt: "No file"
    scorers: []
    metadata:
      rubric_quality: weak
""",
        encoding="utf-8",
    )
    suite = load_suite(suite_path)
    output_path = tmp_path / "out.jsonl"
    result = RunResult(
        suite="test",
        case_id="case-1",
        model="model-a",
        prompt="prompt",
        response="response",
        scores=[ScoreResult(name="contains", passed=True)],
        passed=True,
        acceptance=AcceptanceResult(
            mode="deterministic",
            passed=True,
            overall=1.0,
            reason="ok",
        ),
    )

    manifest_path = write_run_manifest(
        output_path=output_path,
        suite=suite,
        models=["model-a"],
        options=RunOptions(limit=1, judge=True, judge_model="judge-model", retries=2),
        timeout=300,
        results=[result],
    )

    assert manifest_path == tmp_path / "out.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["suite"]["name"] == "test"
    assert manifest["suite"]["sha256"]
    assert manifest["suite"]["case_count"] == 2
    assert manifest["suite"]["selected_case_count"] == 1
    assert manifest["suite"]["rubric_quality_counts"] == {"strong": 1, "weak": 1}
    assert manifest["models"] == ["model-a"]
    assert manifest["options"]["timeout"] == 300
    assert manifest["options"]["judge_model"] == "judge-model"
    assert manifest["judge"] == {"enabled": True, "model": "judge-model"}
    assert manifest["kev_generation"]["seed"] == 42
    assert manifest["output"]["record_count_expected"] == 1


def test_build_run_manifest_handles_suites_without_path() -> None:
    from secure_code_bench.models import BenchmarkCase, BenchmarkSuite

    suite = BenchmarkSuite(name="memory", cases=[BenchmarkCase(id="case", prompt="prompt")])

    manifest = build_run_manifest(
        output_path=Path("out.jsonl"),
        suite=suite,
        models=["model-a", "model-b"],
        options=RunOptions(),
        timeout=600,
        results=[],
    )

    assert manifest["suite"]["path"] is None
    assert manifest["suite"]["sha256"] is None
    assert manifest["output"]["record_count_expected"] == 2


def test_manifest_path_replaces_jsonl_suffix() -> None:
    assert manifest_path_for(Path("results/kev.jsonl")) == Path("results/kev.manifest.json")
