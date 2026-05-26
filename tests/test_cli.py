import json
from pathlib import Path

from typer.testing import CliRunner

from secure_code_bench import cli
from secure_code_bench.models import ModelResponse, RunOptions


class FakeProvider:
    def __init__(self, timeout: float = 60) -> None:
        self.timeout = timeout

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        assert options.retries == 2
        assert options.limit == 1
        return ModelResponse(text="SQL injection should use parameterized queries")


def test_cli_run_writes_jsonl(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("query = user_input\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "{file:sample.py}"
    code_files:
      - sample.py
    scorers:
      - type: contains
        value: SQL injection
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "out.jsonl"
    monkeypatch.setattr(cli, "RoutingProvider", lambda timeout=60: FakeProvider(timeout=timeout))

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(suite_path),
            "--model",
            "openai/test-model",
            "--output",
            str(output_path),
            "--timeout",
            "300",
            "--retries",
            "2",
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert "[1/1] openai/test-model :: case-1 ..." in result.output
    assert "done" in result.output
    assert "1/1 passed" in result.output
    assert output_path.exists()
    manifest_path = tmp_path / "out.manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["models"] == ["openai/test-model"]
    assert manifest["options"]["timeout"] == 300.0


def test_cli_run_writes_multiple_jsonl(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("query = user_input\n", encoding="utf-8")
    suite_a = tmp_path / "suite-a.yml"
    suite_b = tmp_path / "suite-b.yml"
    for path, case_id in ((suite_a, "case-a"), (suite_b, "case-b")):
        path.write_text(
            f"""
name: test
cases:
  - id: {case_id}
    prompt: "{{file:sample.py}}"
    code_files:
      - sample.py
    scorers:
      - type: contains
        value: SQL injection
""",
            encoding="utf-8",
        )
    out_a = tmp_path / "a.jsonl"
    out_b = tmp_path / "b.jsonl"
    monkeypatch.setattr(cli, "RoutingProvider", lambda timeout=60: FakeProvider(timeout=timeout))

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(suite_a),
            str(suite_b),
            "--model",
            "openai/test-model",
            "--output",
            str(out_a),
            "--output",
            str(out_b),
            "--retries",
            "2",
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert out_a.exists()
    assert out_b.exists()
    assert (tmp_path / "a.manifest.json").exists()
    assert (tmp_path / "b.manifest.json").exists()
    assert "case-a" in out_a.read_text()
    assert "case-b" in out_b.read_text()
    assert result.output.count("1/1 passed") == 2


def test_cli_run_mismatched_outputs_errors(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("x\n", encoding="utf-8")
    suite_a = tmp_path / "a.yml"
    suite_b = tmp_path / "b.yml"
    for path in (suite_a, suite_b):
        path.write_text(
            """
name: test
cases:
  - id: c
    prompt: "{file:sample.py}"
    code_files:
      - sample.py
    scorers:
      - type: contains
        value: SQL injection
""",
            encoding="utf-8",
        )
    monkeypatch.setattr(cli, "RoutingProvider", lambda timeout=60: FakeProvider(timeout=timeout))

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(suite_a),
            str(suite_b),
            "--model",
            "openai/test-model",
            "--output",
            str(tmp_path / "only-one.jsonl"),
            "--limit",
            "1",
            "--retries",
            "2",
        ],
    )

    assert result.exit_code != 0
    assert "must match suite count" in result.output


def test_cli_run_help_shows_defaults() -> None:
    result = CliRunner().invoke(cli.app, ["run", "--help"])

    assert result.exit_code == 0
    assert "[default: 3]" in result.output
    assert "[default: 600.0]" in result.output
    assert "--continue-on-error" not in result.output
    assert "--judge" in result.output
    assert "openai/gpt-mini-latest" in result.output
    kev_help = CliRunner().invoke(cli.app, ["kev-suite", "--help"], env={"COLUMNS": "200"}).output
    assert "--prompt-assumption" in kev_help
    assert "--ordered" in kev_help


def test_cli_validate_reports_success(tmp_path: Path) -> None:
    (tmp_path / "sample.py").write_text("safe()\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "{file:sample.py}"
    code_files:
      - sample.py
    scorers: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli.app, ["validate", str(suite_path)])

    assert result.exit_code == 0
    assert "Validation passed" in result.output


def test_cli_validate_exits_nonzero_for_errors(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "{file:missing.py}"
    code_files:
      - missing.py
    scorers: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli.app, ["validate", str(suite_path)])

    assert result.exit_code == 1
    assert "ERROR [missing_code_file]" in result.output
    assert "Validation completed with" in result.output
