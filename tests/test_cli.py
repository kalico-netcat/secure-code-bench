from pathlib import Path

from typer.testing import CliRunner

from secure_code_bench import cli
from secure_code_bench.models import ModelResponse, RunOptions


class FakeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
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
    monkeypatch.setattr(cli, "OpenRouterProvider", lambda: FakeProvider())

    result = CliRunner().invoke(
        cli.app,
        ["run", str(suite_path), "--model", "openai/test-model", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert "[1/1] openai/test-model :: case-1 ..." in result.output
    assert "done" in result.output
    assert "1/1 passed" in result.output
    assert output_path.exists()
