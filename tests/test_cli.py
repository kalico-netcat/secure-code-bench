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
        assert options.workers in {1, 4}
        return ModelResponse(text="SQL injection should use parameterized queries")


class InterruptingProvider:
    def __init__(self, timeout: float = 60) -> None:
        self.calls = 0

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        self.calls += 1
        if self.calls == 1:
            return ModelResponse(text="SQL injection")
        raise KeyboardInterrupt


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
            "--workers",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert "[1/1] openai/test-model :: case-1 ..." in result.output
    assert "[1/1] openai/test-model :: case-1 done" in result.output
    assert "1/1 completed passed" in result.output
    assert output_path.exists()
    manifest_path = tmp_path / "out.manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["models"] == ["openai/test-model"]
    assert manifest["options"]["timeout"] == 300.0
    assert manifest["options"]["workers"] == 1


def test_cli_run_writes_partial_results_on_interrupt(monkeypatch, tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: first
    scorers:
      - type: contains
        value: SQL injection
  - id: case-2
    prompt: second
    scorers:
      - type: contains
        value: SQL injection
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "out.jsonl"
    monkeypatch.setattr(
        cli,
        "RoutingProvider",
        lambda timeout=60: InterruptingProvider(timeout=timeout),
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(suite_path),
            "--model",
            "openai/test-model",
            "--output",
            str(output_path),
            "--workers",
            "1",
        ],
    )

    assert result.exit_code == 130
    assert "Interrupted. Wrote 1 completed result(s)" in result.output
    records = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert [record["case_id"] for record in records] == ["case-1"]
    manifest = json.loads((tmp_path / "out.manifest.json").read_text(encoding="utf-8"))
    assert manifest["output"]["record_count"] == 1
    assert manifest["output"]["record_count_expected"] == 2


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
    assert result.output.count("1/1 completed passed") == 2


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
    assert "[default: 4]" in result.output
    assert "[default: 600.0]" in result.output
    assert "--continue-on-error" not in result.output
    assert "--workers" in result.output
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


def test_cli_report_prints_aggregated_summary(tmp_path: Path) -> None:
    results_path = tmp_path / "results.jsonl"
    records = [
        {
            "suite": "KEV code samples (accepted, may-be-safe)",
            "case_id": "case-1",
            "model": "model-a",
            "status": "completed",
            "prompt": "prompt",
            "response": "response",
            "scores": [
                {
                    "name": "llm_judge",
                    "passed": True,
                    "details": {
                        "guardrails": [{}],
                        "dimensions": {
                            "vulnerability_type": 1,
                            "impact": 1,
                            "code_evidence": 1,
                            "fix_direction": 1,
                        },
                    },
                }
            ],
            "passed": True,
            "acceptance": {"mode": "judge", "passed": True, "reason": "correct"},
            "metadata": {
                "rubric_quality": "strong",
                "expected_response": {"is_vulnerable": True},
            },
        },
        {
            "suite": "KEV code samples (accepted, may-be-safe)",
            "case_id": "case-2",
            "model": "model-a",
            "status": "judge_error",
            "prompt": "prompt",
            "response": "response",
            "scores": [],
            "passed": False,
            "acceptance": {"mode": "judge", "passed": False, "reason": "judge unavailable"},
            "metadata": {"rubric_quality": "weak"},
        },
    ]
    results_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli.app, ["report", str(results_path)])

    assert result.exit_code == 0
    assert "Total records: 2" in result.output
    assert "By model" in result.output
    assert "By status" in result.output
    assert "guardrails=1" in result.output
    assert "failures[judge_error=1, passed=1]" in result.output
    assert "dims[vulnerability_type:avg=1.00,n=1" in result.output


def test_cli_report_writes_html(monkeypatch, tmp_path: Path) -> None:
    results_path = tmp_path / "results.jsonl"
    html_path = tmp_path / "report.html"
    results_path.write_text(
        json.dumps(
            {
                "suite": "suite",
                "case_id": "case",
                "model": "model-a",
                "status": "completed",
                "prompt": "prompt",
                "response": "response",
                "scores": [],
                "passed": True,
                "metadata": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_write_html_report(report_data, output_path):
        output_path.write_text("<html>ok</html>", encoding="utf-8")
        return output_path

    monkeypatch.setattr(cli, "write_html_report", fake_write_html_report)

    result = CliRunner().invoke(cli.app, ["report", str(results_path), "--html", str(html_path)])

    assert result.exit_code == 0
    assert html_path.read_text(encoding="utf-8") == "<html>ok</html>"
    assert "Wrote HTML report" in result.output


def test_cli_report_missing_plotly_errors(monkeypatch, tmp_path: Path) -> None:
    results_path = tmp_path / "results.jsonl"
    results_path.write_text("", encoding="utf-8")

    def fake_write_html_report(report_data, output_path):
        raise cli.HtmlReportError('Plotly is required. Install it with: python -m pip install -e ".[report]"')

    monkeypatch.setattr(cli, "write_html_report", fake_write_html_report)

    result = CliRunner().invoke(
        cli.app,
        ["report", str(results_path), "--html", str(tmp_path / "report.html")],
    )

    assert result.exit_code == 1
    assert 'python -m pip install -e ".[report]"' in result.output
