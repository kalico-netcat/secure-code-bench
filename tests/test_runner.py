from pathlib import Path

from secure_code_bench.models import ModelResponse, RunOptions
from secure_code_bench.runner import run_suite
from secure_code_bench.suites import load_suite


class FakeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        return ModelResponse(text=f"{model}: SQL injection; use parameterized queries")


def test_run_suite_scores_each_model_and_case(tmp_path: Path) -> None:
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
      - type: regex
        pattern: parameterized
""",
        encoding="utf-8",
    )

    suite = load_suite(suite_path)
    results = run_suite(suite, ["model-a", "model-b"], FakeProvider())

    assert len(results) == 2
    assert all(result.passed for result in results)


def test_run_suite_reports_progress_events(tmp_path: Path) -> None:
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
    events = []

    suite = load_suite(suite_path)
    run_suite(
        suite,
        ["model-a"],
        FakeProvider(),
        progress=lambda event, model, current, total: events.append((event, model, current, total)),
    )

    assert events == [
        ("start", "model-a", 1, 1),
        ("finish", "model-a", 1, 1),
    ]
