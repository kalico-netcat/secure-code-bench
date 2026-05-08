from pathlib import Path

from secure_code_bench.models import ModelResponse, RunOptions
from secure_code_bench.runner import run_suite
from secure_code_bench.suites import load_suite


class FakeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        return ModelResponse(text=f"{model}: SQL injection; use parameterized queries")


class FlakyProvider:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("temporary failure")
        return ModelResponse(text="SQL injection")


class FailingProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        raise RuntimeError("permanent failure")


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


def test_run_suite_retries_failed_model_call(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    provider = FlakyProvider()

    results = run_suite(
        suite,
        ["model-a"],
        provider,
        options=RunOptions(retries=1),
    )

    assert provider.calls == 2
    assert results[0].passed is True


def test_run_suite_can_continue_on_error(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)

    results = run_suite(
        suite,
        ["model-a"],
        FailingProvider(),
        options=RunOptions(continue_on_error=True),
    )

    assert len(results) == 1
    assert results[0].passed is False
    assert results[0].response == ""
    assert results[0].metadata["error_type"] == "RuntimeError"
    assert "permanent failure" in results[0].metadata["error"]


def test_run_suite_limits_cases_per_model(tmp_path: Path) -> None:
    suite = _multi_case_suite(tmp_path)
    events = []

    results = run_suite(
        suite,
        ["model-a", "model-b"],
        FakeProvider(),
        options=RunOptions(limit=2),
        progress=lambda event, model, current, total: events.append((event, model, current, total)),
    )

    assert len(results) == 4
    assert [result.case_id for result in results] == ["case-1", "case-2", "case-1", "case-2"]
    assert events[0] == ("start", "model-a", 1, 4)
    assert events[-1] == ("finish", "model-b", 4, 4)


def _one_case_suite(tmp_path: Path):
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
    return load_suite(suite_path)


def _multi_case_suite(tmp_path: Path):
    for index in range(1, 4):
        (tmp_path / f"sample{index}.py").write_text("query = user_input\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "{file:sample1.py}"
    code_files:
      - sample1.py
    scorers:
      - type: contains
        value: SQL injection
  - id: case-2
    prompt: "{file:sample2.py}"
    code_files:
      - sample2.py
    scorers:
      - type: contains
        value: SQL injection
  - id: case-3
    prompt: "{file:sample3.py}"
    code_files:
      - sample3.py
    scorers:
      - type: contains
        value: SQL injection
""",
        encoding="utf-8",
    )
    return load_suite(suite_path)
