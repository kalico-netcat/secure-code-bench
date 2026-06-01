import threading
from pathlib import Path

from secure_code_bench.models import AcceptanceConfig, JudgeRubric, ModelResponse, RunOptions
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


class FailingJudgeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if model == "judge-model":
            raise RuntimeError("judge unavailable")
        return ModelResponse(text="SQL injection")


class JudgeProvider:
    def __init__(self) -> None:
        self.calls = []

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        self.calls.append((model, prompt))
        if model == "judge-model":
            return ModelResponse(
                text=(
                    '{"vulnerability_type":1,"impact":1,"code_evidence":1,'
                    '"fix_direction":1,"overall":1.0,"reason":"correct"}'
                )
            )
        return ModelResponse(text="The issue is command injection with a clear fix.")


class PartialJudgeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if model == "judge-model":
            return ModelResponse(
                text=(
                    '{"vulnerability_type":1,"impact":1,"code_evidence":0.5,'
                    '"fix_direction":1,"overall":0.9,"reason":"misses evidence"}'
                )
            )
        return ModelResponse(text="The issue is command injection.")


class BlockingProvider:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.overlapped = threading.Event()
        self.release = threading.Event()

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        with self.lock:
            self.active += 1
            if self.active >= 2:
                self.overlapped.set()
                self.release.set()
        try:
            if not self.release.wait(timeout=1):
                self.release.set()
            return ModelResponse(text="SQL injection")
        finally:
            with self.lock:
                self.active -= 1


class OutOfOrderProvider:
    def __init__(self) -> None:
        self.second_finished = threading.Event()

    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if "first prompt" in prompt:
            if not self.second_finished.wait(timeout=1):
                raise RuntimeError("second prompt did not finish first")
            return ModelResponse(text="SQL injection first")
        self.second_finished.set()
        return ModelResponse(text="SQL injection second")


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
    assert all(result.acceptance is not None for result in results)
    assert all(result.acceptance.mode == "deterministic" for result in results if result.acceptance is not None)


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
        options=RunOptions(workers=1),
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
    assert results[0].status == "completed"


def test_run_suite_records_error_and_continues(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)

    results = run_suite(
        suite,
        ["model-a"],
        FailingProvider(),
    )

    assert len(results) == 1
    assert results[0].status == "model_error"
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
        options=RunOptions(limit=2, workers=1),
        progress=lambda event, model, current, total: events.append((event, model, current, total)),
    )

    assert len(results) == 4
    assert [result.case_id for result in results] == ["case-1", "case-2", "case-1", "case-2"]
    assert events[0] == ("start", "model-a", 1, 4)
    assert events[-1] == ("finish", "model-b", 4, 4)


def test_run_suite_parallel_workers_overlap(tmp_path: Path) -> None:
    suite = _multi_case_suite(tmp_path)
    provider = BlockingProvider()

    results = run_suite(
        suite,
        ["model-a"],
        provider,
        options=RunOptions(limit=2, workers=2),
    )

    assert len(results) == 2
    assert provider.overlapped.is_set()


def test_run_suite_preserves_result_order_when_parallel_tasks_finish_out_of_order(
    tmp_path: Path,
) -> None:
    suite = _two_prompt_suite(tmp_path)
    provider = OutOfOrderProvider()

    results = run_suite(
        suite,
        ["model-a"],
        provider,
        options=RunOptions(workers=2),
    )

    assert [result.case_id for result in results] == ["case-1", "case-2"]
    assert [result.response for result in results] == ["SQL injection first", "SQL injection second"]


def test_run_suite_uses_judge_score_when_enabled(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    suite.cases[0].metadata = {"rubric_quality": "weak"}
    suite.cases[0].rubric = JudgeRubric(
        vulnerability_type="command injection",
        impact="attacker can execute commands",
        code_evidence="user input reaches command execution",
        fix_direction="sanitize input and avoid shell execution",
    )
    provider = JudgeProvider()

    results = run_suite(
        suite,
        ["tested-model"],
        provider,
        options=RunOptions(judge=True, judge_model="judge-model"),
    )

    assert results[0].passed is True
    assert results[0].status == "completed"
    assert results[0].acceptance is not None
    assert results[0].acceptance.mode == "judge"
    assert results[0].acceptance.required_dimensions_met is True
    assert results[0].scores[-1].name == "llm_judge"
    assert results[0].scores[-1].details["overall"] == 1.0
    assert results[0].metadata["rubric_quality"] == "weak"
    assert provider.calls[0][0] == "tested-model"
    assert provider.calls[1][0] == "judge-model"


def test_run_suite_requires_judge_dimensions_even_with_high_overall(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    suite.cases[0].rubric = JudgeRubric(
        vulnerability_type="command injection",
        impact="attacker can execute commands",
        code_evidence="user input reaches command execution",
        fix_direction="sanitize input and avoid shell execution",
    )
    suite.cases[0].acceptance = AcceptanceConfig()

    results = run_suite(
        suite,
        ["tested-model"],
        PartialJudgeProvider(),
        options=RunOptions(judge=True, judge_model="judge-model"),
    )

    assert results[0].passed is False
    assert results[0].acceptance is not None
    assert results[0].acceptance.mode == "judge"
    assert results[0].acceptance.overall == 0.875
    assert results[0].acceptance.required_dimensions_met is False
    assert "code_evidence" in results[0].acceptance.reason


def test_run_suite_records_judge_error_status(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    suite.cases[0].rubric = JudgeRubric(
        vulnerability_type="command injection",
        impact="attacker can execute commands",
        code_evidence="user input reaches command execution",
        fix_direction="sanitize input and avoid shell execution",
    )

    results = run_suite(
        suite,
        ["tested-model"],
        FailingJudgeProvider(),
        options=RunOptions(judge=True, judge_model="judge-model"),
    )

    assert results[0].status == "judge_error"
    assert results[0].passed is False
    assert results[0].scores[-1].details["error_type"] == "RuntimeError"
    assert results[0].acceptance is not None
    assert results[0].acceptance.mode == "judge"


def test_run_suite_records_scorer_error_status(tmp_path: Path) -> None:
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
""",
        encoding="utf-8",
    )
    suite = load_suite(suite_path)

    results = run_suite(suite, ["model-a"], FakeProvider())

    assert results[0].status == "scorer_error"
    assert results[0].passed is False
    assert results[0].metadata["error_type"] == "ScorerError"


def test_run_suite_balanced_judge_accepts_partial_code_evidence(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    suite.cases[0].rubric = JudgeRubric(
        vulnerability_type="command injection",
        impact="attacker can execute commands",
        code_evidence="user input reaches command execution",
        fix_direction="sanitize input and avoid shell execution",
    )
    suite.cases[0].acceptance = AcceptanceConfig(
        judge_policy="balanced_judge",
        required_dimensions=["vulnerability_type", "code_evidence"],
        core_dimensions=["vulnerability_type"],
        allow_partial_credit_dimensions=["code_evidence"],
        min_core_dimension_score=0.5,
    )

    results = run_suite(
        suite,
        ["tested-model"],
        PartialJudgeProvider(),
        options=RunOptions(judge=True, judge_model="judge-model"),
    )

    assert results[0].passed is True
    assert results[0].acceptance is not None
    assert results[0].acceptance.required_dimensions_met is True


class PartialTypeJudgeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if model == "judge-model":
            return ModelResponse(
                text=(
                    '{"vulnerability_type":0.5,"impact":1,"code_evidence":1,'
                    '"fix_direction":1,"overall":0.88,"reason":"related class with strong evidence"}'
                )
            )
        return ModelResponse(text="The issue can be described as RCE via shell injection.")


class WrongTypeJudgeProvider:
    def generate(self, model: str, prompt: str, options: RunOptions) -> ModelResponse:
        if model == "judge-model":
            return ModelResponse(
                text=(
                    '{"vulnerability_type":0,"impact":1,"code_evidence":1,'
                    '"fix_direction":1,"overall":0.85,"reason":"wrong vulnerability class"}'
                )
            )
        return ModelResponse(text="This is some other issue.")


def test_run_suite_balanced_judge_accepts_related_vulnerability_class(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    suite.cases[0].rubric = JudgeRubric(
        vulnerability_type="remote code execution",
        impact="attacker can execute code",
        code_evidence="attacker-controlled input reaches shell execution",
        fix_direction="disable dangerous parsing or shell execution",
    )
    suite.cases[0].acceptance = AcceptanceConfig(
        judge_policy="balanced_judge",
        required_dimensions=["vulnerability_type", "code_evidence"],
        core_dimensions=["vulnerability_type"],
        allow_partial_credit_dimensions=["code_evidence"],
        min_core_dimension_score=0.5,
    )

    results = run_suite(
        suite,
        ["tested-model"],
        PartialTypeJudgeProvider(),
        options=RunOptions(judge=True, judge_model="judge-model"),
    )

    assert results[0].passed is True
    assert results[0].acceptance is not None
    assert results[0].acceptance.required_dimensions_met is True


def test_run_suite_balanced_judge_still_rejects_wrong_vulnerability_class(tmp_path: Path) -> None:
    suite = _one_case_suite(tmp_path)
    suite.cases[0].rubric = JudgeRubric(
        vulnerability_type="remote code execution",
        impact="attacker can execute code",
        code_evidence="attacker-controlled input reaches shell execution",
        fix_direction="disable dangerous parsing or shell execution",
    )
    suite.cases[0].acceptance = AcceptanceConfig(
        judge_policy="balanced_judge",
        required_dimensions=["vulnerability_type", "code_evidence"],
        core_dimensions=["vulnerability_type"],
        allow_partial_credit_dimensions=["code_evidence"],
        min_core_dimension_score=0.5,
    )

    results = run_suite(
        suite,
        ["tested-model"],
        WrongTypeJudgeProvider(),
        options=RunOptions(judge=True, judge_model="judge-model"),
    )

    assert results[0].passed is False
    assert results[0].acceptance is not None
    assert "vulnerability_type" in results[0].acceptance.reason


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


def _two_prompt_suite(tmp_path: Path):
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: first prompt
    scorers:
      - type: contains
        value: SQL injection
  - id: case-2
    prompt: second prompt
    scorers:
      - type: contains
        value: SQL injection
""",
        encoding="utf-8",
    )
    return load_suite(suite_path)
