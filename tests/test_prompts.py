from pathlib import Path

import pytest

from secure_code_bench.prompts import PromptRenderError, render_prompt
from secure_code_bench.suites import load_suite


def test_render_prompt_injects_declared_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "Review this:\\n{file:sample.py}"
    code_files:
      - sample.py
    scorers: []
""",
        encoding="utf-8",
    )

    suite = load_suite(suite_path)
    rendered = render_prompt(suite, suite.cases[0])

    assert "```python" in rendered
    assert "print('hello')" in rendered


def test_render_prompt_rejects_undeclared_file(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "{file:sample.py}"
    code_files:
      - other.py
    scorers: []
""",
        encoding="utf-8",
    )

    suite = load_suite(suite_path)

    with pytest.raises(PromptRenderError):
        render_prompt(suite, suite.cases[0])


def test_render_prompt_supports_code_file_indexes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("print('indexed')\n", encoding="utf-8")
    suite_path = tmp_path / "suite.yml"
    suite_path.write_text(
        """
name: test
cases:
  - id: case-1
    prompt: "Review this:\\n{file:0}"
    code_files:
      - sample.py
    scorers: []
""",
        encoding="utf-8",
    )

    suite = load_suite(suite_path)
    rendered = render_prompt(suite, suite.cases[0])

    assert "print('indexed')" in rendered
