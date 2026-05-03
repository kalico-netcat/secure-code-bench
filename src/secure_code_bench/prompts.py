from __future__ import annotations

import re
from pathlib import Path

from secure_code_bench.models import BenchmarkCase, BenchmarkSuite

FILE_PLACEHOLDER = re.compile(r"\{file:([^}]+)\}")


class PromptRenderError(ValueError):
    """Raised when prompt template rendering fails."""


def render_prompt(suite: BenchmarkSuite, case: BenchmarkCase) -> str:
    suite_dir = suite.path.parent if suite.path else Path.cwd()
    declared_files = {str(path) for path in case.code_files}

    def replace(match: re.Match[str]) -> str:
        raw_path = match.group(1).strip()
        if declared_files and raw_path not in declared_files:
            raise PromptRenderError(
                f"Case {case.id!r} references {raw_path!r}, but it is not listed in code_files."
            )

        file_path = (suite_dir / raw_path).resolve()
        try:
            content = file_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise PromptRenderError(f"Code file not found for case {case.id!r}: {file_path}") from exc

        return f"```{_language_for(file_path)}\n{content.rstrip()}\n```"

    return FILE_PLACEHOLDER.sub(replace, case.prompt)


def _language_for(path: Path) -> str:
    suffix_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".rb": "ruby",
        ".php": "php",
    }
    return suffix_map.get(path.suffix.lower(), "")

