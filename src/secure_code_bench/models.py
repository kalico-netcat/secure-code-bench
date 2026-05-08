from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScorerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["contains", "regex"]
    value: Optional[str] = None
    pattern: Optional[str] = None
    case_sensitive: bool = False


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    prompt: str
    code_files: list[Path] = Field(default_factory=list)
    scorers: list[ScorerConfig] = Field(default_factory=list)


class BenchmarkSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    cases: list[BenchmarkCase]
    path: Optional[Path] = None


class RunOptions(BaseModel):
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    retries: int = 0
    continue_on_error: bool = False
    limit: Optional[int] = None


class ScoreResult(BaseModel):
    name: str
    passed: bool
    details: dict[str, Any] = Field(default_factory=dict)


class ModelResponse(BaseModel):
    text: str
    raw: dict[str, Any] = Field(default_factory=dict)


class RunResult(BaseModel):
    suite: str
    case_id: str
    model: str
    prompt: str
    response: str
    scores: list[ScoreResult]
    passed: bool
    metadata: dict[str, Any] = Field(default_factory=dict)
