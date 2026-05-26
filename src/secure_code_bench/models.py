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


class AcceptanceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    judge_policy: Literal["strict_dimensions", "balanced_judge"] = "strict_dimensions"
    min_overall: float = 0.75
    required_dimensions: list[str] = Field(default_factory=lambda: ["vulnerability_type", "code_evidence"])
    core_dimensions: list[str] = Field(default_factory=list)
    allow_partial_credit_dimensions: list[str] = Field(default_factory=list)
    min_core_dimension_score: float = 1.0
    min_dimension_score: float = 1.0


class JudgeRubric(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerability_type: str
    impact: str
    code_evidence: str
    fix_direction: str
    notes: Optional[str] = None


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    prompt: str
    code_files: list[Path] = Field(default_factory=list)
    scorers: list[ScorerConfig] = Field(default_factory=list)
    acceptance: Optional[AcceptanceConfig] = None
    rubric: Optional[JudgeRubric] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BenchmarkSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    cases: list[BenchmarkCase]
    path: Optional[Path] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunOptions(BaseModel):
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    retries: int = 0
    limit: Optional[int] = None
    judge: bool = False
    judge_model: str = "openai/gpt-mini-latest"


class ScoreResult(BaseModel):
    name: str
    passed: bool
    score: Optional[float] = None
    max_score: Optional[float] = None
    details: dict[str, Any] = Field(default_factory=dict)


class AcceptanceResult(BaseModel):
    mode: Literal["deterministic", "judge"]
    passed: bool
    overall: Optional[float] = None
    required_dimensions_met: Optional[bool] = None
    reason: str = ""


class ModelResponse(BaseModel):
    text: str
    raw: dict[str, Any] = Field(default_factory=dict)


class RunResult(BaseModel):
    suite: str
    case_id: str
    model: str
    status: Literal["completed", "model_error", "judge_error", "scorer_error"] = "completed"
    prompt: str
    response: str
    scores: list[ScoreResult]
    passed: bool
    acceptance: Optional[AcceptanceResult] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
