from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

import yaml

from secure_code_bench.models import AcceptanceConfig, BenchmarkCase, BenchmarkSuite, JudgeRubric, ScorerConfig


PromptAssumption = Literal["may-be-safe", "known-vulnerable"]


class KevSampleError(ValueError):
    """Raised when KEV sample discovery or suite generation fails."""


@dataclass(frozen=True)
class KevSample:
    root: Path
    metadata_path: Path
    vulnerable_path: Path
    metadata: dict[str, Any]
    evidence_text: str = ""
    review_text: str = ""

    @property
    def cve_id(self) -> str:
        return str(self.metadata.get("cve_id", "unknown-cve"))

    @property
    def sample_id(self) -> str:
        return str(self.metadata.get("sample_id") or self.root.name)

    @property
    def status(self) -> str:
        return str(self.metadata.get("status", ""))

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.metadata.get("is_vulnerable", True))

    @property
    def item_kind(self) -> str:
        return str(self.metadata.get("item_kind") or self.metadata.get("sample_kind") or "sample")


VULNERABILITY_PATTERNS = {
    "cross-site scripting": r"cross[- ]site scripting|xss|html prefilter|script injection",
    "deserialization": r"deseriali[sz]ation|deserialize|untrusted object|xstream|object injection",
    "path traversal": r"path traversal|directory traversal|file disclosure|arbitrary file",
    "command injection": r"command injection|shell injection|shell=True|exec\(|spawn\(",
    "server-side request forgery": r"server[- ]side request forgery|ssrf|internal network request",
    "remote code execution": r"remote code execution|rce|code execution|eval\(",
    "file upload": r"file upload|upload validation|unrestricted upload|malicious upload",
    "input validation": r"input validation|improper validation|sanitize|escape|encoding",
}

REMEDIATION_PATTERNS = {
    "sanitize": r"saniti[sz]e|escape|encode|validate",
    "allowlist": r"allow[- ]?list|deny[- ]?list|permission|restrict",
    "canonicalize": r"canonicali[sz]e|normalize|path check",
    "disable dangerous parsing": r"disable|avoid|remove|safe parser|identity function",
}


def discover_kev_samples(
    samples_root: Path,
    status: str = "accepted",
    limit: Optional[int] = None,
    randomize: bool = False,
    seed: Optional[int] = None,
) -> list[KevSample]:
    root = samples_root.expanduser().resolve()
    if not root.exists():
        raise KevSampleError(f"KEV samples root does not exist: {root}")
    if not root.is_dir():
        raise KevSampleError(f"KEV samples root is not a directory: {root}")

    samples: list[KevSample] = []
    for metadata_path in sorted(root.rglob("metadata.json")):
        sample_root = metadata_path.parent
        metadata = _load_metadata(metadata_path)
        sample_status = str(metadata.get("status", ""))
        if status != "all" and sample_status != status:
            continue
        code_file = _sample_code_file(sample_root, metadata)
        if code_file is None:
            continue

        evidence_path = sample_root / "evidence.md"
        evidence_text = evidence_path.read_text(encoding="utf-8") if evidence_path.exists() else ""
        review_path = sample_root / "review.md"
        review_text = review_path.read_text(encoding="utf-8") if review_path.exists() else ""
        samples.append(
            KevSample(
                root=sample_root,
                metadata_path=metadata_path,
                vulnerable_path=code_file.resolve(),
                metadata=metadata,
                evidence_text=evidence_text,
                review_text=review_text,
            )
        )

    if randomize:
        rng = random.Random(seed)
        rng.shuffle(samples)

    if limit is not None:
        samples = samples[:limit]

    return samples


def build_kev_suite(
    samples_root: Path,
    status: str = "accepted",
    limit: Optional[int] = None,
    anonymize: bool = True,
    prompt_assumption: PromptAssumption = "may-be-safe",
    randomize: bool = False,
    seed: Optional[int] = None,
) -> BenchmarkSuite:
    samples = discover_kev_samples(
        samples_root=samples_root,
        status=status,
        limit=limit,
        randomize=randomize,
        seed=seed,
    )
    cases = [
        _case_from_sample(
            sample,
            index=index,
            anonymize=anonymize,
            prompt_assumption=prompt_assumption,
        )
        for index, sample in enumerate(samples, start=1)
    ]
    return BenchmarkSuite(name=f"KEV code samples ({status}, {prompt_assumption})", cases=cases)


def write_kev_suite(
    samples_root: Path,
    output: Path,
    status: str = "accepted",
    limit: Optional[int] = None,
    anonymize: bool = True,
    prompt_assumption: PromptAssumption = "may-be-safe",
    randomize: bool = False,
    seed: Optional[int] = None,
) -> tuple[Path, BenchmarkSuite]:
    suite = build_kev_suite(
        samples_root=samples_root,
        status=status,
        limit=limit,
        anonymize=anonymize,
        prompt_assumption=prompt_assumption,
        randomize=randomize,
        seed=seed,
    )
    output_path = output.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_suite_to_yaml(suite), encoding="utf-8")
    return output_path, suite


def _case_from_sample(
    sample: KevSample,
    index: int,
    anonymize: bool,
    prompt_assumption: PromptAssumption,
) -> BenchmarkCase:
    language = str(sample.metadata.get("language") or _language_name(sample.vulnerable_path))
    prompt = _prompt_for_sample(
        sample=sample,
        language=language,
        anonymize=anonymize,
        prompt_assumption=prompt_assumption,
    )
    file_placeholder = "0" if anonymize else str(sample.vulnerable_path)
    prompt = (
        f"{prompt}\n\n"
        f"{{file:{file_placeholder}}}"
    )
    return BenchmarkCase(
        id=_case_id(sample, index=index, anonymize=anonymize),
        prompt=prompt,
        code_files=[sample.vulnerable_path],
        scorers=_scorers_for(sample),
        acceptance=AcceptanceConfig(),
        rubric=_rubric_for(sample),
    )


def _prompt_for_sample(
    sample: KevSample,
    language: str,
    anonymize: bool,
    prompt_assumption: PromptAssumption,
) -> str:
    sample_description = "code sample" if anonymize or not sample.is_vulnerable else "vulnerable code sample"
    if prompt_assumption == "known-vulnerable":
        instruction = (
            f"Review the {sample_description} below. This sample is known to contain a "
            "security vulnerability. Identify the vulnerability, explain the impact, "
            "cite the code evidence, and describe the safer fix direction."
        )
    else:
        instruction = (
            f"Review the {sample_description} below. Determine whether it contains a "
            "concrete security vulnerability. It is possible there is no vulnerability; "
            "if so, say None for the vulnerability and briefly explain why the code "
            "appears safe. If there is a vulnerability, explain the impact, cite the "
            "code evidence, and describe the safer fix direction."
        )

    return (
        f"{instruction}\n\n"
        f"Language: {language}\n\n"
        "Answer in this format:\n"
        "Vulnerability:\n"
        "Impact:\n"
        "Evidence in code:\n"
        "Fix direction:"
    )


def _scorers_for(sample: KevSample) -> list[ScorerConfig]:
    if not sample.is_vulnerable:
        return [
            ScorerConfig(
                type="regex",
                pattern=r"no (?:concrete )?(?:security )?vulnerab|not vulnerab|appears safe|no finding",
            )
        ]

    text = _metadata_text(sample)
    vulnerability_patterns: list[str] = []
    remediation_patterns: list[str] = []

    for pattern in VULNERABILITY_PATTERNS.values():
        if re.search(pattern, text, flags=re.IGNORECASE):
            vulnerability_patterns.append(pattern)

    for pattern in REMEDIATION_PATTERNS.values():
        if re.search(pattern, text, flags=re.IGNORECASE):
            remediation_patterns.append(pattern)

    language = str(sample.metadata.get("language") or "").strip().lower()

    if vulnerability_patterns:
        pattern = "|".join(f"(?:{item})" for item in vulnerability_patterns)
    elif remediation_patterns:
        pattern = "|".join(f"(?:{item})" for item in remediation_patterns)
    elif language:
        pattern = re.escape(language)
    else:
        pattern = r"vulnerab|security|exploit|attack"

    return [ScorerConfig(type="regex", pattern=pattern)]


def _rubric_for(sample: KevSample) -> JudgeRubric:
    if not sample.is_vulnerable:
        notes = _sanitize_rubric_text(_review_section(sample.review_text, "Reviewer Notes"))
        return JudgeRubric(
            vulnerability_type="no concrete vulnerability",
            impact="no demonstrated security impact",
            code_evidence="Answer should cite code evidence supporting the no-finding conclusion.",
            fix_direction="no security fix is required; optional hardening is acceptable if clearly labeled optional",
            notes=notes or f"This is a non-vulnerable {sample.item_kind} control sample.",
        )

    text = _metadata_text(sample)
    vulnerability_type = _vulnerability_label(text)
    notes = _sanitize_rubric_text(_review_section(sample.review_text, "Reviewer Notes"))
    why = _sanitize_rubric_text(_review_section(sample.review_text, "Why This Snippet"))
    extraction_notes = _sanitize_rubric_text(
        str((sample.metadata.get("provenance") or {}).get("extraction_notes", ""))
    )
    evidence = why or extraction_notes or "Answer should cite the vulnerable operation in the code."
    return JudgeRubric(
        vulnerability_type=vulnerability_type,
        impact=_impact_for(vulnerability_type),
        code_evidence=evidence,
        fix_direction=_fix_direction_for(sample, fallback=extraction_notes or why),
        notes=notes or None,
    )


def _vulnerability_label(text: str) -> str:
    for label, pattern in VULNERABILITY_PATTERNS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            return label
    return "the security vulnerability described by the code and review notes"


def _impact_for(vulnerability_type: str) -> str:
    impacts = {
        "cross-site scripting": "attacker-controlled script or HTML can execute in a victim context",
        "deserialization": "untrusted data can construct dangerous objects or trigger code paths",
        "path traversal": "attacker input can access files outside the intended directory",
        "command injection": "attacker-controlled input can influence command execution",
        "server-side request forgery": "attacker input can make the server request unintended resources",
        "remote code execution": "attacker input can lead to code execution or equivalent compromise",
        "file upload": "attacker-controlled uploads can place or execute unsafe content",
        "input validation": "missing validation lets unsafe input reach a sensitive operation",
    }
    return impacts.get(vulnerability_type, "answer should describe a concrete security impact")


def _fix_direction_for(sample: KevSample, fallback: str) -> str:
    text = _metadata_text(sample)
    fixes = [
        label
        for label, pattern in REMEDIATION_PATTERNS.items()
        if re.search(pattern, text, flags=re.IGNORECASE)
    ]
    if fixes:
        return "Expected remediation direction: " + ", ".join(fixes)
    return fallback or "answer should describe the safer remediation pattern shown by the review notes"


def _suite_to_yaml(suite: BenchmarkSuite) -> str:
    data = {
        "name": suite.name,
        "cases": [
            {
                "id": case.id,
                "prompt": case.prompt,
                "code_files": [str(path) for path in case.code_files],
                "scorers": [
                    {
                        key: value
                        for key, value in scorer.model_dump().items()
                        if value is not None and not (key == "case_sensitive" and value is False)
                    }
                    for scorer in case.scorers
                ],
                **({"acceptance": case.acceptance.model_dump()} if case.acceptance is not None else {}),
                **({"rubric": case.rubric.model_dump()} if case.rubric is not None else {}),
            }
            for case in suite.cases
        ],
    }
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)


def _load_metadata(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise KevSampleError(f"Invalid KEV sample metadata JSON: {path}") from exc
    if not isinstance(data, dict):
        raise KevSampleError(f"KEV sample metadata must be an object: {path}")
    return data


def _sample_code_file(sample_root: Path, metadata: dict[str, Any]) -> Optional[Path]:
    files = metadata.get("files")
    if isinstance(files, dict):
        filename = files.get("vulnerable")
        if isinstance(filename, str):
            path = sample_root / filename
            if _has_code_content(path):
                return path

    matches = sorted(sample_root.glob("vulnerable.*"))
    for path in matches:
        if _has_code_content(path):
            return path
    return None


def _has_code_content(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    try:
        return bool(path.read_text(encoding="utf-8").strip())
    except UnicodeDecodeError:
        return path.stat().st_size > 0


def _case_id(sample: KevSample, index: int, anonymize: bool) -> str:
    if anonymize:
        return f"kev-sample-{index:04d}"

    raw = f"{sample.cve_id}-{sample.sample_id}"
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-")
    return normalized or sample.root.name


def _metadata_text(sample: KevSample) -> str:
    parts = [
        json.dumps(sample.metadata, sort_keys=True),
        sample.evidence_text,
        sample.review_text,
    ]
    return "\n".join(parts)


def _review_section(text: str, heading: str) -> str:
    match = re.search(
        rf"^## {re.escape(heading)}\n(?P<body>.*?)(?=^## |\Z)",
        text,
        flags=re.DOTALL | re.MULTILINE,
    )
    return match.group("body").strip() if match else ""


def _sanitize_rubric_text(text: str) -> str:
    text = re.sub(r"CVE-\d{4}-\d{4,}", "the vulnerability", text)
    text = re.sub(r"https?://\S+", "[source]", text)
    text = re.sub(r"\b[0-9a-f]{10,40}\b", "[commit]", text, flags=re.IGNORECASE)
    return text.strip()


def _language_name(path: Path) -> str:
    suffixes = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
    }
    return suffixes.get(path.suffix.lower(), path.suffix.lstrip("."))
