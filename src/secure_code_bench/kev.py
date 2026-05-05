from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from secure_code_bench.models import BenchmarkCase, BenchmarkSuite, ScorerConfig


class KevSampleError(ValueError):
    """Raised when KEV sample discovery or suite generation fails."""


@dataclass(frozen=True)
class KevSample:
    root: Path
    metadata_path: Path
    vulnerable_path: Path
    metadata: dict[str, Any]
    evidence_text: str = ""

    @property
    def cve_id(self) -> str:
        return str(self.metadata.get("cve_id", "unknown-cve"))

    @property
    def sample_id(self) -> str:
        return str(self.metadata.get("sample_id") or self.root.name)

    @property
    def status(self) -> str:
        return str(self.metadata.get("status", ""))


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
) -> list[KevSample]:
    root = samples_root.expanduser().resolve()
    if not root.exists():
        raise KevSampleError(f"KEV samples root does not exist: {root}")
    if not root.is_dir():
        raise KevSampleError(f"KEV samples root is not a directory: {root}")

    samples: list[KevSample] = []
    for metadata_path in sorted(root.rglob("metadata.json")):
        sample_root = metadata_path.parent
        vulnerable_files = sorted(sample_root.glob("vulnerable.*"))
        if not vulnerable_files:
            continue

        metadata = _load_metadata(metadata_path)
        sample_status = str(metadata.get("status", ""))
        if status != "all" and sample_status != status:
            continue

        evidence_path = sample_root / "evidence.md"
        evidence_text = evidence_path.read_text(encoding="utf-8") if evidence_path.exists() else ""
        samples.append(
            KevSample(
                root=sample_root,
                metadata_path=metadata_path,
                vulnerable_path=vulnerable_files[0].resolve(),
                metadata=metadata,
                evidence_text=evidence_text,
            )
        )
        if limit is not None and len(samples) >= limit:
            break

    return samples


def build_kev_suite(
    samples_root: Path,
    status: str = "accepted",
    limit: Optional[int] = None,
) -> BenchmarkSuite:
    samples = discover_kev_samples(samples_root=samples_root, status=status, limit=limit)
    cases = [_case_from_sample(sample) for sample in samples]
    return BenchmarkSuite(name=f"KEV code samples ({status})", cases=cases)


def write_kev_suite(
    samples_root: Path,
    output: Path,
    status: str = "accepted",
    limit: Optional[int] = None,
) -> tuple[Path, BenchmarkSuite]:
    suite = build_kev_suite(samples_root=samples_root, status=status, limit=limit)
    output_path = output.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_suite_to_yaml(suite), encoding="utf-8")
    return output_path, suite


def _case_from_sample(sample: KevSample) -> BenchmarkCase:
    language = str(sample.metadata.get("language") or _language_name(sample.vulnerable_path))
    affected_files = sample.metadata.get("affected_files") or []
    affected = ", ".join(str(path) for path in affected_files) or sample.vulnerable_path.name
    prompt = (
        "Review the vulnerable code sample below. Identify the likely security vulnerability, "
        "explain the impact, and describe the safer fix direction.\n\n"
        f"Language: {language}\n"
        f"Affected file: {affected}\n\n"
        f"{{file:{sample.vulnerable_path}}}"
    )
    return BenchmarkCase(
        id=_case_id(sample),
        prompt=prompt,
        code_files=[sample.vulnerable_path],
        scorers=_scorers_for(sample),
    )


def _scorers_for(sample: KevSample) -> list[ScorerConfig]:
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


def _case_id(sample: KevSample) -> str:
    raw = f"{sample.cve_id}-{sample.sample_id}"
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-")
    return normalized or sample.root.name


def _metadata_text(sample: KevSample) -> str:
    parts = [
        json.dumps(sample.metadata, sort_keys=True),
        sample.evidence_text,
    ]
    return "\n".join(parts)


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


