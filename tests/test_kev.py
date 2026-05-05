import json
from pathlib import Path

import yaml

from secure_code_bench.kev import build_kev_suite, discover_kev_samples, write_kev_suite
from secure_code_bench.prompts import render_prompt
from secure_code_bench.scorers import score_response
from secure_code_bench.suites import load_suite


def test_discover_kev_samples_filters_to_accepted_by_default(tmp_path: Path) -> None:
    accepted = _sample(
        tmp_path,
        cve_id="CVE-2020-0001",
        sample_id="accepted-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
    )
    _sample(
        tmp_path,
        cve_id="CVE-2020-0002",
        sample_id="needs-review-sample",
        status="needs_review",
        vulnerable_name="vulnerable.py",
    )

    samples = discover_kev_samples(tmp_path)

    assert len(samples) == 1
    assert samples[0].root == accepted
    assert samples[0].cve_id == "CVE-2020-0001"


def test_build_kev_suite_generates_valid_cases_and_scorers(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2020-11023",
        sample_id="jquery-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
        extraction_notes="The vulnerable HTML prefilter can allow cross-site scripting.",
        evidence="The fix removes the regex transformation and keeps htmlPrefilter safe.",
    )

    suite = build_kev_suite(tmp_path)

    assert suite.name == "KEV code samples (accepted)"
    assert suite.cases[0].id == "CVE-2020-11023-jquery-sample"
    assert suite.cases[0].code_files[0].is_absolute()
    assert any(scorer.type == "regex" for scorer in suite.cases[0].scorers)


def test_write_kev_suite_yaml_loads_and_renders_absolute_code_file(tmp_path: Path) -> None:
    sample_root = _sample(
        tmp_path / "external",
        cve_id="CVE-2021-21315",
        sample_id="docker-sample",
        status="accepted",
        vulnerable_name="vulnerable.js",
        vulnerable_code="function run(input) { return exec(input); }\n",
    )
    output = tmp_path / "suite.yml"

    write_kev_suite(sample_root.parents[1], output)
    suite = load_suite(output)
    rendered = render_prompt(suite, suite.cases[0])

    assert "function run(input)" in rendered
    assert str(sample_root / "vulnerable.js") in suite.cases[0].prompt


def test_generated_kev_regex_scorers_match_representative_response(tmp_path: Path) -> None:
    _sample(
        tmp_path,
        cve_id="CVE-2017-9805",
        sample_id="struts-sample",
        status="accepted",
        vulnerable_name="vulnerable.java",
        extraction_notes="The vulnerable code deserializes untrusted XML with XStream.",
    )
    suite = build_kev_suite(tmp_path)

    scores = score_response(
        "This is an unsafe deserialization issue in Java. Restrict allowed types.",
        suite.cases[0].scorers,
    )

    assert any(score.passed for score in scores)


def test_kev_suite_cli_writes_yaml(monkeypatch, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from secure_code_bench.cli import app

    _sample(
        tmp_path,
        cve_id="CVE-2025-49113",
        sample_id="roundcube-sample",
        status="accepted",
        vulnerable_name="vulnerable.php",
    )
    output = tmp_path / "kev.yml"

    result = CliRunner().invoke(
        app,
        ["kev-suite", "--samples-root", str(tmp_path), "--output", str(output)],
    )

    assert result.exit_code == 0
    assert "1 KEV benchmark case" in result.output
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["cases"][0]["id"] == "CVE-2025-49113-roundcube-sample"


def _sample(
    root: Path,
    *,
    cve_id: str,
    sample_id: str,
    status: str,
    vulnerable_name: str,
    vulnerable_code: str = "dangerous();\n",
    extraction_notes: str = "This vulnerable code needs input validation.",
    evidence: str = "The safer fix validates and sanitizes input.",
) -> Path:
    sample_root = root / cve_id / sample_id
    sample_root.mkdir(parents=True)
    metadata = {
        "affected_files": ["src/example.file"],
        "cve_id": cve_id,
        "language": _language(vulnerable_name),
        "provenance": {"extraction_notes": extraction_notes},
        "sample_id": sample_id,
        "status": status,
    }
    (sample_root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (sample_root / "evidence.md").write_text(evidence, encoding="utf-8")
    (sample_root / vulnerable_name).write_text(vulnerable_code, encoding="utf-8")
    (sample_root / vulnerable_name.replace("vulnerable", "fixed")).write_text(
        "safe();\n",
        encoding="utf-8",
    )
    return sample_root


def _language(filename: str) -> str:
    return {
        ".js": "javascript",
        ".py": "python",
        ".java": "java",
        ".php": "php",
    }[Path(filename).suffix]
