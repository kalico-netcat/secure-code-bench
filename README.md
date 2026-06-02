# secure-code-bench

A small first-pass framework for benchmarking LLMs on code-oriented prompts.

## Quick start

Install the package in editable mode:

```bash
python -m pip install -e ".[dev]"
```

Install optional HTML report dependencies when you want interactive charts:

```bash
python -m pip install -e ".[report]"
```

Create a local `.env` file with your OpenRouter API key:

```bash
cp .env.example .env
```

Then edit `.env`:

```bash
OPENROUTER_API_KEY=your-key-here
```

You can also add first-party OpenAI and Anthropic keys. Models requested with the
`openai:` and `anthropic:` prefixes use those first-party APIs when the matching key is
available, and fall back to OpenRouter when it is not:

```bash
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
```

Run the small checked-in example suite:

```bash
secure-code-bench run examples/basic.yml --model openai/gpt-4.1-mini
```

Results are written as JSONL, with one record per case/model pair.
Each record includes a `status` field: `completed` for normal model answers,
or `model_error`, `judge_error`, or `scorer_error` when infrastructure or
scoring fails before a valid benchmark judgment can be made.
The JSONL output is flushed as records complete, so interrupted runs keep
completed records on disk. On a clean finish, the file is rewritten in stable
suite/model/case order; if interrupted, the manifest records how many expected
records were actually written.
Each run also writes a sibling manifest such as `results/basic.manifest.json`
containing the model list, suite hash, CLI options, timestamp, git state,
provider routing mode, judge model, KEV generation metadata when available, and
case counts.

After generating a local KEV suite under `examples/` as described below, you can still
override the request timeout for slower models. The default is already 600 seconds per
model request. Runs use 4 parallel model/case workers by default; pass `--workers 1`
for serial execution when you need lower provider pressure or easier progress logs:

```bash
secure-code-bench run examples/kev.yml \
  --model anthropic:claude-opus-4.7 \
  --model openai:gpt-5.5 \
  --limit 3 \
  --timeout 900 \
  --workers 1
```

For stronger KEV scoring, enable rubric judging. The tested model sees only the anonymized
code review prompt; the judge sees the model answer plus a hidden rubric generated from
local sample review metadata:

```bash
secure-code-bench run examples/kev.yml \
  --model anthropic:claude-opus-4.7 \
  --model openai:gpt-5.5 \
  --limit 3 \
  --judge
```

The default judge is `openai/gpt-mini-latest` through OpenRouter. Override it with
`--judge-model`, including first-party prefixes such as `openai:gpt-5.5` when needed.

To run multiple suites in a single command, list each suite and pair each with an `--output`
(paired by order). This is useful for running the KEV may-be-safe and known-vulnerable
prompts together:

```bash
secure-code-bench run \
  examples/kev-may-be-safe.yml \
  examples/kev-known-vulnerable.yml \
  --output results/kev-may-be-safe.jsonl \
  --output results/kev-known-vulnerable.jsonl \
  --model anthropic:claude-opus-4.7 \
  --model openai:gpt-5.5 \
  --judge
```

If `--output` is omitted, each suite writes to `results/<suite-stem>.jsonl`.

Aggregate one or more JSONL result files by model, suite, prompt assumption, rubric
quality, vulnerable/control label, result status, and judge guardrail count:

```bash
secure-code-bench report results/kev-may-be-safe.jsonl results/kev-known-vulnerable.jsonl
```

Pass `--json` for machine-readable output.
Text reports include `failures[...]` buckets for common failure causes and
`dims[...]` summaries for judge dimension averages and counts.
Pass `--html` to write a standalone interactive Plotly report:

```bash
secure-code-bench report results/kev-may-be-safe.jsonl results/kev-known-vulnerable.jsonl \
  --html results/report.html
```

For OpenRouter `latest` aliases, omit the leading `~`; the runner adds it when sending
requests:

```bash
secure-code-bench run examples/basic.yml --model anthropic/claude-sonnet-latest
```

Use slash IDs for direct OpenRouter routing, and colon IDs for first-party routing with
OpenRouter fallback on missing keys:

```bash
secure-code-bench run examples/basic.yml --model openai:gpt-5.5
secure-code-bench run examples/basic.yml --model anthropic:claude-sonnet-4-20250514
```

## Suite format

Suites are YAML files with a name and cases. Cases can inject code files into prompts with
`{file:path/from/suite.yml}` placeholders.

```yaml
name: basic secure code checks
cases:
  - id: sql-injection
    prompt: |
      Review this code and identify the main vulnerability:

      {file:samples/sql_injection.py}
    code_files:
      - samples/sql_injection.py
    scorers:
      - type: contains
        value: SQL injection
      - type: regex
        pattern: "(?i)parameteri[sz]ed|prepared statement"
```

V1 supports two deterministic scorers: `contains` and `regex`.

Cases can also define an optional judge acceptance policy. When `--judge` is
enabled, final pass/fail comes from this policy instead of deterministic scorers:

```yaml
acceptance:
  judge_policy: strict_dimensions
  min_overall: 0.75
  required_dimensions:
    - vulnerability_type
    - code_evidence
  core_dimensions: []
  allow_partial_credit_dimensions: []
  min_core_dimension_score: 1.0
  min_dimension_score: 1.0
```

Judge scoring reports four structured dimensions: `vulnerability_type`, `impact`,
`code_evidence`, and `fix_direction`. Each dimension is scored as `0`, `0.5`, or
`1`, and result records include an `acceptance` object explaining the final
decision. Rubrics can also represent safe/control cases by setting the expected
finding to no concrete vulnerability; the judge is instructed to penalize invented
vulnerabilities for those cases.

The runner normalizes judge dimensions and computes `overall` locally from those
dimensions. If the judge returns an `overall` value, it is retained as
`overall_raw` for auditability but does not control pass/fail. Judge results also
apply deterministic polarity guardrails: an answer that says there is no finding
cannot pass a vulnerable rubric, and an answer that invents a vulnerability cannot
pass a no-vulnerability rubric. Guardrail overrides are recorded in
`scores[].details.guardrails`.

## KEV code samples

Generate a suite from accepted samples in the KEV code sample collector project,
[kalico-netcat/find-kev-code-samples](https://github.com/kalico-netcat/find-kev-code-samples):

```bash
secure-code-bench kev-suite \
  --samples-root /path/to/kev-code-samples/samples \
  --output examples/kev.yml
```

To compare prompt priors, generate two suites over the same samples:

```bash
secure-code-bench kev-suite \
  --samples-root /path/to/kev-code-samples/samples \
  --output examples/kev.yml \
  --prompt-assumption both \
  --limit 5 \
  --seed 42
```

This writes `examples/kev-may-be-safe.yml` and
`examples/kev-known-vulnerable.yml`.
Suite generation shuffles discovered samples before applying `--limit` by
default; pass `--seed` to make the random subset reproducible across both prompt
variants. Use `--ordered` to disable shuffling.

`may-be-safe` tells models that there may be no vulnerability and asks them to say
`None` when no concrete issue is present. `known-vulnerable` tells models all
samples contain a vulnerability.

KEV suites are anonymized by default: generated prompts omit CVE IDs, sample IDs,
repository names, and affected file paths. The YAML still contains `code_files` paths so the
runner can load local files, but those paths are replaced with code before calling the model.
When pointed at an anonymized sample export, suite generation uses the
`vulnerable.*` file from each accepted sample directory as the model-facing input.
That file may be labeled vulnerable or no-finding by metadata. `fixed.*` files are
treated as reference solutions, not model-facing benchmark cases. Empty
`vulnerable.*` files are skipped.

Positive KEV cases whose metadata lacks concrete review/evidence text are still
included, but generated cases are marked with `metadata.rubric_quality: weak`.
This makes weak rubric cases visible in result JSONL records while keeping them
runnable for calibration. Negative controls remain in `known-vulnerable` suites by
design so those runs can measure prompt-prior hallucination.
When anonymized sample metadata includes `expected_responses`, suite generation
copies the response for the model-facing `vulnerable.*` file into
`metadata.expected_response`; the LLM judge uses it as hidden grading guidance.

Run the generated suite like any other benchmark:

```bash
secure-code-bench run examples/kev.yml --model openai/gpt-4.1-mini
```

The generated prompts show only the `vulnerable.*` file contents. `metadata.json` and
`evidence.md` are used only to build broad deterministic regex scorers, hidden judge
rubrics, and judge-only expected-response guidance.

Generated suites under `examples/` are intentionally ignored by git, except for the small
checked-in `examples/basic.yml` smoke-test fixture. Regenerate KEV suites from your local
samples path before running them.

## Environment

The CLI automatically loads `.env` from the current working directory before calling
model providers. Variables already set in your shell take precedence over `.env`
values. Optional overrides include `OPENROUTER_BASE_URL`, `OPENAI_BASE_URL`,
`ANTHROPIC_BASE_URL`, and `ANTHROPIC_VERSION`.
