# secure-code-bench

A small first-pass framework for benchmarking LLMs on code-oriented prompts.

## Quick start

Install the package in editable mode:

```bash
python -m pip install -e ".[dev]"
```

Create a local `.env` file with your OpenRouter API key:

```bash
cp .env.example .env
```

Then edit `.env`:

```bash
OPENROUTER_API_KEY=your-key-here
```

Run the small checked-in example suite:

```bash
secure-code-bench run examples/basic.yml --model openai/gpt-4.1-mini
```

Results are written as JSONL, with one record per case/model pair.

After generating a local KEV suite under `examples/` as described below, you can still
override the request timeout for slower models. The default is already 600 seconds per
model request:

```bash
secure-code-bench run examples/kev.yml \
  --model anthropic/claude-opus-4.7 \
  --model openai/gpt-5.5 \
  --limit 3 \
  --timeout 900
```

For stronger KEV scoring, enable rubric judging. The tested model sees only the anonymized
code review prompt; the judge sees the model answer plus a hidden rubric generated from
local sample review metadata:

```bash
secure-code-bench run examples/kev.yml \
  --model anthropic/claude-opus-4.7 \
  --model openai/gpt-5.5 \
  --limit 3 \
  --judge
```

The default judge is `openai/gpt-mini-latest`. Override it with `--judge-model` when needed.

To run multiple suites in a single command, list each suite and pair each with an `--output`
(paired by order). This is useful for running the KEV may-be-safe and known-vulnerable
prompts together:

```bash
secure-code-bench run \
  examples/kev-may-be-safe.yml \
  examples/kev-known-vulnerable.yml \
  --output results/kev-may-be-safe.jsonl \
  --output results/kev-known-vulnerable.jsonl \
  --model anthropic/claude-opus-4.7 \
  --model openai/gpt-5.5 \
  --judge
```

If `--output` is omitted, each suite writes to `results/<suite-stem>.jsonl`.

For OpenRouter `latest` aliases, omit the leading `~`; the runner adds it when sending
requests:

```bash
secure-code-bench run examples/basic.yml --model anthropic/claude-sonnet-latest
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

## KEV code samples

Generate a suite from accepted samples in the local KEV code sample collector:

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

Run the generated suite like any other benchmark:

```bash
secure-code-bench run examples/kev.yml --model openai/gpt-4.1-mini
```

The generated prompts show only the `vulnerable.*` file contents. `metadata.json` and
`evidence.md` are used only to build broad deterministic regex scorers.

Generated suites under `examples/` are intentionally ignored by git, except for the small
checked-in `examples/basic.yml` smoke-test fixture. Regenerate KEV suites from your local
samples path before running them.

## Environment

The CLI automatically loads `.env` from the current working directory before calling
OpenRouter. Variables already set in your shell take precedence over `.env` values.
