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

Run the example suite:

```bash
secure-code-bench run examples/basic.yml --model openai/gpt-4.1-mini
```

Results are written as JSONL, with one record per case/model pair.

For slower models, increase the request timeout and keep going after individual failures:

```bash
secure-code-bench run examples/kev.yml \
  --model anthropic/claude-opus-4.7 \
  --model openai/gpt-5.5 \
  --limit 3 \
  --timeout 300 \
  --retries 2 \
  --continue-on-error
```

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

## KEV code samples

Generate a suite from accepted samples in the local KEV code sample collector:

```bash
secure-code-bench kev-suite \
  --samples-root /path/to/kev-code-samples/samples \
  --output examples/kev.yml
```

KEV suites are anonymized by default: generated prompts omit CVE IDs, sample IDs,
repository names, and affected file paths. The YAML still contains `code_files` paths so the
runner can load local files, but those paths are replaced with code before calling the model.

Run the generated suite like any other benchmark:

```bash
secure-code-bench run examples/kev.yml --model openai/gpt-4.1-mini
```

The generated prompts show only the `vulnerable.*` file contents. `metadata.json` and
`evidence.md` are used only to build broad deterministic regex scorers.

`examples/kev.yml` is a template showing the generated structure. Regenerate it with your
local samples path before running it.

## Environment

The CLI automatically loads `.env` from the current working directory before calling
OpenRouter. Variables already set in your shell take precedence over `.env` values.
