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

## Environment

The CLI automatically loads `.env` from the current working directory before calling
OpenRouter. Variables already set in your shell take precedence over `.env` values.
