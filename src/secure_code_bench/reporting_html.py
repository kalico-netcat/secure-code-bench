from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from secure_code_bench.reporting import DIMENSION_BUCKETS, DIMENSIONS


PLOTLY_INSTALL_HINT = 'python -m pip install -e ".[report]"'


class HtmlReportError(RuntimeError):
    """Raised when HTML report rendering cannot be completed."""


def write_html_report(report: dict[str, Any], output_path: Path) -> Path:
    go, pio, make_subplots = _load_plotly()
    figures = _build_figures(report, go, make_subplots)
    output_path = output_path.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_render_html(report, figures, pio), encoding="utf-8")
    return output_path


def report_chart_data(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "pass_rate_by_model": _pass_rate_by_model(report),
        "failure_buckets_by_model": _failure_buckets_by_model(report),
        "dimension_averages_by_model": _dimension_averages_by_model(report),
        "dimension_histograms": _dimension_histograms(report),
        "guardrails_by_model": _guardrails_by_model(report),
        "strong_vs_all_pass_rate": _strong_vs_all_pass_rate(report),
    }


def _load_plotly():
    try:
        import plotly.graph_objects as go
        import plotly.io as pio
        from plotly.subplots import make_subplots
    except ImportError as exc:
        raise HtmlReportError(
            f"Plotly is required for --html reports. Install it with: {PLOTLY_INSTALL_HINT}"
        ) from exc
    return go, pio, make_subplots


def _build_figures(report: dict[str, Any], go, make_subplots) -> list:
    data = report_chart_data(report)
    figures = [
        _pass_rate_figure(data["pass_rate_by_model"], go),
        _failure_buckets_figure(data["failure_buckets_by_model"], go),
        _dimension_average_figure(data["dimension_averages_by_model"], go),
        _dimension_histogram_figure(data["dimension_histograms"], go),
        _guardrail_figure(data["guardrails_by_model"], go),
    ]
    strong_vs_all = data["strong_vs_all_pass_rate"]
    if strong_vs_all:
        figures.append(_strong_vs_all_figure(strong_vs_all, go))
    return figures


def _render_html(report: dict[str, Any], figures: list, pio) -> str:
    figure_html = []
    for index, figure in enumerate(figures):
        figure_html.append(
            pio.to_html(
                figure,
                include_plotlyjs=True if index == 0 else False,
                full_html=False,
            )
        )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            "<title>secure-code-bench report</title>",
            "<style>",
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px;}",
            "h1{margin-bottom:0;} .meta{color:#555;margin-top:6px;} .chart{margin:32px 0;}",
            "</style>",
            "</head>",
            "<body>",
            "<h1>secure-code-bench report</h1>",
            f"<p class=\"meta\">Total records: {escape(str(report.get('total_records', 0)))}</p>",
            *[f'<section class="chart">{html}</section>' for html in figure_html],
            "</body>",
            "</html>",
            "",
        ]
    )


def _pass_rate_by_model(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for model, summary in sorted(report.get("by_model", {}).items()):
        rows.append(
            {
                "model": model,
                "pass_rate": _percent(summary.get("pass_rate")),
                "completed": summary.get("completed", 0),
                "records": summary.get("records", 0),
            }
        )
    return rows


def _failure_buckets_by_model(report: dict[str, Any]) -> dict[str, dict[str, int]]:
    rows: dict[str, dict[str, int]] = {}
    for model, summary in sorted(report.get("by_model", {}).items()):
        rows[model] = dict(summary.get("failure_buckets", {}))
    return rows


def _dimension_averages_by_model(report: dict[str, Any]) -> dict[str, dict[str, float | None]]:
    rows: dict[str, dict[str, float | None]] = {}
    for model, summary in sorted(report.get("by_model", {}).items()):
        histograms = summary.get("dimension_histograms", {})
        rows[model] = {
            dimension: (histograms.get(dimension, {}) or {}).get("average")
            for dimension in DIMENSIONS
        }
    return rows


def _dimension_histograms(report: dict[str, Any]) -> dict[str, dict[str, int]]:
    histograms = report.get("overall", {}).get("dimension_histograms", {})
    return {
        dimension: dict((histograms.get(dimension, {}) or {}).get("counts", {}))
        for dimension in DIMENSIONS
    }


def _guardrails_by_model(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for model, summary in sorted(report.get("by_model", {}).items()):
        rows.append({"model": model, "guardrails": summary.get("guardrail_count", 0)})
    return rows


def _strong_vs_all_pass_rate(report: dict[str, Any]) -> list[dict[str, Any]]:
    rubric_quality = report.get("by_rubric_quality", {})
    if "strong" not in rubric_quality:
        return []
    return [
        {"label": "all cases", "pass_rate": _percent(report.get("overall", {}).get("pass_rate"))},
        {"label": "strong rubric", "pass_rate": _percent(rubric_quality["strong"].get("pass_rate"))},
    ]


def _pass_rate_figure(rows: list[dict[str, Any]], go):
    figure = go.Figure()
    figure.add_bar(
        x=[row["model"] for row in rows],
        y=[row["pass_rate"] for row in rows],
        customdata=[[row["completed"], row["records"]] for row in rows],
        hovertemplate="pass rate=%{y:.1f}%<br>completed=%{customdata[0]}<br>records=%{customdata[1]}<extra></extra>",
    )
    figure.update_layout(title="Pass rate by model", yaxis_title="Pass rate (%)")
    return figure


def _failure_buckets_figure(rows: dict[str, dict[str, int]], go):
    figure = go.Figure()
    models = list(rows)
    buckets = sorted({bucket for values in rows.values() for bucket in values})
    for bucket in buckets:
        figure.add_bar(x=models, y=[rows[model].get(bucket, 0) for model in models], name=bucket)
    figure.update_layout(title="Failure buckets by model", barmode="stack", yaxis_title="Records")
    return figure


def _dimension_average_figure(rows: dict[str, dict[str, float | None]], go):
    figure = go.Figure()
    models = list(rows)
    for dimension in DIMENSIONS:
        figure.add_bar(
            x=models,
            y=[
                rows[model][dimension] if rows[model][dimension] is not None else 0
                for model in models
            ],
            name=dimension,
        )
    figure.update_layout(title="Judge dimension averages by model", yaxis_title="Average score")
    return figure


def _dimension_histogram_figure(rows: dict[str, dict[str, int]], go):
    figure = go.Figure()
    for bucket in DIMENSION_BUCKETS:
        figure.add_bar(
            x=DIMENSIONS,
            y=[rows.get(dimension, {}).get(bucket, 0) for dimension in DIMENSIONS],
            name=bucket,
        )
    figure.update_layout(title="Judge dimension score histograms", barmode="group", yaxis_title="Count")
    return figure


def _guardrail_figure(rows: list[dict[str, Any]], go):
    figure = go.Figure()
    figure.add_bar(
        x=[row["model"] for row in rows],
        y=[row["guardrails"] for row in rows],
    )
    figure.update_layout(title="Guardrail count by model", yaxis_title="Guardrails")
    return figure


def _strong_vs_all_figure(rows: list[dict[str, Any]], go):
    figure = go.Figure()
    figure.add_bar(
        x=[row["label"] for row in rows],
        y=[row["pass_rate"] for row in rows],
    )
    figure.update_layout(title="Strong-rubric pass rate vs all cases", yaxis_title="Pass rate (%)")
    return figure


def _percent(value: object) -> float:
    if value is None:
        return 0.0
    return float(value) * 100
