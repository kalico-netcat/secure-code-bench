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
        "pass_rate_by_prompt_assumption_model": _pass_rate_by_prompt_assumption_model(report),
        "dimension_averages_by_model": _dimension_averages_by_model(report),
        "dimension_histograms": _dimension_histograms(report),
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
        _pass_rate_figure(
            data["pass_rate_by_prompt_assumption_model"]["may-be-safe"],
            go,
            title="Pass rate by model (may-be-safe prompts)",
        ),
        _pass_rate_figure(
            data["pass_rate_by_prompt_assumption_model"]["known-vulnerable"],
            go,
            title="Pass rate by model (known-vulnerable prompts)",
        ),
        _dimension_average_figure(data["dimension_averages_by_model"], go),
        _dimension_histogram_figure(data["dimension_histograms"], go),
    ]
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
    label_groups = report.get("by_model_vulnerability_label", {})
    for model, summary in sorted(report.get("by_model", {}).items()):
        rows.append(
            {
                "model": model,
                "pass_rate": _percent(summary.get("pass_rate")),
                "completed": summary.get("completed", 0),
                "records": summary.get("records", 0),
                "label_pass_rates": _label_pass_rates(
                    label_groups.get(model, {}), summary.get("completed", 0)
                ),
            }
        )
    return rows


def _pass_rate_by_prompt_assumption_model(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups = report.get("by_prompt_assumption_model", {})
    label_groups = report.get("by_prompt_assumption_model_vulnerability_label", {})
    models = sorted(report.get("by_model", {}))
    return {
        assumption: _pass_rate_rows(
            groups.get(assumption, {}),
            models=models,
            label_groups=label_groups.get(assumption, {}),
        )
        for assumption in ("may-be-safe", "known-vulnerable")
    }


def _pass_rate_rows(
    groups: dict[str, dict[str, Any]],
    models: list[str] | None = None,
    label_groups: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    rows = []
    model_names = models if models is not None else sorted(groups)
    label_groups = label_groups or {}
    for model in model_names:
        summary = groups.get(model, {})
        completed = summary.get("completed", 0)
        pass_rate = None if completed == 0 else _percent(summary.get("pass_rate"))
        rows.append(
            {
                "model": model,
                "pass_rate": pass_rate,
                "completed": completed,
                "records": summary.get("records", 0),
                "label_pass_rates": _label_pass_rates(label_groups.get(model, {}), completed),
            }
        )
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


def _pass_rate_figure(rows: list[dict[str, Any]], go, title: str = "Pass rate by model"):
    figure = go.Figure()
    pass_rates = [row["pass_rate"] for row in rows]
    labels = (("vulnerable", "Vulnerable"), ("control", "Non-vulnerable"))
    for label_key, label in labels:
        figure.add_bar(
            x=[row["model"] for row in rows],
            y=[
                row.get("label_pass_rates", {})
                .get(label_key, {})
                .get("stacked_pass_rate_contribution", 0.0)
                for row in rows
            ],
            name=label,
            customdata=[
                [
                    _format_rate(
                        row.get("label_pass_rates", {}).get(label_key, {}).get("pass_rate")
                    ),
                    row.get("label_pass_rates", {}).get(label_key, {}).get("passed", 0),
                    row.get("label_pass_rates", {}).get(label_key, {}).get("completed", 0),
                    row["completed"],
                    row["records"],
                ]
                for row in rows
            ],
            hovertemplate=(
                f"{label} pass rate=%{{customdata[0]}}<br>"
                "passed=%{customdata[1]}<br>"
                "label completed=%{customdata[2]}<br>"
                "completed=%{customdata[3]}<br>"
                "records=%{customdata[4]}<extra></extra>"
            ),
        )
    figure.add_scatter(
        x=[row["model"] for row in rows],
        y=[0.0 if pass_rate is None else pass_rate for pass_rate in pass_rates],
        mode="text",
        text=["n/a" if pass_rate is None else f"{pass_rate:.1f}%" for pass_rate in pass_rates],
        textposition="top center",
        showlegend=False,
        hoverinfo="skip",
    )
    figure.update_layout(
        title=title,
        barmode="stack",
        yaxis_title="Pass rate (%)",
        yaxis_range=[0, 100],
    )
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


def _label_pass_rates(
    groups: dict[str, dict[str, Any]], total_completed: object
) -> dict[str, dict[str, Any]]:
    completed_total = total_completed if isinstance(total_completed, int) else 0
    rows: dict[str, dict[str, Any]] = {}
    for label in ("vulnerable", "control"):
        summary = groups.get(label, {})
        completed = summary.get("completed", 0)
        passed = summary.get("passed", 0)
        rows[label] = {
            "pass_rate": None if completed == 0 else _percent(summary.get("pass_rate")),
            "stacked_pass_rate_contribution": (
                (passed / completed_total) * 100 if completed_total else 0.0
            ),
            "passed": passed,
            "completed": completed,
            "records": summary.get("records", 0),
        }
    return rows


def _format_rate(value: object) -> str:
    return "n/a" if value is None else f"{float(value):.1f}%"


def _percent(value: object) -> float:
    if value is None:
        return 0.0
    return float(value) * 100
