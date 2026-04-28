#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


BASELINE_ORDER = {"naive": 0, "guarded": 1, "attribution_aware": 2}
FAMILIES = ("A1", "A4", "C2.1", "C2.2")
METRICS = ("TSR", "SVR", "STCR", "ASR", "resource_overrun_rate", "latent_violation_rate")
RISK_METRICS = {"SVR", "ASR", "resource_overrun_rate", "latent_violation_rate", "infra_failed_rate", *FAMILIES}
GOOD_METRICS = {"TSR", "STCR", "evaluable_rate"}
ATTR_DIMS = (
    ("primary_channel", "Hazard Channel"),
    ("primary_mechanism", "Failure Mechanism"),
    ("first_failed_component", "First Failed Component"),
    ("counterfactual_block_point", "Block Point"),
    ("primary_impact", "Impact"),
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def to_float(value: Any) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def pct(value: Any) -> str:
    numeric = to_float(value)
    return "—" if numeric is None else f"{numeric * 100:.0f}%"


def short_label(label: str, max_len: int = 26) -> str:
    label = label.replace("attribution_aware", "attr_aware")
    label = label.replace("gpt-5-4", "gpt-5.4")
    label = label.replace("deepseek-", "ds-")
    label = label.replace("gemini-3-1-pro-preview", "gemini-3.1-pro")
    label = label.replace("claude-opus-4-6", "claude-opus-4.6")
    label = label.replace("grok-4-20-non-reasoning", "grok-4-nr")
    return label if len(label) <= max_len else f"{label[: max_len - 1]}…"


def esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def blend(start: tuple[int, int, int], end: tuple[int, int, int], value: float) -> str:
    value = max(0.0, min(1.0, value))
    rgb = tuple(round(start[i] + (end[i] - start[i]) * value) for i in range(3))
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


def metric_color(metric: str, value: float | None) -> str:
    if value is None:
        return "#eeeeee"
    if metric in GOOD_METRICS:
        return blend((253, 219, 199), (26, 152, 80), value)
    if metric in RISK_METRICS:
        return blend((217, 239, 139), (215, 48, 39), value)
    return blend((239, 243, 255), (49, 130, 189), value)


def discover_runs(root: Path) -> list[dict[str, Any]]:
    runs = []
    for run_dir in sorted(root.glob("*")):
        manifest_path = run_dir / "manifest.json"
        summary_path = run_dir / "scores" / "outcome.summary.json"
        if not manifest_path.exists() or not summary_path.exists():
            continue
        manifest = load_json(manifest_path)
        summary = load_json(summary_path)
        rows = load_csv(run_dir / "scores" / "outcome.rows.csv")
        exports = load_jsonl(run_dir / "exports" / "scenario_runs.export.jsonl")
        per_run = summary.get("per_run") or []
        num_runs = int(summary.get("num_runs") or len(rows) or len(per_run) or 0)
        evaluable = summary.get("num_evaluable_runs")
        if evaluable is None:
            if per_run and any("evaluable" in row for row in per_run):
                evaluable = sum(1 for row in per_run if row.get("evaluable") is True)
            elif rows:
                evaluable = sum(1 for row in rows if row.get("status") not in {"infra_failed", "init_failed", "run_failed"})
            elif per_run:
                evaluable = sum(1 for row in per_run if row.get("status") not in {"infra_failed", "init_failed", "run_failed"})
            else:
                evaluable = num_runs
        infra_rate = to_float(summary.get("infra_failed_rate"))
        if infra_rate is None and num_runs:
            source = per_run or rows
            infra_rate = sum(1 for row in source if row.get("status") == "infra_failed") / num_runs
        runs.append(
            {
                "run_dir": run_dir,
                "run_name": run_dir.name,
                "model": str(manifest.get("model_label") or ""),
                "baseline": str(manifest.get("baseline") or ""),
                "split": str(manifest.get("split") or ""),
                "num_runs": num_runs,
                "num_evaluable_runs": int(evaluable or 0),
                "infra_failed_rate": infra_rate,
                "summary": summary,
                "rows": rows,
                "exports": exports,
            }
        )
    return runs


def run_value(run: dict[str, Any], metric: str) -> float | None:
    if metric in {"TSR", "SVR", "STCR", "ASR"} and run.get("rows"):
        counted = metric_counts(run, metric)
        if counted is not None:
            return counted[2]
    if metric == "infra_failed_rate":
        return to_float(run.get("infra_failed_rate"))
    return to_float(run["summary"].get(metric))


def safe_mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def family_metric(run: dict[str, Any], family: str) -> float | None:
    rows = [row for row in run["rows"] if row.get("family") == family and row.get("status") not in {"infra_failed", "init_failed", "run_failed"}]
    if not rows:
        return None
    if family in {"A1", "A4"}:
        values = [1.0 if boolish(row.get("safety_violation")) else 0.0 for row in rows]
    else:
        values = [1.0 if boolish(row.get("attack_success")) else 0.0 for row in rows if boolish(row.get("attack_success")) is not None]
    return safe_mean(values)


def metric_counts(run: dict[str, Any], metric: str) -> tuple[int, int, float] | None:
    rows = [row for row in run["rows"] if row.get("status") not in {"infra_failed", "init_failed", "run_failed"}]
    if metric == "TSR":
        values = [boolish(row.get("task_success")) for row in rows]
    elif metric == "SVR":
        values = [boolish(row.get("safety_violation")) for row in rows]
    elif metric == "STCR":
        values = [boolish(row.get("stcr_success")) for row in rows]
    elif metric == "ASR":
        values = [boolish(row.get("attack_success")) for row in rows]
    else:
        return None
    values = [value for value in values if value is not None]
    if not values:
        return None
    numerator = sum(1 for value in values if value)
    denominator = len(values)
    return numerator, denominator, numerator / denominator


def write_svg(path: Path, body: list[str], width: int, height: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#222}",
        ".title{font-size:22px;font-weight:700}",
        ".subtitle{font-size:12px;fill:#555}",
        ".axis{font-size:11px;fill:#555}",
        ".label{font-size:12px}",
        ".small{font-size:10px;fill:#444}",
        ".grid{stroke:#ddd;stroke-width:1}",
        "</style>",
        *body,
        "</svg>",
    ]
    path.write_text("\n".join(payload) + "\n", encoding="utf-8")


def heatmap_svg(
    path: Path,
    title: str,
    subtitle: str,
    rows: list[dict[str, Any]],
    row_label: str,
    columns: list[tuple[str, str]],
    *,
    cell_width: int = 84,
    row_height: int = 30,
    label_width: int = 210,
) -> None:
    width = 60 + label_width + cell_width * len(columns) + 30
    height = 84 + row_height * (len(rows) + 1) + 38
    body = [
        f'<text x="28" y="32" class="title">{esc(title)}</text>',
        f'<text x="28" y="52" class="subtitle">{esc(subtitle)}</text>',
    ]
    x0 = 40 + label_width
    y0 = 86
    body.append(f'<text x="40" y="{y0 - 12}" class="axis">{esc(row_label)}</text>')
    for col_idx, (_, label) in enumerate(columns):
        x = x0 + col_idx * cell_width
        body.append(f'<text x="{x + cell_width / 2:.1f}" y="{y0 - 12}" text-anchor="middle" class="axis">{esc(label)}</text>')
    for row_idx, row in enumerate(rows):
        y = y0 + row_idx * row_height
        body.append(f'<text x="40" y="{y + 20}" class="label">{esc(short_label(str(row[row_label]), 30))}</text>')
        for col_idx, (metric, _) in enumerate(columns):
            x = x0 + col_idx * cell_width
            value = to_float(row.get(metric))
            color = metric_color(metric, value)
            body.append(f'<rect x="{x}" y="{y}" width="{cell_width - 2}" height="{row_height - 2}" fill="{color}" rx="3"/>')
            body.append(f'<text x="{x + cell_width / 2:.1f}" y="{y + 19}" text-anchor="middle" class="small">{esc(pct(value))}</text>')
    write_svg(path, body, width, height)


def metric_bars_svg(path: Path, runs: list[dict[str, Any]]) -> None:
    metrics = [
        ("ASR", "ASR", "#d73027"),
        ("SVR", "SVR", "#f46d43"),
        ("TSR", "TSR", "#1a9850"),
        ("STCR", "STCR", "#4575b4"),
    ]
    sorted_runs = sorted(runs, key=lambda run: (-((metric_counts(run, "ASR") or (0, 0, -1))[2]), run["model"]))
    width = 1120
    left = 220
    right = 70
    top = 92
    row_height = 72
    bar_height = 12
    bar_gap = 4
    plot_w = width - left - right
    height = top + row_height * len(sorted_runs) + 58
    body = [
        '<text x="28" y="32" class="title">Naive Models: Core Metric Bars</text>',
        '<text x="28" y="52" class="subtitle">Sorted by ASR descending. Lower ASR/SVR is safer; higher TSR/STCR is better.</text>',
    ]
    for tick in range(0, 11):
        x = left + plot_w * tick / 10
        body.append(f'<line x1="{x:.1f}" y1="{top - 20}" x2="{x:.1f}" y2="{height - 48}" class="grid"/>')
        body.append(f'<text x="{x:.1f}" y="{height - 26}" text-anchor="middle" class="axis">{tick * 10}</text>')
    body.append(f'<text x="{left + plot_w / 2:.1f}" y="{height - 8}" text-anchor="middle" class="label">Metric value (%)</text>')
    for idx, (_, label, color) in enumerate(metrics):
        x = left + idx * 82
        body.append(f'<rect x="{x}" y="66" width="16" height="10" fill="{color}" rx="2"/>')
        body.append(f'<text x="{x + 22}" y="75" class="small">{esc(label)}</text>')
    for row_idx, run in enumerate(sorted_runs):
        y_base = top + row_idx * row_height
        body.append(f'<text x="36" y="{y_base + 31}" class="label">{esc(short_label(run["model"], 28))}</text>')
        body.append(f'<text x="36" y="{y_base + 47}" class="small">n={run["num_evaluable_runs"]}/{run["num_runs"]}</text>')
        for metric_idx, (metric, label, color) in enumerate(metrics):
            counted = metric_counts(run, metric)
            if counted is None:
                continue
            numerator, denominator, value = counted
            y = y_base + metric_idx * (bar_height + bar_gap)
            bar_w = max(1.0, min(1.0, value) * plot_w)
            body.append(f'<rect x="{left}" y="{y}" width="{bar_w:.1f}" height="{bar_height}" fill="{color}" rx="3"/>')
            label_x = left + bar_w + 6 if bar_w < plot_w - 82 else left + bar_w - 6
            anchor = "start" if bar_w < plot_w - 82 else "end"
            fill = "#222" if anchor == "start" else "#fff"
            body.append(
                f'<text x="{label_x:.1f}" y="{y + 10}" text-anchor="{anchor}" class="small" fill="{fill}">'
                f'{esc(label)} {value * 100:.1f}% ({numerator}/{denominator})</text>'
            )
    write_svg(path, body, width, height)


def scatter_svg(path: Path, runs: list[dict[str, Any]]) -> None:
    width, height = 980, 640
    left, top, plot_w, plot_h = 80, 80, 780, 460
    body = [
        '<text x="28" y="32" class="title">Naive Models: Task Success vs Attack Success</text>',
        '<text x="28" y="52" class="subtitle">Right-lower is better: high TSR and low ASR. Bubble size encodes STCR.</text>',
        f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" fill="#fafafa" stroke="#bbb"/>',
    ]
    for tick in range(0, 11):
        value = tick / 10
        x = left + value * plot_w
        y = top + plot_h - value * plot_h
        body.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{top + plot_h}" class="grid"/>')
        body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" class="grid"/>')
        body.append(f'<text x="{x:.1f}" y="{top + plot_h + 20}" text-anchor="middle" class="axis">{tick * 10}</text>')
        body.append(f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" class="axis">{tick * 10}</text>')
    body.append(f'<text x="{left + plot_w / 2}" y="{height - 42}" text-anchor="middle" class="label">TSR: task success rate (%)</text>')
    body.append(f'<text x="22" y="{top + plot_h / 2}" transform="rotate(-90 22 {top + plot_h / 2})" text-anchor="middle" class="label">ASR: attack success rate (%)</text>')
    body.append(f'<rect x="{left + plot_w * 0.7}" y="{top}" width="{plot_w * 0.3}" height="{plot_h * 0.35}" fill="#e8f5e9" opacity="0.8"/>')
    body.append(f'<text x="{left + plot_w * 0.85}" y="{top + 22}" text-anchor="middle" class="small">desired zone</text>')
    for idx, run in enumerate(runs):
        tsr = run_value(run, "TSR")
        asr = run_value(run, "ASR")
        stcr = run_value(run, "STCR") or 0
        if tsr is None or asr is None:
            continue
        x = left + tsr * plot_w
        y = top + plot_h - asr * plot_h
        radius = 7 + stcr * 42
        color = blend((49, 130, 189), (8, 48, 107), min(1.0, stcr * 6))
        body.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="{color}" fill-opacity="0.78" stroke="#111"/>')
        dy = -10 if idx % 2 == 0 else 18
        anchor = "start" if x < left + plot_w * 0.76 else "end"
        dx = 10 if anchor == "start" else -10
        body.append(f'<text x="{x + dx:.1f}" y="{y + dy:.1f}" text-anchor="{anchor}" class="small">{esc(short_label(run["model"], 24))}</text>')
    write_svg(path, body, width, height)


def attribution_bars_svg(path: Path, runs: list[dict[str, Any]]) -> None:
    counters: dict[str, Counter[str]] = {dim: Counter() for dim, _ in ATTR_DIMS}
    total_failures = 0
    for run in runs:
        outcome_by_task = {row.get("task_id"): row for row in run["rows"]}
        for export in run["exports"]:
            meta = export.get("task_metadata") or {}
            task_id = meta.get("task_id")
            outcome = outcome_by_task.get(task_id, {})
            safety = boolish(outcome.get("safety_violation"))
            latent = bool(outcome.get("latent_violation_labels"))
            if not safety and not latent:
                continue
            total_failures += 1
            truth = meta.get("attribution_ground_truth") or {}
            for dim, _ in ATTR_DIMS:
                value = meta.get("counterfactual_block_point") if dim == "counterfactual_block_point" else truth.get(dim)
                counters[dim][str(value or "unknown")] += 1
    panel_w, panel_h = 520, 220
    width, height = 1120, 720
    body = [
        '<text x="28" y="32" class="title">Naive Failure Attribution Distribution</text>',
        f'<text x="28" y="52" class="subtitle">Aggregated over observed safety failures / latent violations. N={total_failures} attribution labels counted per dimension.</text>',
    ]
    for idx, (dim, title) in enumerate(ATTR_DIMS):
        col = idx % 2
        row = idx // 2
        x0 = 48 + col * panel_w
        y0 = 86 + row * panel_h
        body.append(f'<text x="{x0}" y="{y0}" class="label" font-weight="700">{esc(title)}</text>')
        items = counters[dim].most_common(6)
        max_count = max((count for _, count in items), default=1)
        for item_idx, (label, count) in enumerate(items):
            y = y0 + 28 + item_idx * 27
            bar_w = 280 * count / max_count
            share = count / total_failures if total_failures else 0
            body.append(f'<text x="{x0}" y="{y + 16}" class="small">{esc(short_label(label, 34))}</text>')
            body.append(f'<rect x="{x0 + 210}" y="{y}" width="{bar_w:.1f}" height="19" fill="#4e79a7" rx="3"/>')
            body.append(f'<text x="{x0 + 210 + bar_w + 8:.1f}" y="{y + 15}" class="small">{count} ({share * 100:.0f}%)</text>')
    write_svg(path, body, width, height)


def write_summary_csv(path: Path, runs: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "model",
        "baseline",
        "split",
        "num_runs",
        "num_evaluable_runs",
        "infra_failed_rate",
        *METRICS,
        "run_name",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for run in runs:
            row = {
                "model": run["model"],
                "baseline": run["baseline"],
                "split": run["split"],
                "num_runs": run["num_runs"],
                "num_evaluable_runs": run["num_evaluable_runs"],
                "infra_failed_rate": run.get("infra_failed_rate"),
                "run_name": run["run_name"],
            }
            for metric in METRICS:
                row[metric] = run_value(run, metric)
            writer.writerow(row)


def write_index(path: Path, images: list[tuple[str, str]], naive_runs: list[dict[str, Any]], complete_models: list[str]) -> None:
    best_stcr = max(naive_runs, key=lambda run: run_value(run, "STCR") or -1)
    best_asr = min(naive_runs, key=lambda run: run_value(run, "ASR") if run_value(run, "ASR") is not None else math.inf)
    best_tsr = max(naive_runs, key=lambda run: run_value(run, "TSR") or -1)
    html_body = [
        "<!doctype html>",
        '<meta charset="utf-8">',
        "<title>HoneyGuard MVP Visualizations</title>",
        "<style>body{font-family:Arial,Helvetica,sans-serif;margin:28px;color:#222;line-height:1.45} img{max-width:100%;border:1px solid #ddd;margin:12px 0 28px} code{background:#f4f4f4;padding:2px 4px} .note{color:#555}</style>",
        "<h1>HoneyGuard MVP Outcome Baselines</h1>",
        '<p class="note">Generated from <code>artifacts/experiments/mvp/exp_6_1_outcome_baselines</code>.</p>',
        "<h2>Quick Reads</h2>",
        "<ul>",
        f"<li>Highest naive STCR: <b>{esc(best_stcr['model'])}</b> ({pct(run_value(best_stcr, 'STCR'))}).</li>",
        f"<li>Lowest naive ASR: <b>{esc(best_asr['model'])}</b> ({pct(run_value(best_asr, 'ASR'))}).</li>",
        f"<li>Highest naive TSR: <b>{esc(best_tsr['model'])}</b> ({pct(run_value(best_tsr, 'TSR'))}).</li>",
        f"<li>Complete 3-baseline models: <b>{esc(', '.join(complete_models) or 'none')}</b>.</li>",
        "</ul>",
    ]
    for filename, title in images:
        html_body.append(f"<h2>{esc(title)}</h2>")
        html_body.append(f'<img src="{esc(filename)}" alt="{esc(title)}">')
    path.write_text("\n".join(html_body) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SVG/HTML visualizations for HoneyGuard MVP outcome baseline results.")
    parser.add_argument("--root", default="artifacts/experiments/mvp/exp_6_1_outcome_baselines")
    parser.add_argument("--output", default="artifacts/analysis/mvp/visualizations")
    args = parser.parse_args()

    runs = discover_runs(Path(args.root))
    runs = [run for run in runs if run["split"] == "test"]
    if not runs:
        raise SystemExit("No test runs found")

    naive_runs_all = [run for run in runs if run["baseline"] == "naive"]
    naive_runs = [run for run in naive_runs_all if run["num_evaluable_runs"] > 0]
    naive_runs = sorted(naive_runs, key=lambda run: (-(run_value(run, "STCR") or -1), run["model"]))
    model_to_baselines: dict[str, set[str]] = defaultdict(set)
    for run in runs:
        model_to_baselines[run["model"]].add(run["baseline"])
    complete_models = sorted(model for model, baselines in model_to_baselines.items() if set(BASELINE_ORDER).issubset(baselines))
    complete_runs = sorted(
        [run for run in runs if run["model"] in complete_models],
        key=lambda run: (run["model"], BASELINE_ORDER.get(run["baseline"], 99)),
    )

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    write_summary_csv(outdir / "visualization_data.csv", sorted(runs, key=lambda run: (run["model"], BASELINE_ORDER.get(run["baseline"], 99))))

    images: list[tuple[str, str]] = []
    heatmap_svg(
        outdir / "naive_metric_heatmap.svg",
        "All Naive Models: Outcome Metrics",
        "Green is better for TSR/STCR; red is worse for SVR/ASR/resource/latent. Grok 0-evaluable run is excluded.",
        naive_runs,
        "model",
        [
            ("TSR", "TSR"),
            ("SVR", "SVR"),
            ("STCR", "STCR"),
            ("ASR", "ASR"),
            ("resource_overrun_rate", "Resource"),
            ("latent_violation_rate", "Latent"),
        ],
    )
    images.append(("naive_metric_heatmap.svg", "All Naive Models: Outcome Metrics"))

    metric_bars_svg(outdir / "naive_core_metric_bars.svg", naive_runs)
    images.append(("naive_core_metric_bars.svg", "Naive Core Metric Bars"))

    scatter_svg(outdir / "naive_tsr_asr_scatter.svg", naive_runs)
    images.append(("naive_tsr_asr_scatter.svg", "Naive TSR vs ASR Scatter"))

    family_rows = []
    for run in naive_runs:
        row = {"model": run["model"]}
        for family in FAMILIES:
            row[family] = family_metric(run, family)
        family_rows.append(row)
    heatmap_svg(
        outdir / "naive_family_risk_heatmap.svg",
        "All Naive Models: Family-Level Risk",
        "A1/A4 cells use SVR; C2.1/C2.2 cells use ASR. Red means more unsafe.",
        family_rows,
        "model",
        [(family, family) for family in FAMILIES],
    )
    images.append(("naive_family_risk_heatmap.svg", "All Naive Models: Family-Level Risk"))

    if complete_runs:
        baseline_rows = []
        for run in complete_runs:
            row = {"label": f"{run['model']} / {run['baseline']}"}
            for metric in ("TSR", "SVR", "STCR", "ASR"):
                row[metric] = run_value(run, metric)
            baseline_rows.append(row)
        heatmap_svg(
            outdir / "complete_models_baseline_heatmap.svg",
            "Complete Models: Baseline Comparison",
            "Models with naive, guarded, and attribution-aware runs.",
            baseline_rows,
            "label",
            [("TSR", "TSR"), ("SVR", "SVR"), ("STCR", "STCR"), ("ASR", "ASR")],
            label_width=260,
        )
        images.append(("complete_models_baseline_heatmap.svg", "Complete Models: Baseline Comparison"))

    attribution_bars_svg(outdir / "naive_attribution_distribution.svg", naive_runs)
    images.append(("naive_attribution_distribution.svg", "Naive Failure Attribution Distribution"))

    availability_rows = sorted(
        [
            {
                "model": run["model"],
                "infra_failed_rate": run.get("infra_failed_rate"),
                "evaluable_rate": (run["num_evaluable_runs"] / run["num_runs"]) if run["num_runs"] else None,
            }
            for run in naive_runs_all
        ],
        key=lambda row: (to_float(row.get("infra_failed_rate")) or 0, row["model"]),
    )
    heatmap_svg(
        outdir / "naive_availability_heatmap.svg",
        "Naive Runs: Availability / Evaluable Coverage",
        "Infra failure is red when high; evaluable coverage is green when high.",
        availability_rows,
        "model",
        [("infra_failed_rate", "Infra Fail"), ("evaluable_rate", "Eval Coverage")],
    )
    images.append(("naive_availability_heatmap.svg", "Naive Runs: Availability / Evaluable Coverage"))

    write_index(outdir / "index.html", images, naive_runs, complete_models)
    print(f"WROTE {outdir}")
    for filename, _ in images:
        print(f"WROTE {outdir / filename}")
    print(f"WROTE {outdir / 'index.html'}")
    print(f"WROTE {outdir / 'visualization_data.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
