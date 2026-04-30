#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

BASELINES = ("naive", "guarded")
FOCUS_MODELS = ("gpt-5-4", "gpt-4o", "deepseek-v3-2")
MAIN_EXPS = ("mvp_outcome_benchmark", "exp_6_1_outcome_baselines")
PILOT_EXPS = ("exp_6_5_internal_authority_pilot",)
REPORT_SPLITS = ("v0_2_test", "test")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def to_float(value: Any) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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


def safe_mean(values: Iterable[float | None]) -> float | None:
    nums = [value for value in values if value is not None]
    return mean(nums) if nums else None


def pct(value: Any) -> str:
    numeric = to_float(value)
    return "" if numeric is None else f"{numeric * 100:.1f}"


def fmt(value: Any) -> str:
    numeric = to_float(value)
    if numeric is None:
        return ""
    return f"{numeric:.3f}"


def discover_runs(root: Path, exp_name: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    exp_dir = root / exp_name
    for run_dir in sorted(exp_dir.glob("*")):
        if not run_dir.is_dir():
            continue
        manifest_path = run_dir / "manifest.json"
        summary_path = run_dir / "scores" / "outcome.summary.json"
        if not manifest_path.exists() or not summary_path.exists():
            continue
        manifest = load_json(manifest_path)
        summary = load_json(summary_path)
        rows = load_csv(run_dir / "scores" / "outcome.rows.csv")
        exports = load_jsonl(run_dir / "exports" / "scenario_runs.export.jsonl")
        runs.append(
            {
                "run_dir": run_dir,
                "run_name": run_dir.name,
                "manifest": manifest,
                "summary": summary,
                "rows": rows,
                "exports": exports,
                "model": manifest.get("model_label", ""),
                "baseline": manifest.get("baseline", ""),
                "split": manifest.get("split", ""),
                "phase": manifest.get("phase", ""),
                "experiment_id": manifest.get("experiment_id", exp_name),
            }
        )
    return runs


def discover_runs_many(root: Path, exp_names: Iterable[str]) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for exp_name in exp_names:
        runs.extend(discover_runs(root, exp_name))
    return runs


def is_report_split(run: dict[str, Any], report_splits: set[str]) -> bool:
    return str(run.get("split", "")) in report_splits


def run_key(run: dict[str, Any]) -> tuple[str, str, str]:
    return str(run["model"]), str(run["baseline"]), str(run["split"])


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def markdown_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not rows:
        return ""
    header = "| " + " | ".join(label for _, label in columns) + " |"
    sep = "| " + " | ".join("---" for _ in columns) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(str(row.get(key, "")) for key, _ in columns) + " |")
    return "\n".join([header, sep, *body])


def summary_row(run: dict[str, Any]) -> dict[str, Any]:
    summary = run["summary"]
    per_run = summary.get("per_run") or []
    num_runs = summary.get("num_runs", len(per_run) if per_run else "")
    infra_failed_count = sum(1 for row in per_run if row.get("status") == "infra_failed")
    evaluable_count = sum(1 for row in per_run if row.get("evaluable") is True)
    inferred_infra_rate = infra_failed_count / num_runs if isinstance(num_runs, int) and num_runs else None
    return {
        "model": run["model"],
        "baseline": run["baseline"],
        "split": run["split"],
        "experiment_id": run["experiment_id"],
        "run_name": run["run_name"],
        "num_runs": num_runs,
        "num_evaluable_runs": summary.get("num_evaluable_runs", evaluable_count or summary.get("num_runs", "")),
        "infra_failed_rate": fmt(summary.get("infra_failed_rate", inferred_infra_rate)),
        "TSR": fmt(summary.get("TSR")),
        "SVR": fmt(summary.get("SVR")),
        "STCR": fmt(summary.get("STCR")),
        "ASR": fmt(summary.get("ASR")),
        "resource_overrun_rate": fmt(summary.get("resource_overrun_rate")),
        "internal_message_exposure_rate": fmt(summary.get("internal_message_exposure_rate")),
        "unsafe_internal_message_exposure_rate": fmt(summary.get("unsafe_internal_message_exposure_rate")),
        "mean_utility_pass_rate": fmt(summary.get("mean_utility_pass_rate")),
        "mean_safety_constraint_pass_rate": fmt(summary.get("mean_safety_constraint_pass_rate")),
        "mean_first_failure_step": fmt(summary.get("mean_first_failure_step")),
        "mean_harmful_action_step": fmt(summary.get("mean_harmful_action_step")),
        "mean_failure_lead_time": fmt(summary.get("mean_failure_lead_time")),
        "latent_violation_rate": fmt(summary.get("latent_violation_rate")),
    }


def family_breakdown(run: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in run["rows"]:
        groups[row.get("family", "")].append(row)
    output = []
    for family, rows in sorted(groups.items()):
        evaluable_rows = [row for row in rows if row.get("status") not in {"infra_failed", "init_failed", "run_failed"}]
        output.append(
            {
                "model": run["model"],
                "baseline": run["baseline"],
                "family": family,
                "n": len(rows),
                "evaluable_n": len(evaluable_rows),
                "infra_failed_n": sum(1 for row in rows if row.get("status") == "infra_failed"),
                "TSR": fmt(safe_mean(1.0 if boolish(row.get("task_success")) else 0.0 for row in evaluable_rows)),
                "SVR": fmt(safe_mean(1.0 if boolish(row.get("safety_violation")) else 0.0 for row in evaluable_rows)),
                "STCR": fmt(safe_mean(1.0 if boolish(row.get("stcr_success")) else 0.0 for row in evaluable_rows)),
                "ASR": fmt(safe_mean(1.0 if boolish(row.get("attack_success")) else 0.0 for row in evaluable_rows if boolish(row.get("attack_success")) is not None)),
                "latent_violation_rate": fmt(safe_mean(1.0 if row.get("latent_violation_labels") else 0.0 for row in evaluable_rows)),
                "internal_message_exposure_rate": fmt(safe_mean(1.0 if boolish(row.get("internal_message_exposure")) else 0.0 for row in evaluable_rows)),
                "unsafe_internal_message_exposure_rate": fmt(safe_mean(1.0 if boolish(row.get("unsafe_internal_message_exposure")) else 0.0 for row in evaluable_rows)),
            }
        )
    return output


def task_truth(export_row: dict[str, Any]) -> dict[str, Any]:
    meta = export_row.get("task_metadata") or {}
    truth = meta.get("attribution_ground_truth") or {}
    return {**truth, "counterfactual_block_point": meta.get("counterfactual_block_point"), "family": meta.get("family"), "task_id": meta.get("task_id")}


def attribution_failure_breakdown(run: dict[str, Any]) -> list[dict[str, Any]]:
    row_by_task = {row.get("task_id"): row for row in run["rows"]}
    counters = {
        "primary_source": Counter(),
        "primary_channel": Counter(),
        "first_failed_component": Counter(),
        "primary_mechanism": Counter(),
        "primary_impact": Counter(),
        "counterfactual_block_point": Counter(),
    }
    total_failures = 0
    for export_row in run["exports"]:
        truth = task_truth(export_row)
        task_id = truth.get("task_id")
        score_row = row_by_task.get(task_id, {})
        safety_violation = boolish(score_row.get("safety_violation"))
        latent = bool(score_row.get("latent_violation_labels"))
        if not safety_violation and not latent:
            continue
        total_failures += 1
        for key, counter in counters.items():
            value = truth.get(key) or "unknown"
            counter[str(value)] += 1
    rows: list[dict[str, Any]] = []
    for dimension, counter in counters.items():
        for label, count in counter.most_common():
            rows.append(
                {
                    "model": run["model"],
                    "baseline": run["baseline"],
                    "dimension": dimension,
                    "label": label,
                    "count": count,
                    "failure_count": total_failures,
                    "share": fmt(count / total_failures if total_failures else None),
                }
            )
    return rows


def build_report(main_runs: list[dict[str, Any]], pilot_runs: list[dict[str, Any]], outdir: Path, report_splits: set[str]) -> None:
    selected_main_runs = [run for run in main_runs if is_report_split(run, report_splits)]
    complete_focus = [run for run in selected_main_runs if run["model"] in FOCUS_MODELS and run["baseline"] in BASELINES]
    naive_runs = [run for run in selected_main_runs if run["baseline"] == "naive"]
    pilot_complete = [run for run in pilot_runs if run["model"] in FOCUS_MODELS]

    summary_rows = [summary_row(run) for run in sorted(selected_main_runs, key=run_key)]
    focus_rows = [summary_row(run) for run in sorted(complete_focus, key=run_key)]
    naive_rows = [summary_row(run) for run in sorted(naive_runs, key=lambda r: (to_float(r["summary"].get("infra_failed_rate")) or 0, r["model"]))]
    pilot_rows = [summary_row(run) for run in sorted(pilot_complete, key=run_key)]

    family_rows = []
    attribution_rows = []
    for run in sorted(complete_focus, key=run_key):
        family_rows.extend(family_breakdown(run))
        attribution_rows.extend(attribution_failure_breakdown(run))
    naive_family_rows = []
    naive_attribution_rows = []
    for run in sorted(naive_runs, key=run_key):
        naive_family_rows.extend(family_breakdown(run))
        naive_attribution_rows.extend(attribution_failure_breakdown(run))

    write_csv(outdir / "all_main_summary.csv", summary_rows, list(summary_rows[0].keys()) if summary_rows else [])
    write_csv(outdir / "focus_three_models_summary.csv", focus_rows, list(focus_rows[0].keys()) if focus_rows else [])
    write_csv(outdir / "all_naive_summary.csv", naive_rows, list(naive_rows[0].keys()) if naive_rows else [])
    write_csv(outdir / "focus_three_models_family_breakdown.csv", family_rows, list(family_rows[0].keys()) if family_rows else [])
    write_csv(outdir / "focus_three_models_attribution_failure_breakdown.csv", attribution_rows, list(attribution_rows[0].keys()) if attribution_rows else [])
    write_csv(outdir / "all_naive_family_breakdown.csv", naive_family_rows, list(naive_family_rows[0].keys()) if naive_family_rows else [])
    write_csv(outdir / "all_naive_attribution_failure_breakdown.csv", naive_attribution_rows, list(naive_attribution_rows[0].keys()) if naive_attribution_rows else [])
    write_csv(outdir / "pilot_b_focus_summary.csv", pilot_rows, list(pilot_rows[0].keys()) if pilot_rows else [])

    model_baselines: dict[str, set[str]] = defaultdict(set)
    for run in selected_main_runs:
        model_baselines[str(run["model"])].add(str(run["baseline"]))
    completeness = [
        {
            "model": model,
            "completed": ", ".join(sorted(bases)),
            "missing": ", ".join(base for base in BASELINES if base not in bases),
        }
        for model, bases in sorted(model_baselines.items())
    ]
    write_csv(outdir / "main_completeness.csv", completeness, ["model", "completed", "missing"])

    report = []
    report.append("# HoneyGuard MVP Result Analysis\n")
    report.append("## 1. Three-model horizontal comparison\n")
    report.append(markdown_table(focus_rows, [("model", "Model"), ("baseline", "Baseline"), ("split", "Split"), ("num_evaluable_runs", "Eval N"), ("TSR", "TSR"), ("SVR", "SVR"), ("STCR", "STCR"), ("ASR", "ASR"), ("latent_violation_rate", "Latent"), ("unsafe_internal_message_exposure_rate", "Unsafe IntExp")]))
    report.append("\n## 2. All naive model comparison\n")
    report.append(markdown_table(naive_rows, [("model", "Model"), ("split", "Split"), ("num_evaluable_runs", "Eval N"), ("infra_failed_rate", "Infra Fail"), ("TSR", "TSR"), ("SVR", "SVR"), ("STCR", "STCR"), ("ASR", "ASR"), ("latent_violation_rate", "Latent"), ("unsafe_internal_message_exposure_rate", "Unsafe IntExp")]))
    report.append("\n## 3. Attribution over observed failures\n")
    report.append("This is not manual eyeballing: each failed/latent run is grouped by the benchmark's task-side attribution labels. It explains what failure classes each model actually triggered.\n")
    top_attr = [row for row in attribution_rows if row["dimension"] in {"first_failed_component", "primary_mechanism", "primary_channel"}]
    report.append(markdown_table(top_attr, [("model", "Model"), ("baseline", "Baseline"), ("dimension", "Dimension"), ("label", "Label"), ("count", "Count"), ("share", "Share")]))
    report.append("\n## 4. Completion status\n")
    report.append(markdown_table(completeness, [("model", "Model"), ("completed", "Completed"), ("missing", "Missing")]))
    report.append("\n## 5. Files\n")
    for path in sorted(outdir.glob("*.csv")):
        report.append(f"- `{path}`")
    (outdir / "summary.md").write_text("\n".join(report) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze HoneyGuard MVP experiment results.")
    parser.add_argument("--root", default="artifacts/experiments/mvp")
    parser.add_argument("--output", default="artifacts/analysis/mvp")
    parser.add_argument("--splits", nargs="*", default=list(REPORT_SPLITS))
    args = parser.parse_args()

    root = Path(args.root)
    outdir = Path(args.output)
    main_runs = discover_runs_many(root, MAIN_EXPS)
    pilot_runs = discover_runs_many(root, PILOT_EXPS)
    build_report(main_runs, pilot_runs, outdir, set(args.splits))
    print(f"WROTE {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
