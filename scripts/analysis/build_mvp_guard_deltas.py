#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.analysis.analyze_mvp_results import (
    BASELINES,
    MAIN_EXPS,
    REPORT_SPLITS,
    discover_runs_many,
    family_breakdown,
    fmt,
    to_float,
)


FAMILIES = ("A1", "A2", "A3", "A4", "B1", "B2", "B3", "C1", "C2.1", "C2.2")
OVERALL_METRICS = (
    "TSR",
    "SVR",
    "STCR",
    "ASR",
    "resource_overrun_rate",
    "internal_message_exposure_rate",
    "unsafe_internal_message_exposure_rate",
    "mean_utility_pass_rate",
    "mean_safety_constraint_pass_rate",
    "mean_first_failure_step",
    "mean_harmful_action_step",
    "mean_failure_lead_time",
    "latent_violation_rate",
)
PAIR_KEY = ("model", "split")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def delta_value(guarded: Any, naive: Any) -> str:
    guarded_f = to_float(guarded)
    naive_f = to_float(naive)
    if guarded_f is None or naive_f is None:
        return ""
    return fmt(guarded_f - naive_f)


def latest_pairs(runs: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, dict[str, Any]]]:
    paired: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for run in sorted(runs, key=lambda item: (str(item["model"]), str(item["baseline"]), str(item["split"]), str(item["run_name"]))):
        if run["baseline"] not in BASELINES:
            continue
        key = (str(run["model"]), str(run["split"]))
        bucket = paired.setdefault(key, {})
        bucket[str(run["baseline"])] = run
    return paired


def family_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["family"]: row for row in family_breakdown(run)}


def build_overall_delta_rows(pairs: dict[tuple[str, str], dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (model, split), bucket in sorted(pairs.items()):
        naive = bucket.get("naive")
        guarded = bucket.get("guarded")
        if not naive or not guarded:
            continue
        row: dict[str, Any] = {
            "model": model,
            "split": split,
            "naive_run_name": naive["run_name"],
            "guarded_run_name": guarded["run_name"],
            "naive_num_runs": naive["summary"].get("num_runs", ""),
            "guarded_num_runs": guarded["summary"].get("num_runs", ""),
            "naive_num_evaluable_runs": naive["summary"].get("num_evaluable_runs", ""),
            "guarded_num_evaluable_runs": guarded["summary"].get("num_evaluable_runs", ""),
            "naive_infra_failed_rate": fmt(naive["summary"].get("infra_failed_rate")),
            "guarded_infra_failed_rate": fmt(guarded["summary"].get("infra_failed_rate")),
            "delta_infra_failed_rate": delta_value(guarded["summary"].get("infra_failed_rate"), naive["summary"].get("infra_failed_rate")),
        }
        for metric in OVERALL_METRICS:
            row[f"naive_{metric}"] = fmt(naive["summary"].get(metric))
            row[f"guarded_{metric}"] = fmt(guarded["summary"].get(metric))
            row[f"delta_{metric}"] = delta_value(guarded["summary"].get(metric), naive["summary"].get(metric))
        rows.append(row)
    return rows


def build_family_delta_rows(pairs: dict[tuple[str, str], dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (model, split), bucket in sorted(pairs.items()):
        naive = bucket.get("naive")
        guarded = bucket.get("guarded")
        if not naive or not guarded:
            continue
        naive_families = family_map(naive)
        guarded_families = family_map(guarded)
        for family in FAMILIES:
            naive_row = naive_families.get(family)
            guarded_row = guarded_families.get(family)
            if not naive_row or not guarded_row:
                continue
            row: dict[str, Any] = {
                "model": model,
                "split": split,
                "family": family,
                "naive_n": naive_row.get("n", ""),
                "guarded_n": guarded_row.get("n", ""),
                "naive_evaluable_n": naive_row.get("evaluable_n", ""),
                "guarded_evaluable_n": guarded_row.get("evaluable_n", ""),
                "naive_infra_failed_n": naive_row.get("infra_failed_n", ""),
                "guarded_infra_failed_n": guarded_row.get("infra_failed_n", ""),
            }
            for metric in ("TSR", "SVR", "STCR", "ASR", "latent_violation_rate", "internal_message_exposure_rate", "unsafe_internal_message_exposure_rate"):
                row[f"naive_{metric}"] = naive_row.get(metric, "")
                row[f"guarded_{metric}"] = guarded_row.get(metric, "")
                row[f"delta_{metric}"] = delta_value(guarded_row.get(metric), naive_row.get(metric))
            rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Build paired naive-vs-guarded delta tables for the MVP benchmark.")
    parser.add_argument("--root", default="artifacts/experiments/mvp")
    parser.add_argument("--output", default="artifacts/analysis/mvp")
    parser.add_argument("--splits", nargs="*", default=list(REPORT_SPLITS))
    args = parser.parse_args()

    runs = discover_runs_many(Path(args.root), MAIN_EXPS)
    runs = [run for run in runs if str(run.get("split", "")) in set(args.splits)]
    paired = latest_pairs(runs)

    overall_rows = build_overall_delta_rows(paired)
    family_rows = build_family_delta_rows(paired)

    outdir = Path(args.output)
    write_csv(
        outdir / "guard_delta_summary.csv",
        overall_rows,
        [
            "model",
            "split",
            "naive_run_name",
            "guarded_run_name",
            "naive_num_runs",
            "guarded_num_runs",
            "naive_num_evaluable_runs",
            "guarded_num_evaluable_runs",
            "naive_infra_failed_rate",
            "guarded_infra_failed_rate",
            "delta_infra_failed_rate",
            *[f"naive_{metric}" for metric in OVERALL_METRICS],
            *[f"guarded_{metric}" for metric in OVERALL_METRICS],
            *[f"delta_{metric}" for metric in OVERALL_METRICS],
        ],
    )
    write_csv(
        outdir / "guard_delta_family_breakdown.csv",
        family_rows,
        [
            "model",
            "split",
            "family",
            "naive_n",
            "guarded_n",
            "naive_evaluable_n",
            "guarded_evaluable_n",
            "naive_infra_failed_n",
            "guarded_infra_failed_n",
            "naive_TSR",
            "guarded_TSR",
            "delta_TSR",
            "naive_SVR",
            "guarded_SVR",
            "delta_SVR",
            "naive_STCR",
            "guarded_STCR",
            "delta_STCR",
            "naive_ASR",
            "guarded_ASR",
            "delta_ASR",
            "naive_latent_violation_rate",
            "guarded_latent_violation_rate",
            "delta_latent_violation_rate",
            "naive_internal_message_exposure_rate",
            "guarded_internal_message_exposure_rate",
            "delta_internal_message_exposure_rate",
            "naive_unsafe_internal_message_exposure_rate",
            "guarded_unsafe_internal_message_exposure_rate",
            "delta_unsafe_internal_message_exposure_rate",
        ],
    )

    print(f"WROTE {outdir / 'guard_delta_summary.csv'}")
    print(f"WROTE {outdir / 'guard_delta_family_breakdown.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
