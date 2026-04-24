#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FOCUS_MODELS = ("gpt-5-4", "gpt-4o", "deepseek-v3-2")
BASELINES = ("naive", "guarded", "attribution_aware")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def discover_runs(root: Path, models: set[str], baselines: set[str]) -> list[Path]:
    exp_dir = root / "exp_6_1_outcome_baselines"
    runs = []
    for run_dir in sorted(exp_dir.glob("*")):
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            continue
        manifest = load_json(manifest_path)
        if manifest.get("split") != "test":
            continue
        if str(manifest.get("model_label")) not in models:
            continue
        if str(manifest.get("baseline")) not in baselines:
            continue
        if not (run_dir / "exports" / "scenario_runs.export.jsonl").exists():
            continue
        runs.append(run_dir)
    return runs


def run_command(parts: list[str], dry_run: bool) -> None:
    print("+", " ".join(parts))
    if dry_run:
        return
    subprocess.run(parts, cwd=str(REPO_ROOT), check=True)


def fmt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def write_summary(runs: list[Path], output: Path, mode: str) -> None:
    rows = []
    for run_dir in runs:
        manifest = load_json(run_dir / "manifest.json")
        summary_path = run_dir / "scores" / f"attribution_{mode}.summary.json"
        if not summary_path.exists():
            continue
        summary = load_json(summary_path)
        rows.append(
            {
                "model": manifest.get("model_label"),
                "baseline": manifest.get("baseline"),
                "run_name": run_dir.name,
                "num_scored": summary.get("num_scored"),
                "source_accuracy": fmt(summary.get("source_accuracy")),
                "channel_accuracy": fmt(summary.get("channel_accuracy")),
                "mechanism_accuracy": fmt(summary.get("mechanism_accuracy")),
                "component_accuracy": fmt(summary.get("component_accuracy")),
                "impact_accuracy": fmt(summary.get("impact_accuracy")),
                "block_point_match_rate": fmt(summary.get("block_point_match_rate")),
                "mean_failure_chain_overlap": fmt(summary.get("mean_failure_chain_overlap")),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "model",
        "baseline",
        "run_name",
        "num_scored",
        "source_accuracy",
        "channel_accuracy",
        "mechanism_accuracy",
        "component_accuracy",
        "impact_accuracy",
        "block_point_match_rate",
        "mean_failure_chain_overlap",
    ]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    md = ["# HoneyGuard MVP Attribution Summary", ""]
    md.append("| Model | Baseline | N | Source | Channel | Mechanism | Component | Impact | Block |")
    md.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for row in rows:
        md.append(
            "| {model} | {baseline} | {num_scored} | {source_accuracy} | {channel_accuracy} | {mechanism_accuracy} | {component_accuracy} | {impact_accuracy} | {block_point_match_rate} |".format(**row)
        )
    (output.with_suffix(".md")).write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run MVP attribution prediction + scoring for selected completed runs.")
    parser.add_argument("--root", default="artifacts/experiments/mvp")
    parser.add_argument("--output", default="artifacts/analysis/mvp/attribution_rule_summary.csv")
    parser.add_argument("--mode", choices=("oracle", "rule", "llm"), default="rule")
    parser.add_argument("--models", nargs="*", default=list(FOCUS_MODELS))
    parser.add_argument("--baselines", nargs="*", default=list(BASELINES))
    parser.add_argument("--filter", choices=("all", "failed_or_latent"), default="all")
    parser.add_argument("--judge-model", default="gpt-4o-mini")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    runs = discover_runs(Path(args.root), set(args.models), set(args.baselines))
    if not runs:
        raise SystemExit("No matching runs found")

    for run_dir in runs:
        export_path = run_dir / "exports" / "scenario_runs.export.jsonl"
        outcome_rows = run_dir / "scores" / "outcome.rows.csv"
        pred_path = run_dir / "scores" / f"attribution_{args.mode}.predictions.jsonl"
        summary_path = run_dir / "scores" / f"attribution_{args.mode}.summary.json"
        rows_path = run_dir / "scores" / f"attribution_{args.mode}.rows.csv"
        judge_cmd = [
            sys.executable,
            "scripts/analysis/trace_attribution_judge.py",
            "--input",
            str(export_path),
            "--output",
            str(pred_path),
            "--mode",
            args.mode,
            "--filter",
            args.filter,
            "--outcome-rows",
            str(outcome_rows),
        ]
        if args.mode == "llm":
            judge_cmd.extend(["--model", args.judge_model])
        score_cmd = [
            sys.executable,
            "eval/attribution_scorer.py",
            "--input",
            str(export_path),
            "--predictions",
            str(pred_path),
            "--output-json",
            str(summary_path),
            "--output-csv",
            str(rows_path),
        ]
        run_command(judge_cmd, args.dry_run)
        run_command(score_cmd, args.dry_run)

    if not args.dry_run:
        write_summary(runs, Path(args.output), args.mode)
        print(f"WROTE {args.output}")
        print(f"WROTE {Path(args.output).with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
