#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.experiments.mvp.common import (
    DEFAULT_OUTPUT_ROOT,
    apply_baseline_to_directory,
    build_paths,
    build_run_name,
    collect_llm_config_refs,
    env_snapshot,
    fetch_server_runtime_metadata,
    git_commit,
    resolve_model_label,
    run_logged_command,
    validate_model_label_match,
    write_commands,
    write_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run HoneyGuard MVP Phase 6.5 internal authority pilot experiment.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="HoneyGuard API base URL.")
    parser.add_argument(
        "--baseline",
        choices=("naive", "guarded", "attribution_aware"),
        required=True,
        help="Baseline policy preset.",
    )
    parser.add_argument("--model-label", default="", help="Model name to record for this run. Must match the real runtime model by default.")
    parser.add_argument(
        "--require-model-match",
        dest="require_model_match",
        action="store_true",
        help="Require --model-label to match the current runtime model identifier. Enabled by default.",
    )
    parser.add_argument(
        "--no-require-model-match",
        dest="require_model_match",
        action="store_false",
        help="Disable runtime-model consistency checking for --model-label.",
    )
    parser.add_argument("--tag", default="", help="Optional free-form run tag.")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Root directory for saved experiment runs.")
    parser.add_argument("--timeout", type=float, default=120.0, help="run_scenarios timeout in seconds.")
    parser.set_defaults(require_model_match=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    experiment_id = "exp_6_5_internal_authority_pilot"
    split = "pilot_b"
    model_label = resolve_model_label(args.model_label)
    server_runtime = fetch_server_runtime_metadata(args.base_url)
    runtime_model_identifier = validate_model_label_match(
        model_label,
        args.require_model_match,
        str(server_runtime.get("runtime_model_identifier") or "").strip(),
    )
    run_name = build_run_name(split, args.baseline, model_label, args.tag)
    paths = build_paths(Path(args.output_root), experiment_id, run_name)

    assemble_cmd = [
        "python3",
        "scripts/assemble_mvp_benchmark.py",
        "--split",
        split,
        "--output",
        str(paths.assembled_dir),
    ]
    run_cmd = [
        "uv",
        "run",
        "python",
        "test/run_scenarios.py",
        "--base-url",
        args.base_url,
        "--target",
        str(paths.baseline_dir),
        "--limit",
        "0",
        "--timeout",
        str(args.timeout),
        "--output",
        str(paths.raw_dir / "scenario_runs.jsonl"),
        "--db-path",
        str(paths.raw_dir / "scenario_runs.db"),
    ]
    export_cmd = [
        "uv",
        "run",
        "python",
        "scripts/export_run_to_json.py",
        "--run-jsonl",
        str(paths.raw_dir / "scenario_runs.jsonl"),
        "--output",
        str(paths.exports_dir / "scenario_runs.export.jsonl"),
        "--scenario-root",
        str(paths.baseline_dir),
    ]
    score_cmd = [
        "uv",
        "run",
        "python",
        "eval/outcome_scorer.py",
        "--input",
        str(paths.exports_dir / "scenario_runs.export.jsonl"),
        "--output-json",
        str(paths.scores_dir / "outcome.summary.json"),
        "--output-csv",
        str(paths.scores_dir / "outcome.rows.csv"),
    ]
    commands = [assemble_cmd, run_cmd, export_cmd, score_cmd]

    run_logged_command(assemble_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="01_assemble")
    apply_baseline_to_directory(paths.assembled_dir, paths.baseline_dir, args.baseline)
    write_commands(paths.commands_path, commands)
    write_manifest(
        paths.manifest_path,
        {
            "experiment_id": experiment_id,
            "phase": "6.5",
            "created_at": run_name.split("__", 1)[0],
            "split": split,
            "baseline": args.baseline,
            "model_label": model_label,
            "runtime_model_identifier": runtime_model_identifier,
            "runtime_identifier_source": str(server_runtime.get("runtime_identifier_source") or ""),
            "server_runtime_metadata": server_runtime,
            "require_model_match": args.require_model_match,
            "tag": args.tag,
            "git_commit": git_commit(),
            "repo_root": str(REPO_ROOT),
            "run_dir": str(paths.run_dir),
            "source_split_dir": split,
            "env": env_snapshot(),
            "llm_config_refs": collect_llm_config_refs(paths.baseline_dir),
            "commands": {
                "assemble": " ".join(assemble_cmd),
                "run": " ".join(run_cmd),
                "export": " ".join(export_cmd),
                "score": " ".join(score_cmd),
            },
            "outputs": {
                "assembled_dir": str(paths.assembled_dir),
                "baseline_dir": str(paths.baseline_dir),
                "raw_jsonl": str(paths.raw_dir / "scenario_runs.jsonl"),
                "raw_db": str(paths.raw_dir / "scenario_runs.db"),
                "export_jsonl": str(paths.exports_dir / "scenario_runs.export.jsonl"),
                "score_json": str(paths.scores_dir / "outcome.summary.json"),
                "score_csv": str(paths.scores_dir / "outcome.rows.csv"),
            },
        },
    )
    run_logged_command(run_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="02_run")
    run_logged_command(export_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="03_export")
    run_logged_command(score_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="04_score")

    print(f"EXPERIMENT_RUN_DIR {paths.run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
