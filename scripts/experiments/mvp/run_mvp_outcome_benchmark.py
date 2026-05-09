#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.experiments.mvp.common import (
    DEFAULT_OUTPUT_ROOT,
    apply_baseline_to_directory,
    build_paths,
    build_paths_from_run_dir,
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
    parser = argparse.ArgumentParser(description="Run the HoneyGuard MVP outcome benchmark.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="HoneyGuard API base URL.")
    parser.add_argument(
        "--resume-run-dir",
        default="",
        help="Resume an existing run directory in place instead of creating a new one.",
    )
    parser.add_argument(
        "--split",
        choices=("dev", "test", "full", "v0_2_dev", "v0_2_test", "v0_2_transient", "v0_2_full"),
        default="",
        help="Benchmark split to run. Use v0_2_test for the current main benchmark; v0_2_transient is an optional trajectory pilot.",
    )
    parser.add_argument(
        "--baseline",
        choices=("naive", "guarded"),
        default="",
        help="Baseline policy preset.",
    )
    parser.add_argument(
        "--model-label",
        default="",
        help="Model name to record for this run. Must match the real runtime model by default.",
    )
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
    experiment_id = "mvp_outcome_benchmark"
    resume_run_dir = Path(args.resume_run_dir).resolve() if args.resume_run_dir.strip() else None

    if resume_run_dir:
        if not resume_run_dir.exists() or not resume_run_dir.is_dir():
            raise SystemExit(f"resume-run-dir does not exist or is not a directory: {resume_run_dir}")
        manifest_path = resume_run_dir / "manifest.json"
        if not manifest_path.exists():
            raise SystemExit(f"resume-run-dir is missing manifest.json: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise SystemExit(f"manifest.json must be a JSON object: {manifest_path}")

        split = str(manifest.get("split") or args.split or "").strip()
        baseline = str(manifest.get("baseline") or args.baseline or "").strip()
        tag = str(manifest.get("tag") or args.tag or "").strip()
        manifest_model_label = str(manifest.get("model_label") or "").strip()
        if args.model_label and manifest_model_label and resolve_model_label(args.model_label) != resolve_model_label(manifest_model_label):
            raise SystemExit(
                f"--model-label={args.model_label!r} does not match resume manifest model_label {manifest_model_label!r}"
            )
        model_label = resolve_model_label(args.model_label or manifest_model_label)
        if args.split and str(args.split).strip() != split:
            raise SystemExit(f"--split={args.split!r} does not match resume manifest split {split!r}")
        if args.baseline and str(args.baseline).strip() != baseline:
            raise SystemExit(f"--baseline={args.baseline!r} does not match resume manifest baseline {baseline!r}")
        if args.tag and str(args.tag).strip() != tag:
            raise SystemExit(f"--tag={args.tag!r} does not match resume manifest tag {tag!r}")

        paths = build_paths_from_run_dir(resume_run_dir)
        if not any(paths.baseline_dir.glob("*.yaml")):
            raise SystemExit(f"resume-run-dir is missing baseline YAML configs: {paths.baseline_dir}")
        run_name = resume_run_dir.name
    else:
        if not args.split or not args.baseline:
            raise SystemExit("--split and --baseline are required unless --resume-run-dir is used.")
        split = str(args.split).strip()
        baseline = str(args.baseline).strip()
        tag = str(args.tag).strip()
        model_label = resolve_model_label(args.model_label)
        run_name = build_run_name(split, baseline, model_label, tag)
        paths = build_paths(Path(args.output_root), experiment_id, run_name)

    if not split or not baseline:
        raise SystemExit("split and baseline could not be resolved.")

    server_runtime = fetch_server_runtime_metadata(args.base_url)
    runtime_model_identifier = validate_model_label_match(
        model_label,
        args.require_model_match,
        str(server_runtime.get("runtime_model_identifier") or "").strip(),
    )

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
    if resume_run_dir:
        run_cmd.insert(run_cmd.index("--limit"), "--resume")
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

    if not resume_run_dir:
        run_logged_command(assemble_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="01_assemble")
        apply_baseline_to_directory(paths.assembled_dir, paths.baseline_dir, baseline)
        write_commands(paths.commands_path, commands)
        write_manifest(
            paths.manifest_path,
            {
                "experiment_id": experiment_id,
                "phase": "mvp_outcome_benchmark",
                "created_at": run_name.split("__", 1)[0],
                "split": split,
                "baseline": baseline,
                "model_label": model_label,
                "runtime_model_identifier": runtime_model_identifier,
                "runtime_identifier_source": str(server_runtime.get("runtime_identifier_source") or ""),
                "server_runtime_metadata": server_runtime,
                "require_model_match": args.require_model_match,
                "tag": tag,
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
    else:
        print(f"RESUMING_RUN_DIR {paths.run_dir}")
        manifest["runtime_model_identifier"] = runtime_model_identifier
        manifest["runtime_identifier_source"] = str(server_runtime.get("runtime_identifier_source") or "")
        manifest["server_runtime_metadata"] = server_runtime
        manifest["env"] = env_snapshot()
        manifest["llm_config_refs"] = collect_llm_config_refs(paths.baseline_dir)
        manifest["resume_events"] = list(manifest.get("resume_events") or [])
        manifest["resume_events"].append(
            {
                "resumed_at": datetime.now(timezone.utc).isoformat(),
                "base_url": args.base_url,
                "git_commit": git_commit(),
                "commands": {
                    "run": " ".join(run_cmd),
                    "export": " ".join(export_cmd),
                    "score": " ".join(score_cmd),
                },
            }
        )
        write_manifest(paths.manifest_path, manifest)

    run_logged_command(run_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="02_run")
    run_logged_command(export_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="03_export")
    run_logged_command(score_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="04_score")

    print(f"EXPERIMENT_RUN_DIR {paths.run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
