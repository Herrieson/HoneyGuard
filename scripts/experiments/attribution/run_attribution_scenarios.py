#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Sequence

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.experiments.mvp.common import (
    build_paths,
    collect_llm_config_refs,
    env_snapshot,
    fetch_server_runtime_metadata,
    git_commit,
    now_utc_compact,
    resolve_model_label,
    run_logged_command,
    slugify,
    validate_model_label_match,
    write_commands,
    write_manifest,
)


DEFAULT_SCENARIO_ROOT = REPO_ROOT / "configs" / "attribution" / "scenarios"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "artifacts" / "experiments" / "attribution"


@dataclass(frozen=True)
class SelectedScenario:
    path: Path
    relative_path: str
    task_id: str
    scenario: str
    track: str
    family: str
    difficulty: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run HoneyGuard attribution scenarios with one command."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="HoneyGuard API base URL.")
    parser.add_argument(
        "--scenario-root",
        default=str(DEFAULT_SCENARIO_ROOT),
        help="Root directory containing attribution YAML scenarios.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Optional source file or directory under --scenario-root. Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--track",
        action="append",
        default=[],
        help="Optional track filter (A, B, C). Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--family",
        action="append",
        default=[],
        help="Optional family filter such as A1, B3, C2.1. Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--difficulty",
        action="append",
        default=[],
        help="Optional difficulty filter (easy, medium, hard, veryhard). Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--task-id",
        action="append",
        default=[],
        help="Optional exact task_id filter. Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Optional fnmatch pattern against task_id, scenario, filename, or relative path.",
    )
    parser.add_argument(
        "--selection-label",
        default="",
        help="Optional short label used in the run directory name.",
    )
    parser.add_argument("--instruction", default="", help="Optional instruction override passed to run_scenarios.")
    parser.add_argument("--limit", type=int, default=0, help="Max number of scenarios to run (0 means no limit).")
    parser.add_argument("--workers", type=int, default=1, help="Number of concurrent run_scenarios workers.")
    parser.add_argument("--timeout", type=float, default=120.0, help="run_scenarios timeout in seconds.")
    parser.add_argument("--token-env", default="HSE_API_TOKEN", help="Env var name for API token.")
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
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="Root directory for saved attribution experiment runs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Assemble scenarios and write manifest/logs without calling the API.",
    )
    parser.set_defaults(require_model_match=True)
    return parser.parse_args()


def normalize_cli_values(values: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for raw in values:
        for item in str(raw or "").split(","):
            cleaned = item.strip()
            if cleaned:
                normalized.append(cleaned)
    return normalized


def normalize_match_set(values: Sequence[str]) -> set[str]:
    return {value.strip().lower() for value in normalize_cli_values(values)}


def load_yaml_mapping(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def resolve_sources(scenario_root: Path, raw_sources: Sequence[str]) -> list[Path]:
    sources = normalize_cli_values(raw_sources)
    if not sources:
        return [scenario_root]

    resolved: list[Path] = []
    for raw in sources:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = scenario_root / raw
        candidate = candidate.resolve()
        if not candidate.exists():
            raise FileNotFoundError(f"source does not exist: {candidate}")
        resolved.append(candidate)
    return resolved


def iter_yaml_files(source: Path) -> Iterable[Path]:
    if source.is_file():
        if source.suffix.lower() in {".yaml", ".yml"}:
            yield source
        return

    if not source.is_dir():
        raise NotADirectoryError(f"source is not a directory: {source}")

    for path in sorted(source.rglob("*.yaml")):
        if path.is_file():
            yield path


def scenario_matches(
    item: SelectedScenario,
    *,
    tracks: set[str],
    families: set[str],
    difficulties: set[str],
    task_ids: set[str],
    patterns: list[str],
) -> bool:
    if tracks and item.track.lower() not in tracks:
        return False
    if families and item.family.lower() not in families:
        return False
    if difficulties and item.difficulty.lower() not in difficulties:
        return False
    if task_ids and item.task_id.lower() not in task_ids:
        return False
    if patterns:
        haystacks = (
            item.task_id,
            item.scenario,
            Path(item.relative_path).name,
            item.relative_path,
        )
        if not any(fnmatch(hay.lower(), pattern.lower()) for hay in haystacks for pattern in patterns):
            return False
    return True


def collect_selected_scenarios(
    scenario_root: Path,
    sources: Sequence[Path],
    *,
    tracks: set[str],
    families: set[str],
    difficulties: set[str],
    task_ids: set[str],
    patterns: list[str],
) -> list[SelectedScenario]:
    selected: list[SelectedScenario] = []
    seen_paths: set[Path] = set()

    for source in sources:
        for path in iter_yaml_files(source):
            path = path.resolve()
            if path in seen_paths:
                continue
            seen_paths.add(path)
            data = load_yaml_mapping(path)
            task_id = str(data.get("task_id") or path.stem).strip()
            scenario = str(data.get("scenario") or task_id).strip()
            track = str(data.get("track") or "").strip()
            family = str(data.get("family") or "").strip()
            difficulty = str(data.get("difficulty") or "").strip()
            try:
                relative_path = str(path.relative_to(scenario_root))
            except ValueError:
                relative_path = path.name

            item = SelectedScenario(
                path=path,
                relative_path=relative_path,
                task_id=task_id,
                scenario=scenario,
                track=track,
                family=family,
                difficulty=difficulty,
            )
            if scenario_matches(
                item,
                tracks=tracks,
                families=families,
                difficulties=difficulties,
                task_ids=task_ids,
                patterns=patterns,
            ):
                selected.append(item)

    selected.sort(key=lambda item: (item.relative_path, item.task_id))
    if not selected:
        raise FileNotFoundError("no attribution scenarios matched the requested filters")
    return selected


def assemble_selected_scenarios(selected: Sequence[SelectedScenario], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    seen_task_ids: dict[str, Path] = {}
    seen_names: dict[str, Path] = {}

    for item in selected:
        if item.task_id in seen_task_ids:
            raise ValueError(f"duplicate task_id {item.task_id!r}: {seen_task_ids[item.task_id]} and {item.path}")
        seen_task_ids[item.task_id] = item.path

        if item.path.name in seen_names:
            raise ValueError(f"duplicate filename {item.path.name!r}: {seen_names[item.path.name]} and {item.path}")
        seen_names[item.path.name] = item.path

        shutil.copy2(item.path, output_dir / item.path.name)


def write_assemble_logs(log_dir: Path, selected: Sequence[SelectedScenario], output_dir: Path) -> None:
    lines = [
        f"ASSEMBLED_COUNT {len(selected)}",
        f"OUTPUT_DIR {output_dir}",
        "SELECTED_FILES",
    ]
    lines.extend(item.relative_path for item in selected)
    stdout = "\n".join(lines) + "\n"
    (log_dir / "01_assemble.stdout.log").write_text(stdout, encoding="utf-8")
    (log_dir / "01_assemble.stderr.log").write_text("", encoding="utf-8")
    print(stdout, end="")


def chunk_selected(selected: Sequence[SelectedScenario], worker_count: int) -> list[list[SelectedScenario]]:
    if worker_count <= 1:
        return [list(selected)]

    shard_count = min(worker_count, len(selected))
    shards: list[list[SelectedScenario]] = [[] for _ in range(shard_count)]
    for idx, item in enumerate(selected):
        shards[idx % shard_count].append(item)
    return [shard for shard in shards if shard]


def assemble_shards(selected: Sequence[SelectedScenario], shard_root: Path, worker_count: int) -> list[dict]:
    shard_root.mkdir(parents=True, exist_ok=True)
    shards = chunk_selected(selected, worker_count)
    plans: list[dict] = []
    for idx, shard in enumerate(shards, start=1):
        shard_name = f"worker-{idx:02d}"
        shard_dir = shard_root / shard_name
        assemble_selected_scenarios(shard, shard_dir)
        plans.append(
            {
                "worker_id": idx,
                "name": shard_name,
                "dir": shard_dir,
                "selected": list(shard),
            }
        )
    return plans


def summarize_selection(selected: Sequence[SelectedScenario]) -> dict:
    track_counts = Counter(item.track for item in selected)
    family_counts = Counter(item.family for item in selected)
    difficulty_counts = Counter(item.difficulty for item in selected)
    return {
        "count": len(selected),
        "tracks": dict(sorted(track_counts.items())),
        "families": dict(sorted(family_counts.items())),
        "difficulties": dict(sorted(difficulty_counts.items())),
    }


def derive_selection_label(args: argparse.Namespace, selected: Sequence[SelectedScenario]) -> str:
    if args.selection_label.strip():
        return args.selection_label.strip()

    families = normalize_cli_values(args.family)
    tracks = normalize_cli_values(args.track)
    difficulties = normalize_cli_values(args.difficulty)
    task_ids = normalize_cli_values(args.task_id)
    patterns = normalize_cli_values(args.pattern)
    sources = normalize_cli_values(args.source)

    if task_ids:
        return f"tasks-{len(task_ids)}"
    if families:
        return "family-" + "-".join(slugify(value) for value in families[:3])
    if tracks:
        return "track-" + "-".join(slugify(value) for value in tracks[:3])
    if difficulties:
        return "difficulty-" + "-".join(slugify(value) for value in difficulties[:3])
    if patterns:
        return "pattern-match"
    if sources:
        return "source-" + "-".join(slugify(Path(value).name) for value in sources[:3])
    return "all" if len(selected) > 1 else slugify(selected[0].task_id)


def build_run_name(selection_label: str, selected_count: int, model_label: str, tag: str) -> str:
    parts = [
        now_utc_compact(),
        f"selection-{slugify(selection_label)}",
        f"count-{selected_count}",
        f"model-{slugify(model_label)}",
    ]
    if tag.strip():
        parts.append(f"tag-{slugify(tag)}")
    return "__".join(parts)


def relative_to_repo(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


def build_run_command(
    *,
    base_url: str,
    target_dir: Path,
    timeout: float,
    token_env: str,
    output_jsonl: Path,
    output_db: Path,
    instruction: str,
) -> list[str]:
    cmd = [
        "uv",
        "run",
        "python",
        "test/run_scenarios.py",
        "--base-url",
        base_url,
        "--target",
        str(target_dir),
        "--limit",
        "0",
        "--timeout",
        str(timeout),
        "--token-env",
        token_env,
        "--output",
        str(output_jsonl),
        "--db-path",
        str(output_db),
    ]
    if instruction.strip():
        cmd.extend(["--instruction", instruction])
    return cmd


def merge_worker_jsonl(worker_jsonls: Sequence[Path], output_path: Path, selected: Sequence[SelectedScenario]) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    order_by_name = {item.path.name: idx for idx, item in enumerate(selected)}
    records: list[tuple[int, str]] = []

    for path in worker_jsonls:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                config_name = Path(str(record.get("config_path") or "")).name
                order = order_by_name.get(config_name, len(order_by_name))
                records.append((order, stripped))

    records.sort(key=lambda item: item[0])
    with output_path.open("w", encoding="utf-8") as handle:
        for _, line in records:
            handle.write(line)
            handle.write("\n")
    return len(records)


def ensure_aggregate_db(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scenario_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            config_path TEXT,
            status TEXT,
            instruction TEXT,
            started_at TEXT,
            ended_at TEXT,
            run_response TEXT,
            error TEXT
        )
        """
    )
    conn.commit()


def merge_worker_dbs(worker_dbs: Sequence[Path], output_db: Path) -> int:
    output_db.parent.mkdir(parents=True, exist_ok=True)
    if output_db.exists():
        output_db.unlink()

    dst = sqlite3.connect(output_db)
    ensure_aggregate_db(dst)
    inserted = 0
    try:
        dst_cursor = dst.cursor()
        for path in worker_dbs:
            if not path.exists():
                continue
            src = sqlite3.connect(path)
            try:
                src_cursor = src.cursor()
                rows = src_cursor.execute(
                    """
                    SELECT session_id, config_path, status, instruction, started_at, ended_at, run_response, error
                    FROM scenario_runs
                    ORDER BY id
                    """
                ).fetchall()
            finally:
                src.close()

            if not rows:
                continue
            dst_cursor.executemany(
                """
                INSERT INTO scenario_runs (
                    session_id, config_path, status, instruction, started_at, ended_at, run_response, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            inserted += len(rows)
        dst.commit()
    finally:
        dst.close()
    return inserted


def run_worker(plan: dict, cmd: Sequence[str], log_dir: Path) -> dict:
    log_name = f"02_run.{plan['name']}"
    run_logged_command(list(cmd), cwd=REPO_ROOT, log_dir=log_dir, log_name=log_name)
    return {
        "worker_id": plan["worker_id"],
        "name": plan["name"],
        "jsonl": Path(cmd[cmd.index("--output") + 1]),
        "db": Path(cmd[cmd.index("--db-path") + 1]),
    }


def write_parallel_run_summary(log_dir: Path, shard_plans: Sequence[dict], worker_count: int) -> None:
    lines = [
        f"WORKERS {worker_count}",
        f"SHARDS {len(shard_plans)}",
    ]
    for plan in shard_plans:
        lines.append(f"{plan['name']} {len(plan['selected'])} {plan['dir']}")
    summary = "\n".join(lines) + "\n"
    (log_dir / "02_run.stdout.log").write_text(summary, encoding="utf-8")
    (log_dir / "02_run.stderr.log").write_text("", encoding="utf-8")


def main() -> int:
    args = parse_args()
    scenario_root = Path(args.scenario_root).resolve()
    if not scenario_root.exists() or not scenario_root.is_dir():
        raise SystemExit(f"scenario root does not exist or is not a directory: {scenario_root}")

    sources = resolve_sources(scenario_root, args.source)
    matched = collect_selected_scenarios(
        scenario_root,
        sources,
        tracks=normalize_match_set(args.track),
        families=normalize_match_set(args.family),
        difficulties=normalize_match_set(args.difficulty),
        task_ids=normalize_match_set(args.task_id),
        patterns=normalize_cli_values(args.pattern),
    )
    selected = matched[: args.limit] if args.limit > 0 else matched
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")

    model_label = resolve_model_label(args.model_label)
    server_runtime: dict = {}
    runtime_model_identifier = ""
    if not args.dry_run:
        server_runtime = fetch_server_runtime_metadata(args.base_url)
        runtime_model_identifier = validate_model_label_match(
            model_label,
            args.require_model_match,
            str(server_runtime.get("runtime_model_identifier") or "").strip(),
        )

    selection_label = derive_selection_label(args, matched)
    run_name = build_run_name(selection_label, len(selected), model_label, args.tag)
    experiment_id = "exp_attribution_scenarios"
    paths = build_paths(Path(args.output_root), experiment_id, run_name)

    assemble_selected_scenarios(selected, paths.assembled_dir)
    write_assemble_logs(paths.logs_dir, selected, paths.assembled_dir)
    shard_root = paths.configs_dir / "shards"
    effective_workers = min(args.workers, len(selected))
    shard_plans = assemble_shards(selected, shard_root, effective_workers)

    raw_shard_root = paths.raw_dir / "workers"
    raw_shard_root.mkdir(parents=True, exist_ok=True)

    worker_commands: list[list[str]] = []
    for plan in shard_plans:
        worker_jsonl = raw_shard_root / f"{plan['name']}.scenario_runs.jsonl"
        worker_db = raw_shard_root / f"{plan['name']}.scenario_runs.db"
        worker_commands.append(
            build_run_command(
                base_url=args.base_url,
                target_dir=plan["dir"],
                timeout=args.timeout,
                token_env=args.token_env,
                output_jsonl=worker_jsonl,
                output_db=worker_db,
                instruction=args.instruction,
            )
        )

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
        str(paths.assembled_dir),
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
    commands = [*worker_commands, export_cmd, score_cmd]
    write_commands(paths.commands_path, commands)

    manifest_payload = {
        "experiment_id": experiment_id,
        "created_at": run_name.split("__", 1)[0],
        "selection_label": selection_label,
        "model_label": model_label,
        "runtime_model_identifier": runtime_model_identifier,
        "runtime_identifier_source": str(server_runtime.get("runtime_identifier_source") or ""),
        "server_runtime_metadata": server_runtime,
        "require_model_match": args.require_model_match,
        "dry_run": args.dry_run,
        "workers_requested": args.workers,
        "workers_effective": effective_workers,
        "tag": args.tag,
        "git_commit": git_commit(),
        "repo_root": str(REPO_ROOT),
        "run_dir": str(paths.run_dir),
        "scenario_root": str(scenario_root),
        "source_filters": [relative_to_repo(path) for path in sources],
        "filter_args": {
            "track": normalize_cli_values(args.track),
            "family": normalize_cli_values(args.family),
            "difficulty": normalize_cli_values(args.difficulty),
            "task_id": normalize_cli_values(args.task_id),
            "pattern": normalize_cli_values(args.pattern),
            "limit": args.limit,
            "workers": args.workers,
            "instruction_override": bool(args.instruction.strip()),
        },
        "matched_selection_summary": summarize_selection(matched),
        "selection_summary": summarize_selection(selected),
        "shards": [
            {
                "worker_id": plan["worker_id"],
                "name": plan["name"],
                "count": len(plan["selected"]),
                "dir": str(plan["dir"]),
                "task_ids": [item.task_id for item in plan["selected"]],
            }
            for plan in shard_plans
        ],
        "selected_scenarios": [
            {
                "task_id": item.task_id,
                "scenario": item.scenario,
                "track": item.track,
                "family": item.family,
                "difficulty": item.difficulty,
                "relative_path": item.relative_path,
            }
            for item in selected
        ],
        "env": env_snapshot(),
        "llm_config_refs": collect_llm_config_refs(paths.assembled_dir),
        "commands": {
            "run_workers": [" ".join(cmd) for cmd in worker_commands],
            "export": " ".join(export_cmd),
            "score": " ".join(score_cmd),
        },
        "outputs": {
            "assembled_dir": str(paths.assembled_dir),
            "shard_root": str(shard_root),
            "raw_jsonl": str(paths.raw_dir / "scenario_runs.jsonl"),
            "raw_db": str(paths.raw_dir / "scenario_runs.db"),
            "raw_worker_dir": str(raw_shard_root),
            "export_jsonl": str(paths.exports_dir / "scenario_runs.export.jsonl"),
            "score_json": str(paths.scores_dir / "outcome.summary.json"),
            "score_csv": str(paths.scores_dir / "outcome.rows.csv"),
        },
    }
    write_manifest(paths.manifest_path, manifest_payload)

    if args.dry_run:
        print(f"DRY_RUN_DIR {paths.run_dir}")
        return 0

    write_parallel_run_summary(paths.logs_dir, shard_plans, effective_workers)
    if effective_workers == 1:
        run_worker(shard_plans[0], worker_commands[0], paths.logs_dir)
    else:
        futures: dict[concurrent.futures.Future, tuple[dict, list[str]]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
            for plan, cmd in zip(shard_plans, worker_commands):
                futures[executor.submit(run_worker, plan, cmd, paths.logs_dir)] = (plan, cmd)
            for future in concurrent.futures.as_completed(futures):
                future.result()

    merge_worker_jsonl(
        [raw_shard_root / f"{plan['name']}.scenario_runs.jsonl" for plan in shard_plans],
        paths.raw_dir / "scenario_runs.jsonl",
        selected,
    )
    merge_worker_dbs(
        [raw_shard_root / f"{plan['name']}.scenario_runs.db" for plan in shard_plans],
        paths.raw_dir / "scenario_runs.db",
    )
    run_logged_command(export_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="03_export")
    run_logged_command(score_cmd, cwd=REPO_ROOT, log_dir=paths.logs_dir, log_name="04_score")

    print(f"EXPERIMENT_RUN_DIR {paths.run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
