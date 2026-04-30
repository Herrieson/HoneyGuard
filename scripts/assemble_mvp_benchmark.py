#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
LEGACY_V0_1_ROOT = REPO_ROOT / "configs" / "mvp" / "_archive" / "v0_1_splits"
DEFAULT_SOURCES = (
    LEGACY_V0_1_ROOT / "dev",
    LEGACY_V0_1_ROOT / "formal",
)
PRESET_SOURCES = {
    "dev": (LEGACY_V0_1_ROOT / "dev",),
    "test": (LEGACY_V0_1_ROOT / "formal",),
    "full": DEFAULT_SOURCES,
    "pilot_b": (LEGACY_V0_1_ROOT / "pilot_b",),
    "v0_2_dev": (REPO_ROOT / "configs" / "mvp" / "v0_2" / "dev",),
    "v0_2_test": (REPO_ROOT / "configs" / "mvp" / "v0_2" / "test",),
    "v0_2_full": (
        REPO_ROOT / "configs" / "mvp" / "v0_2" / "dev",
        REPO_ROOT / "configs" / "mvp" / "v0_2" / "test",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assemble the HoneyGuard MVP benchmark YAMLs into one runnable directory."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Target directory for the assembled YAML files.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Optional source directory. Can be provided multiple times. Defaults to configs/mvp/_archive/v0_1_splits/dev and configs/mvp/_archive/v0_1_splits/formal.",
    )
    parser.add_argument(
        "--split",
        choices=sorted(PRESET_SOURCES.keys()),
        default="full",
        help="Preset source split. Ignored if --source is provided. Default: full.",
    )
    return parser.parse_args()


def load_task_id(path: Path) -> str:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    task_id = data.get("task_id")
    if isinstance(task_id, str) and task_id.strip():
        return task_id.strip()
    return path.stem


def resolve_copy_source(path: Path) -> Path:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")

    scenario = data.get("scenario")
    if set(data.keys()) == {"scenario"} and isinstance(scenario, str) and scenario.strip().endswith((".yaml", ".yml")):
        target = Path(scenario.strip())
        if not target.is_absolute():
            target = (REPO_ROOT / target).resolve()
        else:
            target = target.resolve()
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(f"wrapper scenario target does not exist: {target}")
        return target

    return path


def collect_yaml_files(source_dirs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for source_dir in source_dirs:
        if not source_dir.exists():
            raise FileNotFoundError(f"source directory does not exist: {source_dir}")
        if not source_dir.is_dir():
            raise NotADirectoryError(f"source is not a directory: {source_dir}")
        files.extend(sorted(source_dir.glob("*.yaml")))
    if not files:
        raise FileNotFoundError("no YAML files found in the selected source directories")
    return files


def assemble(files: list[Path], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    seen_task_ids: dict[str, Path] = {}
    seen_names: dict[str, Path] = {}

    for src in files:
        copy_source = resolve_copy_source(src)
        task_id = load_task_id(copy_source)
        if task_id in seen_task_ids:
            raise ValueError(f"duplicate task_id {task_id!r}: {seen_task_ids[task_id]} and {copy_source}")
        seen_task_ids[task_id] = copy_source

        if src.name in seen_names:
            raise ValueError(f"duplicate filename {src.name!r}: {seen_names[src.name]} and {src}")
        seen_names[src.name] = src

        shutil.copy2(copy_source, output_dir / src.name)

    print(f"ASSEMBLED_COUNT {len(files)}")
    print(f"OUTPUT_DIR {output_dir}")


def main() -> int:
    args = parse_args()
    source_dirs = [Path(p).resolve() for p in args.source] if args.source else list(PRESET_SOURCES[args.split])
    output_dir = Path(args.output).resolve()

    try:
        files = collect_yaml_files(source_dirs)
        assemble(files, output_dir)
    except Exception as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
