#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.scenario.playground_composer import DEFAULT_PLAYGROUND_ROOT, compose_recipe_to_directory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compose HoneyGuard MVP playground scenarios from recipe files.")
    parser.add_argument("--recipe", required=True, help="Recipe YAML path or recipe id.")
    parser.add_argument("--output", required=True, help="Directory that will receive generated scenario YAMLs.")
    parser.add_argument(
        "--playground-root",
        default=str(DEFAULT_PLAYGROUND_ROOT),
        help="Root directory containing substrates/, hazards/, and recipes/ definitions.",
    )
    parser.add_argument(
        "--print-manifest",
        action="store_true",
        help="Print the generation manifest as JSON after composing scenarios.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    recipe_path = Path(args.recipe)
    output_dir = Path(args.output)
    manifest = compose_recipe_to_directory(recipe_path, output_dir, Path(args.playground_root))
    if args.print_manifest:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        print(f"PLAYGROUND_GENERATED {manifest['generated_count']}")
        print(f"PLAYGROUND_OUTPUT {manifest['output_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
