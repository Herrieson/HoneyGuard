#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from generate_from_seed import (
    ATTACK_INTENT_OPTIONS,
    PROMPT_VERSION_DEFAULT,
    ProviderConfig,
    LLMOrchestrator,
    ScenarioGeneratorV2,
    _slugify_seed,
)

SURFACE_OPTIONS = ("auto", "enterprise", "user", "hybrid")


@dataclass
class SeedCase:
    index: int
    scenario_name: str
    target_surface: str
    attack_intent: str
    attack_intent_note: str
    seed: str
    output_relpath: str


@dataclass
class BatchConfig:
    provider: str
    model_version: str
    base_url: Optional[str]
    azure_endpoint: Optional[str]
    azure_api_version: Optional[str]
    api_key: str
    temperature: float
    llm_max_retries: int
    prompt_version: str
    max_steps: int


def _normalize_surface(value: str, default_value: str) -> str:
    token = (value or "").strip().lower() or default_value
    if token not in SURFACE_OPTIONS:
        raise ValueError(f"invalid target_surface '{token}', expected one of {SURFACE_OPTIONS}")
    return token


def _normalize_intent(value: str, default_value: str) -> str:
    token = (value or "").strip().lower() or default_value
    if token not in ATTACK_INTENT_OPTIONS:
        raise ValueError(f"invalid attack_intent '{token}', expected one of {ATTACK_INTENT_OPTIONS}")
    return token


def _normalize_name(name: str, seed: str) -> str:
    raw = (name or "").strip()
    if not raw:
        raw = _slugify_seed(seed)
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw).strip("_")
    if not slug:
        slug = _slugify_seed(seed)
    return slug[:120]


def _default_output_relpath(scenario_name: str) -> str:
    return f"{scenario_name}.yaml"


def _resolve_api_key(args: argparse.Namespace) -> str:
    provider = args.provider.lower()
    key = os.getenv(args.api_key_env)
    if provider == "azure" and not key:
        key = os.getenv(args.azure_api_key_env)
    if not key:
        hint = args.azure_api_key_env if provider == "azure" else args.api_key_env
        raise ValueError(f"Missing API key in env: {hint}")
    return key


def _resolve_model(args: argparse.Namespace) -> str:
    if args.provider.lower() == "azure":
        deployment = os.getenv(args.azure_deployment_env)
        if deployment:
            return deployment
    return args.model


def _load_cases(args: argparse.Namespace) -> List[SeedCase]:
    seeds_file = Path(args.seeds_file)
    if not seeds_file.is_file():
        raise FileNotFoundError(f"seeds file not found: {seeds_file}")

    with seeds_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames is None:
            raise ValueError("seeds file must include a header row")

        columns = {c.strip() for c in reader.fieldnames if c}
        if "seed" not in columns:
            raise ValueError("seeds file must include a 'seed' column")

        cases: List[SeedCase] = []
        out_paths = set()

        for idx, row in enumerate(reader, start=2):
            seed = str((row or {}).get("seed") or "").strip()
            if not seed:
                continue

            scenario_name = _normalize_name(str((row or {}).get("scenario_name") or ""), seed)
            target_surface = _normalize_surface(str((row or {}).get("target_surface") or ""), args.target_surface)
            attack_intent = _normalize_intent(str((row or {}).get("attack_intent") or ""), args.attack_intent)

            note = str((row or {}).get("attack_intent_note") or "").strip()
            attack_intent_note = note if note else args.attack_intent_note

            rel = str((row or {}).get("output_relpath") or "").strip()
            output_relpath = rel if rel else _default_output_relpath(scenario_name)
            output_relpath = output_relpath.replace("\\", "/")
            if output_relpath.startswith("/"):
                raise ValueError(f"line {idx}: output_relpath must be relative, got '{output_relpath}'")
            if ".." in Path(output_relpath).parts:
                raise ValueError(f"line {idx}: output_relpath must not contain '..', got '{output_relpath}'")

            if output_relpath in out_paths:
                raise ValueError(f"duplicate output_relpath in seeds file: {output_relpath}")
            out_paths.add(output_relpath)

            cases.append(
                SeedCase(
                    index=len(cases) + 1,
                    scenario_name=scenario_name,
                    target_surface=target_surface,
                    attack_intent=attack_intent,
                    attack_intent_note=attack_intent_note,
                    seed=seed,
                    output_relpath=output_relpath,
                )
            )

    if not cases:
        raise ValueError("no valid seed rows found in seeds file")
    return cases


def _build_batch_cfg(args: argparse.Namespace) -> BatchConfig:
    provider = args.provider.lower()
    model_version = _resolve_model(args)
    api_key = _resolve_api_key(args)
    azure_endpoint = os.getenv(args.azure_endpoint_env) if provider == "azure" else None
    azure_api_version = os.getenv(args.azure_api_version_env) if provider == "azure" else None

    return BatchConfig(
        provider=provider,
        model_version=model_version,
        base_url=args.base_url,
        azure_endpoint=azure_endpoint,
        azure_api_version=azure_api_version,
        api_key=api_key,
        temperature=args.temperature,
        llm_max_retries=max(1, args.llm_max_retries),
        prompt_version=args.prompt_version,
        max_steps=max(1, args.max_steps),
    )


def _build_pipeline(batch_cfg: BatchConfig, case: SeedCase) -> ScenarioGeneratorV2:
    llm_cfg = ProviderConfig(
        provider=batch_cfg.provider,
        model=batch_cfg.model_version,
        base_url=batch_cfg.base_url,
        azure_endpoint=batch_cfg.azure_endpoint,
        azure_api_version=batch_cfg.azure_api_version,
        api_key=batch_cfg.api_key,
        temperature=batch_cfg.temperature,
        max_retries=batch_cfg.llm_max_retries,
    )
    llm = LLMOrchestrator(llm_cfg)
    return ScenarioGeneratorV2(
        llm=llm,
        target_surface_mode=case.target_surface,
        attack_intent_mode=case.attack_intent,
        attack_intent_note=case.attack_intent_note,
    )


def _run_one_case(
    args: argparse.Namespace,
    batch_cfg: BatchConfig,
    case: SeedCase,
    output_dir: Path,
) -> Dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    output_path = output_dir / case.output_relpath

    if output_path.exists():
        if args.resume:
            return {
                "status": "skipped",
                "reason": "exists",
                "case_index": case.index,
                "scenario_name": case.scenario_name,
                "seed": case.seed,
                "target_surface": case.target_surface,
                "attack_intent_mode": case.attack_intent,
                "attack_intent": "unknown",
                "attack_intent_note": case.attack_intent_note,
                "output": str(output_path.resolve()),
                "attempts": 0,
                "duration_sec": round(time.perf_counter() - t0, 4),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }
        if not args.overwrite:
            return {
                "status": "failed",
                "error": f"output already exists: {output_path} (use --resume or --overwrite)",
                "case_index": case.index,
                "scenario_name": case.scenario_name,
                "seed": case.seed,
                "target_surface": case.target_surface,
                "attack_intent_mode": case.attack_intent,
                "attack_intent": "unknown",
                "attack_intent_note": case.attack_intent_note,
                "output": str(output_path.resolve()),
                "attempts": 0,
                "duration_sec": round(time.perf_counter() - t0, 4),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }

    attempts_total = max(1, args.max_retries_per_case + 1)
    last_error = ""

    for attempt in range(1, attempts_total + 1):
        try:
            pipeline = _build_pipeline(batch_cfg, case)

            world = pipeline.generate_world(case.seed)
            plot = pipeline.generate_plot(case.seed, world)
            merged_for_acceptance = pipeline._merge_files(world.files, plot.attack_artifacts)
            pipeline._ensure_state_targets(merged_for_acceptance, plot.expected_state_changes)
            acceptance = pipeline.generate_acceptance(case.seed, world, plot, merged_for_acceptance)

            generated_at = datetime.now(timezone.utc).isoformat()
            cfg = pipeline.compose_config(
                scenario_name=case.scenario_name,
                seed=case.seed,
                world=world,
                plot=plot,
                acceptance=acceptance,
                provider=batch_cfg.provider,
                model_version=batch_cfg.model_version,
                prompt_version=batch_cfg.prompt_version,
                generated_at=generated_at,
                max_steps=batch_cfg.max_steps,
            )

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")

            return {
                "status": "success",
                "case_index": case.index,
                "scenario_name": cfg.get("scenario") or case.scenario_name,
                "seed": case.seed,
                "target_surface": cfg.get("target_surface") or case.target_surface,
                "attack_intent_mode": case.attack_intent,
                "attack_intent": cfg.get("attack_intent") or "unknown",
                "attack_intent_note": cfg.get("attack_intent_note") or case.attack_intent_note,
                "output": str(output_path.resolve()),
                "files": len(cfg.get("files", {})),
                "acceptance_criteria": len(cfg.get("acceptance_criteria", [])),
                "attempts": attempt,
                "duration_sec": round(time.perf_counter() - t0, 4),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "model_version": cfg.get("generation_meta", {}).get("model_version", batch_cfg.model_version),
                "prompt_version": cfg.get("generation_meta", {}).get("prompt_version", batch_cfg.prompt_version),
                "generated_at": cfg.get("generation_meta", {}).get("generated_at", generated_at),
            }
        except Exception as exc:  # pragma: no cover
            last_error = str(exc)
            if attempt >= attempts_total:
                break
            time.sleep(args.retry_backoff_sec * attempt)

    return {
        "status": "failed",
        "error": last_error or "unknown error",
        "case_index": case.index,
        "scenario_name": case.scenario_name,
        "seed": case.seed,
        "target_surface": case.target_surface,
        "attack_intent_mode": case.attack_intent,
        "attack_intent": "unknown",
        "attack_intent_note": case.attack_intent_note,
        "output": str(output_path.resolve()),
        "attempts": attempts_total,
        "duration_sec": round(time.perf_counter() - t0, 4),
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


def _write_manifest(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _build_summary(
    args: argparse.Namespace,
    batch_cfg: BatchConfig,
    seeds_file: Path,
    output_dir: Path,
    manifest_path: Path,
    rows: List[Dict[str, Any]],
    elapsed_sec: float,
) -> Dict[str, Any]:
    status_counter = Counter(str(r.get("status") or "unknown") for r in rows)
    intent_counter = Counter(str(r.get("attack_intent") or "unknown") for r in rows if r.get("status") == "success")
    surface_counter = Counter(str(r.get("target_surface") or "unknown") for r in rows if r.get("status") == "success")

    failed_examples: List[Dict[str, Any]] = []
    for row in rows:
        if row.get("status") != "failed":
            continue
        failed_examples.append(
            {
                "case_index": row.get("case_index"),
                "scenario_name": row.get("scenario_name"),
                "error": row.get("error", ""),
            }
        )
        if len(failed_examples) >= 20:
            break

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "batch_name": args.batch_name,
        "seeds_file": str(seeds_file.resolve()),
        "output_dir": str(output_dir.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "provider": batch_cfg.provider,
        "model_version": batch_cfg.model_version,
        "prompt_version": batch_cfg.prompt_version,
        "workers": args.workers,
        "llm_max_retries": args.llm_max_retries,
        "max_retries_per_case": args.max_retries_per_case,
        "elapsed_sec": round(elapsed_sec, 4),
        "total": len(rows),
        "status_counts": dict(status_counter),
        "success_by_attack_intent": dict(sorted(intent_counter.items())),
        "success_by_target_surface": dict(sorted(surface_counter.items())),
        "failed_examples": failed_examples,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch-generate HoneyGuard scenarios from TSV seed list.")
    parser.add_argument("--seeds-file", required=True, help="TSV file with header; must include 'seed' column")
    parser.add_argument("--output-dir", required=True, help="Directory to write generated YAML files")
    parser.add_argument("--batch-name", default="seed_batch_v2", help="Name for summary/manifest metadata")

    parser.add_argument("--target-surface", default="auto", choices=list(SURFACE_OPTIONS), help="Default target_surface")
    parser.add_argument(
        "--attack-intent",
        default="auto",
        choices=list(ATTACK_INTENT_OPTIONS),
        help="Default attack intent when row value is empty",
    )
    parser.add_argument("--attack-intent-note", default="", help="Default attack intent note when row value is empty")
    parser.add_argument("--max-steps", type=int, default=10, help="Scenario max steps")

    parser.add_argument("--workers", type=int, default=4, help="Parallel workers")
    parser.add_argument("--max-retries-per-case", type=int, default=1, help="Retry count for each failed case")
    parser.add_argument("--retry-backoff-sec", type=float, default=1.0, help="Base retry backoff seconds")
    parser.add_argument("--resume", action="store_true", help="Skip cases whose output file already exists")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs")
    parser.add_argument("--fail-fast", action="store_true", help="Stop processing once one case fails")

    parser.add_argument("--provider", default="azure", choices=["openai", "azure"], help="LLM provider")
    parser.add_argument("--model", default="gpt-4o", help="Model/deployment name")
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible base URL")
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY", help="OpenAI API key env")
    parser.add_argument("--azure-api-key-env", default="AZURE_OPENAI_API_KEY", help="Azure API key env")
    parser.add_argument("--azure-endpoint-env", default="AZURE_OPENAI_ENDPOINT", help="Azure endpoint env")
    parser.add_argument("--azure-api-version-env", default="AZURE_OPENAI_API_VERSION", help="Azure api version env")
    parser.add_argument("--azure-deployment-env", default="AZURE_OPENAI_DEPLOYMENT", help="Azure deployment env")
    parser.add_argument("--temperature", type=float, default=0.4, help="LLM temperature")
    parser.add_argument("--llm-max-retries", type=int, default=3, help="Retries per LLM stage")
    parser.add_argument(
        "--prompt-version",
        default=PROMPT_VERSION_DEFAULT,
        help="Prompt contract version written to generation_meta",
    )

    parser.add_argument("--manifest-path", default="", help="Optional manifest jsonl path")
    parser.add_argument("--summary-path", default="", help="Optional summary json path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.overwrite and args.resume:
        raise SystemExit("--overwrite and --resume cannot be used together")

    seeds_file = Path(args.seeds_file)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = Path(args.manifest_path) if args.manifest_path else output_dir / "_batch_manifest.jsonl"
    summary_path = Path(args.summary_path) if args.summary_path else output_dir / "_batch_summary.json"

    batch_cfg = _build_batch_cfg(args)
    cases = _load_cases(args)

    started = time.perf_counter()
    results: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(_run_one_case, args, batch_cfg, case, output_dir): case
            for case in cases
        }

        for future in as_completed(future_map):
            case = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover
                result = {
                    "status": "failed",
                    "case_index": case.index,
                    "scenario_name": case.scenario_name,
                    "seed": case.seed,
                    "target_surface": case.target_surface,
                    "attack_intent_mode": case.attack_intent,
                    "attack_intent": "unknown",
                    "attack_intent_note": case.attack_intent_note,
                    "output": str((output_dir / case.output_relpath).resolve()),
                    "attempts": 0,
                    "duration_sec": 0.0,
                    "error": str(exc),
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }

            results.append(result)
            status = result.get("status", "unknown")
            print(
                json.dumps(
                    {
                        "status": status,
                        "case_index": result.get("case_index"),
                        "scenario_name": result.get("scenario_name"),
                        "attack_intent": result.get("attack_intent"),
                        "target_surface": result.get("target_surface"),
                        "output": result.get("output"),
                        "error": result.get("error", ""),
                    },
                    ensure_ascii=False,
                )
            )

            if args.fail_fast and status == "failed":
                for pending in future_map:
                    if pending is not future:
                        pending.cancel()
                break

    results_sorted = sorted(results, key=lambda x: int(x.get("case_index") or 0))
    _write_manifest(manifest_path, results_sorted)

    elapsed = time.perf_counter() - started
    summary = _build_summary(args, batch_cfg, seeds_file, output_dir, manifest_path, results_sorted, elapsed)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    final = {
        "batch_name": args.batch_name,
        "seeds_file": str(seeds_file.resolve()),
        "output_dir": str(output_dir.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "summary_path": str(summary_path.resolve()),
        "total": summary["total"],
        "status_counts": summary["status_counts"],
        "success_by_attack_intent": summary["success_by_attack_intent"],
        "elapsed_sec": summary["elapsed_sec"],
    }
    print(json.dumps(final, ensure_ascii=False, indent=2))

    if summary["status_counts"].get("failed", 0) > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
