#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List


EXP_NAME = "mvp_compositional_playground"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


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
    numeric = to_float(value)
    if numeric is not None:
        if numeric == 1.0:
            return True
        if numeric == 0.0:
            return False
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def fmt(value: Any) -> str:
    numeric = to_float(value)
    if numeric is None:
        return ""
    return f"{numeric:.3f}"


def safe_mean(values: Iterable[float | None]) -> float | None:
    nums = [value for value in values if value is not None]
    return mean(nums) if nums else None


def discover_runs(root: Path) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    exp_dir = root / EXP_NAME
    if not exp_dir.exists():
        return runs
    for run_dir in sorted(exp_dir.glob("*")):
        if not run_dir.is_dir():
            continue
        manifest_path = run_dir / "manifest.json"
        summary_path = run_dir / "scores" / "outcome.summary.json"
        rows_path = run_dir / "scores" / "outcome.rows.csv"
        if not manifest_path.exists() or not summary_path.exists() or not rows_path.exists():
            continue
        runs.append(
            {
                "run_dir": run_dir,
                "manifest": load_json(manifest_path),
                "summary": load_json(summary_path),
                "rows": load_csv(rows_path),
            }
        )
    return runs


def split_list(raw: Any) -> list[str]:
    if raw in (None, "", "None"):
        return []
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw)
    if "|" in text:
        return [part.strip() for part in text.split("|") if part.strip()]
    return [text.strip()] if text.strip() else []


def row_metric(row: dict[str, Any], key: str) -> float | None:
    if key in {"task_success", "safety_violation", "stcr_success", "attack_success", "resource_overrun", "internal_message_exposure", "unsafe_internal_message_exposure"}:
        value = boolish(row.get(key))
        if value is None:
            return None
        return 1.0 if value else 0.0
    if key in {"latent_violation_rate"}:
        labels = row.get("latent_violation_labels")
        if labels not in (None, "", "None"):
            return 1.0
        return to_float(row.get("latent_violation_rate")) or 0.0
    return to_float(row.get(key))


def aggregate_rows(rows: list[dict[str, Any]], metric_keys: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {"n": len(rows), "evaluable_n": sum(1 for row in rows if boolish(row.get("evaluable")))}
    for key in metric_keys:
        result[key] = fmt(safe_mean(row_metric(row, key) for row in rows))
    return result


def summary_row(run: dict[str, Any]) -> dict[str, Any]:
    manifest = run["manifest"]
    summary = run["summary"]
    return {
        "model": manifest.get("model_label", ""),
        "baseline": manifest.get("baseline", ""),
        "recipe_id": (manifest.get("playground_manifest") or {}).get("recipe_id", ""),
        "run_name": run["run_dir"].name,
        "num_runs": summary.get("num_runs", ""),
        "num_evaluable_runs": summary.get("num_evaluable_runs", ""),
        "TSR": fmt(summary.get("TSR")),
        "SVR": fmt(summary.get("SVR")),
        "STCR": fmt(summary.get("STCR")),
        "ASR": fmt(summary.get("ASR")),
        "resource_overrun_rate": fmt(summary.get("resource_overrun_rate")),
        "latent_violation_rate": fmt(summary.get("latent_violation_rate")),
        "internal_message_exposure_rate": fmt(summary.get("internal_message_exposure_rate")),
        "unsafe_internal_message_exposure_rate": fmt(summary.get("unsafe_internal_message_exposure_rate")),
        "mean_first_failure_step": fmt(summary.get("mean_first_failure_step")),
        "mean_failure_lead_time": fmt(summary.get("mean_failure_lead_time")),
    }


def scenario_rows(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    metric_keys = [
        "task_success",
        "safety_violation",
        "stcr_success",
        "attack_success",
        "resource_overrun",
        "internal_message_exposure",
        "unsafe_internal_message_exposure",
        "latent_violation_rate",
        "first_failure_step",
        "harmful_action_step",
        "failure_lead_time",
    ]
    for run in runs:
        manifest = run["manifest"]
        for row in run["rows"]:
            composition_group_id = row.get("composition_group_id") or ""
            output.append(
                {
                    "model": manifest.get("model_label", ""),
                    "baseline": manifest.get("baseline", ""),
                    "run_name": run["run_dir"].name,
                    "task_id": row.get("task_id", ""),
                    "family": row.get("family", ""),
                    "recipe_id": row.get("recipe_id", ""),
                    "composition_group_id": composition_group_id,
                    "composition_scenario_id": row.get("composition_scenario_id", ""),
                    "composition_type": row.get("composition_type", ""),
                    "scenario_role": row.get("scenario_role", ""),
                    "substrate_id": row.get("substrate_id", ""),
                    "hazard_ids": row.get("hazard_ids", ""),
                    "hazard_families": row.get("hazard_families", ""),
                    "hazard_channels": row.get("hazard_channels", ""),
                    "hazard_sources": row.get("hazard_sources", ""),
                    "dominant_hazard_hypothesis": row.get("dominant_hazard_hypothesis", ""),
                    "interaction_hypothesis": row.get("interaction_hypothesis", ""),
                    "order_index": row.get("order_index", ""),
                    **aggregate_rows([row], metric_keys),
                }
            )
    return output


def group_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (str(row.get("model") or ""), str(row.get("baseline") or ""), str(row.get("composition_group_id") or ""))
        groups[key].append(row)

    output: list[dict[str, Any]] = []
    metric_keys = [
        "task_success",
        "safety_violation",
        "stcr_success",
        "attack_success",
        "resource_overrun",
        "internal_message_exposure",
        "unsafe_internal_message_exposure",
        "latent_violation_rate",
        "first_failure_step",
        "harmful_action_step",
        "failure_lead_time",
    ]
    for (model, baseline, group_id), group_rows_items in sorted(groups.items()):
        roles = defaultdict(list)
        for row in group_rows_items:
            roles[str(row.get("scenario_role") or "unknown")].append(row)
        all_hazards = sorted(
            {
                hazard
                for row in group_rows_items
                for hazard in split_list(row.get("hazard_ids"))
                if hazard
            }
        )
        first = lambda key: next((str(row.get(key) or "") for row in group_rows_items if str(row.get(key) or "")), "")
        output.append(
            {
                "model": model,
                "baseline": baseline,
                "composition_group_id": group_id,
                "recipe_id": first("recipe_id"),
                "composition_type": first("composition_type"),
                "substrate_id": first("substrate_id"),
                "hazard_ids": "|".join(all_hazards),
                "dominant_hazard_hypothesis": first("dominant_hazard_hypothesis"),
                "interaction_hypothesis": first("interaction_hypothesis"),
                "clean": fmt(safe_mean(row_metric(row, "safety_violation") for row in roles.get("clean", []))),
                "single": fmt(safe_mean(row_metric(row, "safety_violation") for row in roles.get("single", []))),
                "combo": fmt(safe_mean(row_metric(row, "safety_violation") for row in roles.get("combo", []))),
                "combo_reverse": fmt(safe_mean(row_metric(row, "safety_violation") for row in roles.get("combo_reverse", []))),
                "single_latent": fmt(safe_mean(row_metric(row, "latent_violation_rate") for row in roles.get("single", []))),
                "combo_latent": fmt(safe_mean(row_metric(row, "latent_violation_rate") for row in roles.get("combo", []))),
                "combo_reverse_latent": fmt(safe_mean(row_metric(row, "latent_violation_rate") for row in roles.get("combo_reverse", []))),
                "single_internal": fmt(safe_mean(row_metric(row, "unsafe_internal_message_exposure") for row in roles.get("single", []))),
                "combo_internal": fmt(safe_mean(row_metric(row, "unsafe_internal_message_exposure") for row in roles.get("combo", []))),
                "n": len(group_rows_items),
                "clean_n": len(roles.get("clean", [])),
                "single_n": len(roles.get("single", [])),
                "combo_n": len(roles.get("combo", [])),
                "combo_reverse_n": len(roles.get("combo_reverse", [])),
                "scenario_roles": "|".join(sorted(roles.keys())),
            }
        )
    return output


def interaction_rows(group_rows_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in group_rows_data:
        clean = to_float(row.get("clean"))
        single = to_float(row.get("single"))
        combo = to_float(row.get("combo"))
        combo_reverse = to_float(row.get("combo_reverse"))
        if combo is None and single is None and clean is None:
            continue
        output.append(
            {
                **{key: row.get(key, "") for key in ("model", "baseline", "composition_group_id", "recipe_id", "composition_type", "substrate_id", "hazard_ids", "dominant_hazard_hypothesis", "interaction_hypothesis")},
                "safety_delta_vs_clean": fmt((combo - clean) if combo is not None and clean is not None else None),
                "single_vs_clean": fmt((single - clean) if single is not None and clean is not None else None),
                "combo_vs_single_mean": fmt((combo - single) if combo is not None and single is not None else None),
                "combo_reverse_vs_combo": fmt((combo_reverse - combo) if combo_reverse is not None and combo is not None else None),
                "combo_reverse_present": str(bool(combo_reverse is not None)),
            }
        )
    return output


def order_effect_rows(group_rows_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in group_rows_data:
        combo = to_float(row.get("combo"))
        combo_reverse = to_float(row.get("combo_reverse"))
        if combo is None or combo_reverse is None:
            continue
        output.append(
            {
                **{key: row.get(key, "") for key in ("model", "baseline", "composition_group_id", "recipe_id", "substrate_id", "hazard_ids", "dominant_hazard_hypothesis")},
                "combo_safety_violation": fmt(combo),
                "reverse_safety_violation": fmt(combo_reverse),
                "order_delta": fmt(combo_reverse - combo),
                "combo_latent": row.get("combo_latent", ""),
                "reverse_latent": row.get("combo_reverse_latent", ""),
            }
        )
    return output


def dominance_rows(scenario_rows_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in scenario_rows_data:
        key = (str(row.get("model") or ""), str(row.get("baseline") or ""), str(row.get("composition_group_id") or ""))
        groups[key].append(row)

    output: list[dict[str, Any]] = []
    for (model, baseline, group_id), rows in sorted(groups.items()):
        clean_rows = [row for row in rows if row.get("scenario_role") == "clean"]
        single_rows = [row for row in rows if row.get("scenario_role") == "single"]
        combo_rows = [row for row in rows if row.get("scenario_role") == "combo"]
        clean = safe_mean(row_metric(row, "safety_violation") for row in clean_rows)
        combo = safe_mean(row_metric(row, "safety_violation") for row in combo_rows)
        if clean is None or not single_rows:
            continue

        by_hazard: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in single_rows:
            hazards = split_list(row.get("hazard_ids"))
            if len(hazards) == 1:
                by_hazard[hazards[0]].append(row)
        if len(by_hazard) < 2:
            continue

        single_effects: dict[str, float] = {}
        single_rates: dict[str, float] = {}
        for hazard_id, items in by_hazard.items():
            rate = safe_mean(row_metric(row, "safety_violation") for row in items)
            if rate is None:
                continue
            single_rates[hazard_id] = rate
            single_effects[hazard_id] = rate - clean
        if not single_effects:
            continue
        observed_dominant = max(single_effects.items(), key=lambda item: (item[1], item[0]))[0]
        combo_closest = ""
        if combo is not None and single_rates:
            combo_closest = min(single_rates.items(), key=lambda item: (abs(item[1] - combo), item[0]))[0]

        dominant_hypothesis = next((str(row.get("dominant_hazard_hypothesis") or "") for row in rows if row.get("dominant_hazard_hypothesis")), "")
        recipe_id = next((str(row.get("recipe_id") or "") for row in rows if row.get("recipe_id")), "")
        substrate_id = next((str(row.get("substrate_id") or "") for row in rows if row.get("substrate_id")), "")
        output.append(
            {
                "model": model,
                "baseline": baseline,
                "composition_group_id": group_id,
                "recipe_id": recipe_id,
                "substrate_id": substrate_id,
                "hazard_ids": "|".join(sorted(by_hazard.keys())),
                "dominant_hazard_hypothesis": dominant_hypothesis,
                "observed_single_safety": json.dumps({key: fmt(value) for key, value in sorted(single_rates.items())}, ensure_ascii=False),
                "clean_safety": fmt(clean),
                "observed_effect": json.dumps({key: fmt(value) for key, value in sorted(single_effects.items())}, ensure_ascii=False),
                "combo_safety": fmt(combo),
                "observed_dominance_guess": observed_dominant,
                "combo_closest_single": combo_closest,
                "dominance_match": str(observed_dominant == dominant_hypothesis),
                "combo_closest_match": str(combo_closest == dominant_hypothesis),
            }
        )
    return output


def build_summary(runs: list[dict[str, Any]], scenario_rows_data: list[dict[str, Any]], group_rows_data: list[dict[str, Any]], output_dir: Path) -> None:
    run_summary = [summary_row(run) for run in sorted(runs, key=lambda item: (item["manifest"].get("model_label", ""), item["manifest"].get("baseline", ""), item["run_dir"].name))]
    write_csv(output_dir / "run_summary.csv", run_summary, list(run_summary[0].keys()) if run_summary else [])
    write_csv(output_dir / "scenario_summary.csv", scenario_rows_data, list(scenario_rows_data[0].keys()) if scenario_rows_data else [])
    write_csv(output_dir / "group_summary.csv", group_rows_data, list(group_rows_data[0].keys()) if group_rows_data else [])
    write_csv(output_dir / "interaction_summary.csv", interaction_rows(group_rows_data), [
        "model",
        "baseline",
        "composition_group_id",
        "recipe_id",
        "composition_type",
        "substrate_id",
        "hazard_ids",
        "dominant_hazard_hypothesis",
        "interaction_hypothesis",
        "safety_delta_vs_clean",
        "single_vs_clean",
        "combo_vs_single_mean",
        "combo_reverse_vs_combo",
        "combo_reverse_present",
    ])
    write_csv(output_dir / "order_effects.csv", order_effect_rows(group_rows_data), [
        "model",
        "baseline",
        "composition_group_id",
        "recipe_id",
        "substrate_id",
        "hazard_ids",
        "dominant_hazard_hypothesis",
        "combo_safety_violation",
        "reverse_safety_violation",
        "order_delta",
        "combo_latent",
        "reverse_latent",
    ])
    write_csv(output_dir / "dominance_summary.csv", dominance_rows(scenario_rows_data), [
        "model",
        "baseline",
        "composition_group_id",
        "recipe_id",
        "substrate_id",
        "hazard_ids",
        "dominant_hazard_hypothesis",
        "observed_single_safety",
        "clean_safety",
        "observed_effect",
        "combo_safety",
        "observed_dominance_guess",
        "combo_closest_single",
        "dominance_match",
        "combo_closest_match",
    ])

    md: list[str] = ["# HoneyGuard Compositional Playground Analysis", ""]
    md.append("## Run summary")
    if run_summary:
        md.append("| Model | Baseline | Run | TSR | SVR | STCR | ASR | Latent | Unsafe IntExp |")
        md.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for row in run_summary:
            md.append(
                "| {model} | {baseline} | {run_name} | {TSR} | {SVR} | {STCR} | {ASR} | {latent_violation_rate} | {unsafe_internal_message_exposure_rate} |".format(
                    **row
                )
            )
    md.append("")
    md.append("## Group interactions")
    if group_rows_data:
        md.append("| Model | Baseline | Group | Roles | Clean | Single | Combo | Reverse | Hypothesis |")
        md.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for row in group_rows_data:
            md.append(
                "| {model} | {baseline} | {composition_group_id} | {scenario_roles} | {clean} | {single} | {combo} | {combo_reverse} | {dominant_hazard_hypothesis} |".format(
                    **row
                )
            )
    md.append("")
    md.append("## Files")
    for path in sorted(output_dir.glob("*.csv")):
        md.append(f"- `{path}`")
    (output_dir / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze HoneyGuard compositional playground results.")
    parser.add_argument("--root", default="artifacts/experiments/mvp")
    parser.add_argument("--output", default="artifacts/analysis/mvp/compositional_playground")
    args = parser.parse_args()

    runs = discover_runs(Path(args.root))
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    scenario_rows_data = scenario_rows(runs)
    group_rows_data = group_rows(scenario_rows_data)
    build_summary(runs, scenario_rows_data, group_rows_data, outdir)
    print(f"WROTE {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
