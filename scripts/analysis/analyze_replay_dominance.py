#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.common import write_json


SIGNAL_KEYS = (
    ("sensitive_read", "sensitive_read"),
    ("sensitive_access", "sensitive_access"),
    ("untrusted_sink", "untrusted_sink"),
    ("step_risk_positive", "risk_positive"),
    ("step_safety_failure", "safety_failure"),
    ("step_utility_failure", "utility_failure"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze replay evidence for compositional playground dominance, masking, "
            "amplification, and order effects."
        )
    )
    parser.add_argument("--rows-jsonl", required=True, help="Run-level output from replay_run_trace.py.")
    parser.add_argument("--steps-jsonl", default="", help="Step-level output from replay_run_trace.py.")
    parser.add_argument("--output-dir", required=True, help="Directory for dominance analysis outputs.")
    parser.add_argument("--model-label", default="", help="Optional model label to attach to rows.")
    parser.add_argument("--baseline", default="", help="Optional baseline label to attach to rows.")
    parser.add_argument("--run-name", default="", help="Optional run name to attach to rows.")
    return parser.parse_args()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def serialize_csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames: List[str] = []
    seen = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: serialize_csv_value(row.get(key)) for key in fieldnames})


def boolish(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value in (None, "", "None"):
        return None
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def intish(value: Any) -> Optional[int]:
    if value in (None, "", "None"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def split_list(raw: Any) -> List[str]:
    if raw in (None, "", "None"):
        return []
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw)
    if "|" in text:
        return [part.strip() for part in text.split("|") if part.strip()]
    return [text.strip()] if text.strip() else []


def first_nonempty(rows: Iterable[Dict[str, Any]], key: str) -> str:
    for row in rows:
        value = row.get(key)
        if value not in (None, "", "None"):
            return str(value)
    return ""


def event_sequence(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for step in sorted(steps, key=lambda item: intish(item.get("step_id")) or 0):
        step_id = intish(step.get("step_id"))
        for key, signal in SIGNAL_KEYS:
            if boolish(step.get(key)) is True:
                events.append(
                    {
                        "step_id": step_id,
                        "signal": signal,
                        "tool_name": step.get("tool_name") or "",
                        "status": step.get("status") or "",
                    }
                )
    return events


def run_events_from_row(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = [
        ("first_sensitive_read_step", "sensitive_read"),
        ("first_sensitive_access_step", "sensitive_access"),
        ("first_untrusted_sink_step", "untrusted_sink"),
        ("first_risk_positive_step", "risk_positive"),
        ("first_safety_failure_step", "safety_failure"),
        ("first_utility_failure_step", "utility_failure"),
    ]
    events: List[Dict[str, Any]] = []
    for key, signal in candidates:
        step_id = intish(row.get(key))
        if step_id is not None:
            events.append({"step_id": step_id, "signal": signal, "tool_name": "", "status": ""})
    return sorted(events, key=lambda item: (item.get("step_id") or 0, item.get("signal") or ""))


def run_info(row: Dict[str, Any], steps_by_session: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    session_id = str(row.get("session_id") or "")
    events = event_sequence(steps_by_session.get(session_id, []))
    if not events:
        events = run_events_from_row(row)
    first_event = events[0] if events else {}
    safety_violation = boolish(row.get("replay_safety_violation"))
    risk_positive = intish(row.get("first_risk_positive_step")) is not None
    active = bool(events) or safety_violation is True or risk_positive is True
    return {
        "row": row,
        "session_id": session_id,
        "role": str(row.get("scenario_role") or ""),
        "hazard_ids": split_list(row.get("hazard_ids")),
        "events": events,
        "active": active,
        "safety_violation": safety_violation,
        "first_event_step": first_event.get("step_id"),
        "first_event_signal": first_event.get("signal") or "",
        "first_event_tool": first_event.get("tool_name") or "",
        "signals": sorted({str(item.get("signal") or "") for item in events if item.get("signal")}),
    }


def overlap_score(single: Dict[str, Any], combo: Dict[str, Any]) -> int:
    if not single.get("events") or not combo.get("events"):
        return 0
    single_first = single["events"][0]
    combo_first = combo["events"][0]
    if (
        single_first.get("signal") == combo_first.get("signal")
        and single_first.get("tool_name")
        and single_first.get("tool_name") == combo_first.get("tool_name")
    ):
        return 4
    if single_first.get("signal") == combo_first.get("signal"):
        return 3
    single_pairs = {(item.get("signal"), item.get("tool_name")) for item in single["events"]}
    combo_pairs = {(item.get("signal"), item.get("tool_name")) for item in combo["events"]}
    if single_pairs & combo_pairs:
        return 2
    if set(single.get("signals") or []) & set(combo.get("signals") or []):
        return 1
    return 0


def overlap_label(score: int) -> str:
    if score >= 4:
        return "first_signal_and_tool_match"
    if score == 3:
        return "first_signal_match"
    if score == 2:
        return "path_signal_and_tool_overlap"
    if score == 1:
        return "path_signal_overlap"
    return "none"


def pick_combo(runs: List[Dict[str, Any]], role: str) -> Optional[Dict[str, Any]]:
    matches = [item for item in runs if item.get("role") == role]
    if not matches:
        return None
    matches.sort(
        key=lambda item: (
            item.get("first_event_step") is None,
            item.get("first_event_step") or 10**9,
            item.get("session_id") or "",
        )
    )
    return matches[0]


def analyze_group(
    group_id: str,
    runs: List[Dict[str, Any]],
    context: Dict[str, str],
) -> Dict[str, Any]:
    combo = pick_combo(runs, "combo")
    reverse = pick_combo(runs, "combo_reverse")
    clean = pick_combo(runs, "clean")
    single_runs = [item for item in runs if item.get("role") == "single" and len(item.get("hazard_ids") or []) == 1]
    singles_by_hazard: Dict[str, Dict[str, Any]] = {
        item["hazard_ids"][0]: item for item in single_runs if item.get("hazard_ids")
    }
    all_hazards = sorted({hazard for item in runs for hazard in item.get("hazard_ids") or [] if hazard})
    hypothesis = first_nonempty([item["row"] for item in runs], "dominant_hazard_hypothesis")

    overlap: Dict[str, str] = {}
    overlap_scores: Dict[str, int] = {}
    if combo:
        for hazard, single in singles_by_hazard.items():
            score = overlap_score(single, combo)
            overlap_scores[hazard] = score
            overlap[hazard] = overlap_label(score)

    observed_candidates = [
        hazard for hazard, score in sorted(overlap_scores.items(), key=lambda item: (-item[1], item[0])) if score > 0
    ]
    observed_first_hazard = observed_candidates[0] if observed_candidates else ""
    if not combo or not combo.get("active"):
        dominant_supported: Optional[bool] = False if hypothesis else None
    elif not hypothesis or not observed_first_hazard:
        dominant_supported = None
    else:
        dominant_supported = observed_first_hazard == hypothesis

    masked = [
        hazard
        for hazard, single in sorted(singles_by_hazard.items())
        if single.get("active") and overlap_scores.get(hazard, 0) == 0
    ]
    if combo and combo.get("active") is not True:
        masked = [hazard for hazard, single in sorted(singles_by_hazard.items()) if single.get("active")]

    single_active_hazards = {hazard for hazard, single in singles_by_hazard.items() if single.get("active")}
    amplified = []
    if combo and combo.get("active") and not single_active_hazards:
        amplified = all_hazards
    elif combo and combo.get("safety_violation") is True:
        amplified = [hazard for hazard in all_hazards if hazard not in single_active_hazards]

    unactivated = [hazard for hazard in all_hazards if hazard not in single_active_hazards and hazard != observed_first_hazard]

    order_effect = None
    if combo and reverse:
        order_effect = (
            combo.get("safety_violation") != reverse.get("safety_violation")
            or combo.get("first_event_signal") != reverse.get("first_event_signal")
            or combo.get("first_event_step") != reverse.get("first_event_step")
        )

    explanation = ""
    if dominant_supported is True:
        explanation = "combo replay path overlaps with the hypothesized dominant hazard single-control path"
    elif dominant_supported is False and observed_first_hazard:
        explanation = "combo replay path overlaps with a non-hypothesized hazard single-control path"
    elif combo and combo.get("active"):
        explanation = "combo replay is active, but no single-control path overlap was detected"
    else:
        explanation = "combo replay did not activate a replay-observed safety path"

    return {
        **context,
        "composition_group_id": group_id,
        "recipe_id": first_nonempty([item["row"] for item in runs], "recipe_id"),
        "composition_type": first_nonempty([item["row"] for item in runs], "composition_type"),
        "substrate_id": first_nonempty([item["row"] for item in runs], "substrate_id"),
        "hazard_ids": "|".join(all_hazards),
        "dominant_hazard_hypothesis": hypothesis,
        "dominant_hazard_supported": dominant_supported,
        "observed_first_hazard": observed_first_hazard,
        "observed_first_hazard_candidates": "|".join(observed_candidates),
        "single_to_combo_path_overlap": overlap,
        "masked_hazard_ids": "|".join(masked),
        "amplified_hazard_ids": "|".join(amplified),
        "configured_but_unactivated_hazard_ids": "|".join(unactivated),
        "order_effect_detected": order_effect,
        "clean_replay_safety_violation": clean.get("safety_violation") if clean else None,
        "combo_replay_safety_violation": combo.get("safety_violation") if combo else None,
        "combo_first_event_step": combo.get("first_event_step") if combo else None,
        "combo_first_event_signal": combo.get("first_event_signal") if combo else "",
        "combo_first_event_tool": combo.get("first_event_tool") if combo else "",
        "combo_reverse_replay_safety_violation": reverse.get("safety_violation") if reverse else None,
        "combo_reverse_first_event_step": reverse.get("first_event_step") if reverse else None,
        "combo_reverse_first_event_signal": reverse.get("first_event_signal") if reverse else "",
        "combo_reverse_first_event_tool": reverse.get("first_event_tool") if reverse else "",
        "single_active_hazard_ids": "|".join(sorted(single_active_hazards)),
        "single_safety_violating_hazard_ids": "|".join(
            sorted(hazard for hazard, single in singles_by_hazard.items() if single.get("safety_violation") is True)
        ),
        "scenario_roles": "|".join(sorted({str(item.get("role") or "unknown") for item in runs})),
        "num_runs": len(runs),
        "dominance_explanation": explanation,
    }


def build_group_rows(
    rows: List[Dict[str, Any]],
    step_rows: List[Dict[str, Any]],
    args: argparse.Namespace,
) -> List[Dict[str, Any]]:
    steps_by_session: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for step in step_rows:
        steps_by_session[str(step.get("session_id") or "")].append(step)

    context = {
        "model": args.model_label,
        "baseline": args.baseline,
        "run_name": args.run_name,
    }
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        group_id = str(row.get("composition_group_id") or "")
        if not group_id:
            continue
        info = run_info(row, steps_by_session)
        groups[group_id].append(info)

    return [analyze_group(group_id, runs, context) for group_id, runs in sorted(groups.items())]


def build_summary(group_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    support_counts = Counter(str(row.get("dominant_hazard_supported")) for row in group_rows)
    return {
        "num_groups": len(group_rows),
        "dominant_support_counts": dict(sorted(support_counts.items())),
        "num_dominant_supported": sum(1 for row in group_rows if row.get("dominant_hazard_supported") is True),
        "num_dominant_contradicted": sum(1 for row in group_rows if row.get("dominant_hazard_supported") is False),
        "num_order_effect": sum(1 for row in group_rows if row.get("order_effect_detected") is True),
        "num_with_masking": sum(1 for row in group_rows if row.get("masked_hazard_ids")),
        "num_with_amplification": sum(1 for row in group_rows if row.get("amplified_hazard_ids")),
        "num_with_configured_but_unactivated": sum(
            1 for row in group_rows if row.get("configured_but_unactivated_hazard_ids")
        ),
    }


def write_markdown(path: Path, group_rows: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    lines = ["# Replay Dominance Analysis", ""]
    lines.append("## Summary")
    for key, value in summary.items():
        lines.append(f"- `{key}`: {serialize_csv_value(value)}")
    lines.append("")
    lines.append("## Groups")
    if group_rows:
        lines.append(
            "| Group | Hazards | Hypothesis | Observed | Supported | Masked | Amplified | Order effect |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for row in group_rows:
            lines.append(
                "| {composition_group_id} | {hazard_ids} | {dominant_hazard_hypothesis} | "
                "{observed_first_hazard} | {dominant_hazard_supported} | {masked_hazard_ids} | "
                "{amplified_hazard_ids} | {order_effect_detected} |".format(**row)
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    rows = load_jsonl(Path(args.rows_jsonl))
    step_rows = load_jsonl(Path(args.steps_jsonl)) if args.steps_jsonl else []
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    group_rows = build_group_rows(rows, step_rows, args)
    summary = build_summary(group_rows)
    write_jsonl(outdir / "replay_dominance.groups.jsonl", group_rows)
    write_csv(outdir / "replay_dominance.groups.csv", group_rows)
    write_json(outdir / "replay_dominance.summary.json", summary)
    write_markdown(outdir / "summary.md", group_rows, summary)
    print(f"WROTE {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
