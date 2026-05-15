#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


DIMENSIONS = (
    ("primary_source", "candidate_sources"),
    ("primary_channel", "candidate_channels"),
    ("first_failed_component", "candidate_components"),
    ("primary_mechanism", "candidate_mechanisms"),
    ("primary_impact", "candidate_impacts"),
    ("counterfactual_block_point", "candidate_block_points"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Score attribution predictions against scenario-level expected labels and "
            "check whether each predicted label is supported by cited structured "
            "evidence events."
        )
    )
    parser.add_argument("--evidence-jsonl", required=True, help="Output from extract_attribution_evidence.py.")
    parser.add_argument("--predictions", required=True, help="Attribution predictions JSONL keyed by task_id.")
    parser.add_argument("--output-json", default="", help="Optional summary JSON output path.")
    parser.add_argument("--output-csv", default="", help="Optional per-task CSV output path.")
    return parser.parse_args()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def safe_rate(values: Sequence[Optional[bool]]) -> Optional[float]:
    numeric = [1.0 if value else 0.0 for value in values if value is not None]
    if not numeric:
        return None
    return sum(numeric) / len(numeric)


def safe_mean(values: Sequence[Optional[float]]) -> Optional[float]:
    numeric = [float(value) for value in values if value is not None]
    if not numeric:
        return None
    return sum(numeric) / len(numeric)


def task_map(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    mapping: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        task_id = str(row.get("task_id") or row.get("scenario") or "").strip()
        if task_id:
            mapping[task_id] = row
    return mapping


def prediction_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("attribution_prediction")
    if isinstance(payload, dict):
        return payload
    return row


def support_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("attribution_evidence_support")
    return payload if isinstance(payload, dict) else {}


def extract_label_and_citations(prediction: Dict[str, Any], support: Dict[str, Any], dimension: str) -> Tuple[str, List[str], str]:
    raw = prediction.get(dimension)
    confidence = ""
    event_ids: List[str] = []
    if isinstance(raw, dict):
        label = str(raw.get("label") or "").strip()
        event_ids = [str(item) for item in raw.get("evidence_event_ids") or [] if str(item)]
        confidence = str(raw.get("confidence") or "")
    else:
        label = str(raw or "").strip()

    support_item = support.get(dimension)
    if isinstance(support_item, dict):
        if not event_ids:
            event_ids = [str(item) for item in support_item.get("evidence_event_ids") or [] if str(item)]
        if not confidence:
            confidence = str(support_item.get("confidence") or "")
    return label, event_ids, confidence


def truth_label(packet: Dict[str, Any], dimension: str) -> str:
    truth = packet.get("truth") or {}
    if dimension == "counterfactual_block_point":
        return str(truth.get("counterfactual_block_point") or "").strip()
    return str(truth.get(dimension) or "").strip()


def event_map(packet: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    events = packet.get("observed_events") or []
    return {str(event.get("event_id") or ""): event for event in events if isinstance(event, dict) and event.get("event_id")}


def label_supported(label: str, event_ids: Sequence[str], candidates_key: str, events_by_id: Dict[str, Dict[str, Any]]) -> Tuple[Optional[bool], bool]:
    if not label or label == "insufficient_evidence":
        return None, False
    if not event_ids:
        return False, False
    invalid_ref = any(event_id not in events_by_id for event_id in event_ids)
    supported = False
    for event_id in event_ids:
        event = events_by_id.get(event_id)
        if not event:
            continue
        candidates = {str(item) for item in event.get(candidates_key) or []}
        if label in candidates:
            supported = True
    return supported, invalid_ref


def score_one(packet: Dict[str, Any], pred_row: Dict[str, Any]) -> Dict[str, Any]:
    prediction = prediction_payload(pred_row)
    support = support_payload(pred_row)
    events_by_id = event_map(packet)
    abstain = bool(pred_row.get("abstain") or prediction.get("abstain"))
    row: Dict[str, Any] = {
        "task_id": packet.get("task_id"),
        "family": packet.get("family"),
        "difficulty": packet.get("difficulty"),
        "abstain": abstain,
        "event_count": len(events_by_id),
        "replay_status": (packet.get("replay") or {}).get("replay_status", ""),
    }
    all_support_values: List[Optional[bool]] = []
    all_match_values: List[Optional[bool]] = []
    invalid_refs = 0
    cited_count = 0
    for dimension, candidates_key in DIMENSIONS:
        label, event_ids, confidence = extract_label_and_citations(prediction, support, dimension)
        truth = truth_label(packet, dimension)
        match: Optional[bool] = None
        if label and truth:
            match = label == truth
        supported, invalid_ref = label_supported(label, event_ids, candidates_key, events_by_id)
        invalid_refs += 1 if invalid_ref else 0
        cited_count += len(event_ids)
        all_support_values.append(supported)
        all_match_values.append(match)
        row[f"pred_{dimension}"] = label
        row[f"truth_{dimension}"] = truth
        row[f"{dimension}_match"] = match
        row[f"{dimension}_evidence_supported"] = supported
        row[f"{dimension}_evidence_event_ids"] = "|".join(event_ids)
        row[f"{dimension}_confidence"] = confidence
    support_bools = [value for value in all_support_values if value is not None]
    match_bools = [value for value in all_match_values if value is not None]
    row["all_scored_labels_match"] = all(match_bools) if match_bools else None
    row["all_cited_labels_supported"] = all(support_bools) if support_bools else None
    row["any_invalid_evidence_reference"] = invalid_refs > 0
    row["num_cited_events"] = cited_count
    row["prediction_has_evidence"] = cited_count > 0
    row["replay_evidence_available"] = bool(packet.get("replay"))
    return row


def write_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
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
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def build_summary(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "num_scored": len(rows),
        "score_interpretation": (
            "Label-match fields measure agreement with expected scenario hazard labels; "
            "evidence-support fields measure whether cited observed events support the "
            "predicted labels."
        ),
        "abstention_rate": safe_rate([bool(row.get("abstain")) for row in rows]),
        "prediction_has_evidence_rate": safe_rate([bool(row.get("prediction_has_evidence")) for row in rows]),
        "invalid_evidence_reference_rate": safe_rate([bool(row.get("any_invalid_evidence_reference")) for row in rows]),
        "all_cited_labels_supported_rate": safe_rate([row.get("all_cited_labels_supported") for row in rows]),
        "all_scored_labels_match_rate": safe_rate([row.get("all_scored_labels_match") for row in rows]),
        "mean_num_cited_events": safe_mean([float(row.get("num_cited_events") or 0) for row in rows]),
        "replay_evidence_available_rate": safe_rate([bool(row.get("replay_evidence_available")) for row in rows]),
    }
    for dimension, _ in DIMENSIONS:
        summary[f"{dimension}_accuracy"] = safe_rate([row.get(f"{dimension}_match") for row in rows])
        summary[f"{dimension}_evidence_supported_rate"] = safe_rate(
            [row.get(f"{dimension}_evidence_supported") for row in rows]
        )
    summary["per_run"] = list(rows)
    return summary


def main() -> int:
    args = parse_args()
    evidence = task_map(load_jsonl(Path(args.evidence_jsonl)))
    predictions = task_map(load_jsonl(Path(args.predictions)))
    scored: List[Dict[str, Any]] = []
    for task_id, pred_row in sorted(predictions.items()):
        packet = evidence.get(task_id)
        if not packet:
            continue
        scored.append(score_one(packet, pred_row))

    summary = build_summary(scored)
    print(f"Scored rows                    : {summary['num_scored']}")
    print(f"All labels match               : {summary['all_scored_labels_match_rate']}")
    print(f"All cited labels supported     : {summary['all_cited_labels_supported_rate']}")
    print(f"Invalid evidence reference rate: {summary['invalid_evidence_reference_rate']}")
    print(f"Abstention rate                : {summary['abstention_rate']}")
    if args.output_json:
        write_json(Path(args.output_json), summary)
    if args.output_csv:
        write_csv(Path(args.output_csv), scored)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
