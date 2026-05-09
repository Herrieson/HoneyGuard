#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


RISK_CATEGORIES = {
    "unauthorized_trigger_rate",
    "explicit_leakage",
    "silent_leakage",
    "stealth_detectability",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export HoneyGuard scenario run logs into a normalized JSON format."
    )
    parser.add_argument("--run-jsonl", required=True, help="Path to run_scenarios JSONL output.")
    parser.add_argument("--output", required=True, help="Output path (.json or .jsonl).")
    parser.add_argument("--hse-db", default="logs/hse.db", help="Optional HoneyGuard trace SQLite DB.")
    parser.add_argument(
        "--scenario-root",
        default="configs/mvp/_archive/v0_1_splits/bootstrap",
        help="Canonical scenario directory used when historical runs point at copied YAML files.",
    )
    parser.add_argument("--config-path", default="", help="Filter by config_path.")
    parser.add_argument("--session-id", default="", help="Filter by session_id.")
    parser.add_argument("--scenario", default="", help="Filter by scenario/task_id.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser.parse_args()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
    return records


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def parse_json_text(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def resolve_config_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if path.exists():
        return path.resolve()
    alt = (Path.cwd() / raw_path).resolve()
    return alt


def record_dedupe_key(record: Dict[str, Any], fallback_index: int) -> str:
    config_path = str(record.get("config_path") or "").strip()
    if config_path:
        return f"config:{resolve_config_path(config_path)}"
    session_id = str(record.get("session_id") or "").strip()
    if session_id:
        return f"session:{session_id}"
    return f"record:{fallback_index}"


def dedupe_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest: Dict[str, Tuple[int, Dict[str, Any]]] = {}
    for idx, record in enumerate(records):
        latest[record_dedupe_key(record, idx)] = (idx, record)
    return [item[1] for item in sorted(latest.values(), key=lambda item: item[0])]


def has_benchmark_metadata(config_data: Dict[str, Any]) -> bool:
    return any(
        key in config_data
        for key in ("task_id", "track", "family", "attribution_ground_truth", "resource_limits", "composition")
    )


def resolve_canonical_config_path(record: Dict[str, Any], current_path: Path, scenario_root: Path) -> Path:
    current_data = load_yaml(current_path)
    scenario_ref = current_data.get("scenario")
    if isinstance(scenario_ref, str) and scenario_ref.strip().endswith((".yaml", ".yml")):
        referred = resolve_config_path(scenario_ref.strip())
        referred_data = load_yaml(referred)
        if has_benchmark_metadata(referred_data):
            return referred

    if not scenario_root.exists():
        return current_path

    candidates: List[Path] = []
    if current_path.name:
        direct = (scenario_root / current_path.name).resolve()
        if direct.exists():
            candidates.append(direct)
        candidates.extend(sorted(scenario_root.rglob(current_path.name)))

    stem = current_path.stem
    if stem:
        stem_match = (scenario_root / f"{stem}.yaml").resolve()
        if stem_match.exists():
            candidates.append(stem_match)

    run_response = parse_json_text(record.get("run_response"))
    scenario_name = str(record.get("scenario") or stem or "")
    if not scenario_name:
        scenario_name = str(run_response.get("scenario") or "")
    if scenario_name:
        named = (scenario_root / f"{scenario_name}.yaml").resolve()
        if named.exists():
            candidates.append(named)

    seen: set[str] = set()
    for candidate in candidates:
        candidate_key = str(candidate)
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        data = load_yaml(candidate)
        if has_benchmark_metadata(data):
            return candidate
    return current_path


def normalize_sqlite_timestamp(raw: Any) -> Optional[str]:
    if not raw:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if "T" in text:
        return text
    return text.replace(" ", "T") + "Z"


def parse_iso_datetime(raw: Any) -> Optional[datetime]:
    if not raw:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def wall_clock_seconds(started_at: Any, ended_at: Any) -> Optional[float]:
    started = parse_iso_datetime(started_at)
    ended = parse_iso_datetime(ended_at)
    if not started or not ended:
        return None
    return max((ended - started).total_seconds(), 0.0)


def load_hse_events(db_path: Path, session_id: str) -> Dict[str, List[Dict[str, Any]]]:
    if not session_id or not db_path.exists():
        return {"traces": [], "tool_calls": []}

    traces: List[Dict[str, Any]] = []
    tool_calls: List[Dict[str, Any]] = []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(
            """
            SELECT id, trace_id, payload, created_at
            FROM traces
            WHERE session_id = ?
            ORDER BY id ASC
            """,
            (session_id,),
        )
        for row in cursor.fetchall():
            payload = parse_json_text(row["payload"])
            traces.append(
                {
                    "event_index": int(row["id"]),
                    "trace_id": row["trace_id"],
                    "timestamp": normalize_sqlite_timestamp(row["created_at"]),
                    "payload": payload,
                }
            )

        cursor = conn.execute(
            """
            SELECT id, trace_id, tool_name, args, output, status, created_at
            FROM tool_calls
            WHERE session_id = ?
            ORDER BY id ASC
            """,
            (session_id,),
        )
        for row in cursor.fetchall():
            args = parse_json_text(row["args"])
            tool_calls.append(
                {
                    "event_index": int(row["id"]),
                    "trace_id": row["trace_id"],
                    "timestamp": normalize_sqlite_timestamp(row["created_at"]),
                    "tool_name": row["tool_name"],
                    "args": args,
                    "output": row["output"],
                    "status": row["status"],
                }
            )
    finally:
        conn.close()
    return {"traces": traces, "tool_calls": tool_calls}


def event_kind(category: Any) -> str:
    cat = str(category or "").strip()
    if cat == "safety_boundary_preserved":
        return "safety"
    if cat in RISK_CATEGORIES:
        return "risk"
    return "utility"


def derive_safety_events(acceptance_results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for item in acceptance_results or []:
        if not isinstance(item, dict):
            continue
        events.append(
            {
                "category": str(item.get("category") or "uncategorized"),
                "kind": event_kind(item.get("category")),
                "passed": bool(item.get("passed")),
                "enforce": item.get("enforce"),
                "detail": item.get("detail"),
                "criterion_index": item.get("index"),
            }
        )
    return events


def find_trace_event(raw_events: List[Dict[str, Any]], trace_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not trace_id:
        return None
    for item in raw_events:
        if item.get("trace_id") == trace_id:
            return item
    return None


def normalize_run_steps(
    record: Dict[str, Any],
    raw_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    run_responses = record.get("run_responses") or []
    normalized_steps: List[Dict[str, Any]] = []
    final_trace_id: Optional[str] = None
    global_step_id = 1

    for run_step in run_responses:
        if not isinstance(run_step, dict):
            continue
        run_step_index = run_step.get("step")
        user_instruction = run_step.get("instruction")
        parsed = parse_json_text(run_step.get("response"))
        final_trace_id = parsed.get("trace_id") or final_trace_id
        trace_event = find_trace_event(raw_events, parsed.get("trace_id"))
        timestamp = trace_event.get("timestamp") if trace_event else None
        tool_calls = parsed.get("tool_calls") or []

        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue
            normalized_steps.append(
                {
                    "step_id": global_step_id,
                    "run_step_index": run_step_index,
                    "timestamp": timestamp,
                    "agent": tool_call.get("agent"),
                    "observation": {
                        "user_instruction": user_instruction,
                        "tool_results_in": [],
                    },
                    "action": {
                        "type": "tool_call",
                        "tool_name": tool_call.get("name"),
                        "args": tool_call.get("args") or {},
                        "planning_summary": None,
                        "selected_subgoal": None,
                        "why_this_action": None,
                        "trust_level": None,
                    },
                    "tool_name": tool_call.get("name"),
                    "tool_response": {
                        "output": tool_call.get("output"),
                        "error": tool_call.get("error"),
                        "status": tool_call.get("status"),
                        "elapsed_sec": tool_call.get("elapsed_sec"),
                    },
                    "environment_diff": None,
                    "risk_events": [],
                }
            )
            global_step_id += 1

        acceptance_results = parsed.get("acceptance_results") or []
        final_risk_events = [
            item
            for item in derive_safety_events(acceptance_results)
            if item.get("kind") == "risk" and item.get("passed") is True
        ]
        normalized_steps.append(
            {
                "step_id": global_step_id,
                "run_step_index": run_step_index,
                "timestamp": timestamp,
                "agent": None,
                "observation": {
                    "user_instruction": user_instruction,
                    "tool_results_in": tool_calls if isinstance(tool_calls, list) else [],
                },
                "action": {
                    "type": "final_response",
                    "tool_name": None,
                    "args": None,
                    "planning_summary": None,
                    "selected_subgoal": None,
                    "why_this_action": None,
                    "trust_level": None,
                },
                "tool_name": None,
                "tool_response": {
                    "output": parsed.get("agent_response"),
                    "error": None,
                    "status": "ok",
                    "elapsed_sec": None,
                },
                "environment_diff": None,
                "risk_events": final_risk_events,
            }
        )
        global_step_id += 1

    return {
        "trace_id": final_trace_id,
        "run_steps": normalized_steps,
    }


def collect_task_metadata(config_data: Dict[str, Any]) -> Dict[str, Any]:
    composition = config_data.get("composition") or {}
    composition = composition if isinstance(composition, dict) else {}
    return {
        "task_id": config_data.get("task_id"),
        "scenario": config_data.get("scenario"),
        "track": config_data.get("track"),
        "family": config_data.get("family"),
        "difficulty": config_data.get("difficulty"),
        "controlled_hazard": config_data.get("controlled_hazard"),
        "expected_safe_behavior": config_data.get("expected_safe_behavior") or [],
        "success_criteria": config_data.get("success_criteria") or [],
        "forbidden_actions": config_data.get("forbidden_actions") or [],
        "safety_constraints": config_data.get("safety_constraints") or [],
        "attribution_ground_truth": config_data.get("attribution_ground_truth") or {},
        "failure_chain": config_data.get("failure_chain") or [],
        "counterfactual_block_point": config_data.get("counterfactual_block_point"),
        "resource_limits": config_data.get("resource_limits") or {},
        "composition": composition,
        "composition_group_id": composition.get("composition_group_id"),
        "composition_scenario_id": composition.get("composition_scenario_id"),
        "composition_type": composition.get("composition_type"),
        "scenario_role": composition.get("scenario_role"),
        "substrate_id": composition.get("substrate_id"),
        "substrate_name": composition.get("substrate_name"),
        "hazard_ids": composition.get("hazard_ids") or [],
        "hazard_families": composition.get("hazard_families") or [],
        "hazard_channels": composition.get("hazard_channels") or [],
        "hazard_sources": composition.get("hazard_sources") or [],
        "hazard_names": composition.get("hazard_names") or [],
        "order_index": composition.get("order_index"),
        "interaction_hypothesis": composition.get("interaction_hypothesis"),
        "dominant_hazard_hypothesis": composition.get("dominant_hazard_hypothesis"),
        "run_role": composition.get("run_role"),
    }


def agent_names(config_data: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for item in config_data.get("agents") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())
    return names


def split_agent_transcript(text: Any, names: List[str]) -> List[Dict[str, Any]]:
    if not isinstance(text, str) or not text or not names:
        return []
    pattern = re.compile(r"(?m)^(" + "|".join(re.escape(name) for name in names) + r"):\s*")
    matches = list(pattern.finditer(text))
    segments: List[Dict[str, Any]] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        segments.append(
            {
                "agent": match.group(1),
                "start": match.start(),
                "end": end,
                "text": text[start:end].strip(),
            }
        )
    return segments


def user_facing_response(agent_response: Any, config_data: Dict[str, Any]) -> Dict[str, Any]:
    text = agent_response if isinstance(agent_response, str) else ""
    segments = split_agent_transcript(text, agent_names(config_data))
    if not segments:
        return {
            "user_facing_response": text,
            "final_agent": None,
            "internal_message_exposure": False,
        }
    executor_segments = [segment for segment in segments if segment.get("agent") == "executor"]
    final_segment = executor_segments[-1] if executor_segments else segments[-1]
    return {
        "user_facing_response": final_segment.get("text") or "",
        "final_agent": final_segment.get("agent"),
        "internal_message_exposure": len(segments) > 1,
    }


def build_resource_usage(
    record: Dict[str, Any],
    run_response: Dict[str, Any],
    task_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    tool_calls = run_response.get("tool_calls") or []
    total_elapsed = 0.0
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        elapsed = call.get("elapsed_sec")
        if isinstance(elapsed, (int, float)):
            total_elapsed += float(elapsed)

    limits = task_metadata.get("resource_limits") or {}
    return {
        "total_tool_calls": len(tool_calls) if isinstance(tool_calls, list) else 0,
        "total_tool_elapsed_sec": total_elapsed,
        "wall_clock_sec": wall_clock_seconds(record.get("started_at"), record.get("ended_at")),
        "step_budget": limits.get("max_steps"),
        "api_call_budget": limits.get("max_api_calls"),
        "token_budget": limits.get("max_tokens"),
    }


def build_export_record(record: Dict[str, Any], hse_db: Path, scenario_root: Path) -> Dict[str, Any]:
    config_path = resolve_config_path(str(record.get("config_path") or ""))
    config_data = load_yaml(config_path)
    if not has_benchmark_metadata(config_data):
        config_path = resolve_canonical_config_path(record, config_path, scenario_root)
        config_data = load_yaml(config_path)
    task_metadata = collect_task_metadata(config_data)
    run_response = parse_json_text(record.get("run_response"))
    final_response = user_facing_response(run_response.get("agent_response"), config_data)
    acceptance_results = run_response.get("acceptance_results") or []
    hse = load_hse_events(hse_db, str(record.get("session_id") or ""))
    normalized = normalize_run_steps(record, hse["traces"])
    safety_events = derive_safety_events(acceptance_results)

    return {
        "export_version": "0.1",
        "run_metadata": {
            "session_id": record.get("session_id"),
            "config_path": str(config_path),
            "status": record.get("status"),
            "base_url": record.get("base_url"),
            "started_at": record.get("started_at"),
            "ended_at": record.get("ended_at"),
            "instruction_override": record.get("instruction"),
            "error": record.get("error"),
        },
        "task_metadata": task_metadata,
        "composition": task_metadata.get("composition") or {},
        "trace": {
            "trace_version": "0.1",
            "session_id": record.get("session_id"),
            "task_id": task_metadata.get("task_id"),
            "trace_id": normalized.get("trace_id"),
            "raw_events": hse["traces"],
            "run_steps": normalized.get("run_steps") or [],
            "safety_events": safety_events,
            "resource_usage": build_resource_usage(record, run_response, task_metadata),
        },
        "final_output": {
            "agent_response": run_response.get("agent_response"),
            "user_facing_response": final_response["user_facing_response"],
            "final_agent": final_response["final_agent"],
            "internal_message_exposure": final_response["internal_message_exposure"],
            "trace_id": run_response.get("trace_id"),
            "tool_calls": run_response.get("tool_calls") or [],
        },
        "final_state": {
            "acceptance_passed": run_response.get("acceptance_passed"),
            "acceptance_results": acceptance_results,
            "observed_status": record.get("status"),
        },
        "safety_events": safety_events,
        "resource_usage": build_resource_usage(record, run_response, task_metadata),
        "runtime_artifacts": {
            "run_responses": record.get("run_responses") or [],
            "init_response": record.get("init_response"),
            "hse_tool_calls": hse["tool_calls"],
        },
    }


def filter_records(records: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    filtered: List[Dict[str, Any]] = []
    for record in records:
        if args.config_path and str(record.get("config_path") or "") != args.config_path:
            continue
        if args.session_id and str(record.get("session_id") or "") != args.session_id:
            continue
        if args.scenario:
            config_path = resolve_config_path(str(record.get("config_path") or ""))
            config_data = load_yaml(config_path)
            scenario_name = str(config_data.get("task_id") or config_data.get("scenario") or Path(config_path).stem)
            if scenario_name != args.scenario:
                continue
        filtered.append(record)
    return filtered


def write_output(path: Path, rows: List[Dict[str, Any]], pretty: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(rows) == 1 and path.suffix.lower() == ".json":
        with path.open("w", encoding="utf-8") as handle:
            json.dump(rows[0], handle, ensure_ascii=False, indent=2 if pretty else None)
            handle.write("\n")
        return

    if path.suffix.lower() == ".jsonl":
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False))
                handle.write("\n")
        return

    with path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2 if pretty else None)
        handle.write("\n")


def main() -> int:
    args = parse_args()
    run_jsonl = Path(args.run_jsonl)
    if not run_jsonl.exists():
        raise SystemExit(f"run_jsonl not found: {run_jsonl}")

    records = load_jsonl(run_jsonl)
    records = filter_records(records, args)
    deduped_records = dedupe_records(records)
    if len(deduped_records) != len(records):
        print(f"DEDUPED_RUN_RECORDS {len(records)} -> {len(deduped_records)}")
    records = deduped_records
    if not records:
        raise SystemExit("no matching records found")

    hse_db = Path(args.hse_db)
    scenario_root = resolve_config_path(args.scenario_root)
    exported = [build_export_record(record, hse_db, scenario_root) for record in records]
    write_output(Path(args.output), exported, pretty=args.pretty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
