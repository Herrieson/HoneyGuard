#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.init_from_config import load_config  # noqa: E402


DEFAULT_BASE_DIR = REPO_ROOT / "configs" / "honeyspace" / "scenarios" / "base_dev"
DEFAULT_OVERLAY_DIR = REPO_ROOT / "configs" / "honeyspace" / "attack_overlays" / "dev"
DEFAULT_MANIFEST = REPO_ROOT / "configs" / "honeyspace" / "manifests" / "base_dev.yaml"


ALLOWED_CHANNELS = {
    "user_instruction",
    "retrieved_content",
    "tool_output",
    "tool_metadata",
    "mcp_resource",
    "mcp_auth_or_session",
    "memory_state",
    "helper_agent_message",
    "policy_context",
    "environment_state",
    "supply_chain_config",
    "multimodal_content",
}

ALLOWED_OBJECTIVES = {
    "credential_seeking",
    "sensitive_data_exfiltration",
    "unsafe_external_send",
    "unauthorized_tool_invocation",
    "privilege_escalation",
    "fake_authorization",
    "destructive_write_or_delete",
    "integrity_corruption",
    "resource_exhaustion",
    "trace_evasion_or_log_tampering",
    "human_approval_manipulation",
    "system_prompt_or_policy_leakage",
}

ALLOWED_MODIFIERS = {
    "adaptive_decoy_avoidance",
    "multi_step",
    "payload_splitting",
    "obfuscated_instruction",
    "cross_session",
    "multi_agent_propagation",
    "tool_chain",
    "low_visibility",
}


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def as_nonempty_str(value: Any, field: str, path: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path}: {field} must be a non-empty string")
    return value.strip()


def as_str_list(value: Any, field: str, path: Path, *, allow_empty: bool = False) -> list[str]:
    if value is None:
        if allow_empty:
            return []
        raise ValueError(f"{path}: {field} is required")
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{path}: {field} must be a list of non-empty strings")
    if not value and not allow_empty:
        raise ValueError(f"{path}: {field} must not be empty")
    return [item.strip() for item in value]


def collect_yaml_files(path: Path) -> list[Path]:
    if not path.exists():
        raise FileNotFoundError(f"directory does not exist: {path}")
    return sorted(p for p in path.glob("*.yaml") if p.is_file())


def validate_base_task(path: Path) -> dict[str, Any]:
    data = load_yaml(path)

    task_id = as_nonempty_str(data.get("task_id"), "task_id", path)
    scenario = as_nonempty_str(data.get("scenario"), "scenario", path)
    if scenario != task_id:
        raise ValueError(f"{path}: scenario must equal task_id for base tasks")
    if data.get("suite") != "honeyspace_base_dev":
        raise ValueError(f"{path}: suite must be honeyspace_base_dev")
    if "honeyspace" in data:
        raise ValueError(f"{path}: clean base task must not contain top-level honeyspace")

    base = data.get("honeyspace_base")
    if not isinstance(base, dict):
        raise ValueError(f"{path}: missing honeyspace_base mapping")
    if base.get("base_task_id") != task_id:
        raise ValueError(f"{path}: honeyspace_base.base_task_id must equal task_id")
    if "honey_affordances" in base:
        raise ValueError(f"{path}: clean base task must not contain honey affordances")

    protected = base.get("protected_objects")
    if not isinstance(protected, list) or not protected:
        raise ValueError(f"{path}: honeyspace_base.protected_objects must be a non-empty list")
    protected_ids = set()
    for idx, obj in enumerate(protected):
        if not isinstance(obj, dict):
            raise ValueError(f"{path}: protected_objects[{idx}] must be a mapping")
        protected_ids.add(as_nonempty_str(obj.get("id"), f"protected_objects[{idx}].id", path))
        as_nonempty_str(obj.get("type"), f"protected_objects[{idx}].type", path)
        as_nonempty_str(obj.get("sensitivity"), f"protected_objects[{idx}].sensitivity", path)
        events = obj.get("compromise_events")
        if not isinstance(events, list) or not events:
            raise ValueError(f"{path}: protected_objects[{idx}].compromise_events must be non-empty")

    threat_model = base.get("threat_model")
    if not isinstance(threat_model, dict):
        raise ValueError(f"{path}: honeyspace_base.threat_model must be a mapping")
    threat_classes = as_str_list(threat_model.get("classes"), "threat_model.classes", path)
    unknown_threats = sorted(set(threat_classes) - ALLOWED_OBJECTIVES)
    if unknown_threats:
        raise ValueError(f"{path}: unknown threat classes: {unknown_threats}")

    benign_affordances = base.get("benign_allowed_affordances")
    if not isinstance(benign_affordances, list) or not benign_affordances:
        raise ValueError(f"{path}: honeyspace_base.benign_allowed_affordances must be non-empty")

    attack_slots = base.get("attack_slots")
    if not isinstance(attack_slots, list) or not attack_slots:
        raise ValueError(f"{path}: honeyspace_base.attack_slots must be non-empty")

    slot_channels: set[str] = set()
    slot_objectives: set[str] = set()
    slot_modifiers: set[str] = set()
    for idx, slot in enumerate(attack_slots):
        if not isinstance(slot, dict):
            raise ValueError(f"{path}: attack_slots[{idx}] must be a mapping")
        as_nonempty_str(slot.get("id"), f"attack_slots[{idx}].id", path)
        channel = as_nonempty_str(slot.get("channel"), f"attack_slots[{idx}].channel", path)
        if channel not in ALLOWED_CHANNELS:
            raise ValueError(f"{path}: attack_slots[{idx}].channel {channel!r} is not allowed")
        objectives = as_str_list(slot.get("objective_classes"), f"attack_slots[{idx}].objective_classes", path)
        unknown_objectives = sorted(set(objectives) - ALLOWED_OBJECTIVES)
        if unknown_objectives:
            raise ValueError(f"{path}: unknown objective classes: {unknown_objectives}")
        modifiers = as_str_list(slot.get("modifiers"), f"attack_slots[{idx}].modifiers", path, allow_empty=True)
        unknown_modifiers = sorted(set(modifiers) - ALLOWED_MODIFIERS)
        if unknown_modifiers:
            raise ValueError(f"{path}: unknown modifiers: {unknown_modifiers}")
        as_nonempty_str(slot.get("description"), f"attack_slots[{idx}].description", path)
        slot_channels.add(channel)
        slot_objectives.update(objectives)
        slot_modifiers.update(modifiers)

    expected_safe_path = base.get("expected_safe_path")
    if not isinstance(expected_safe_path, list) or not expected_safe_path:
        raise ValueError(f"{path}: honeyspace_base.expected_safe_path must be non-empty")

    # Reuse HoneyGuard's current config loader for runtime-shape validation.
    load_config(path)

    return {
        "path": path,
        "task_id": task_id,
        "channels": slot_channels,
        "objectives": slot_objectives,
        "modifiers": slot_modifiers,
        "protected_ids": protected_ids,
    }


def validate_overlay(path: Path, bases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    data = load_yaml(path)

    overlay_id = as_nonempty_str(data.get("overlay_id"), "overlay_id", path)
    base_task_id = as_nonempty_str(data.get("base_task_id"), "base_task_id", path)
    if base_task_id not in bases:
        raise ValueError(f"{path}: unknown base_task_id {base_task_id!r}")
    if data.get("suite") != "honeyspace_attack_overlays_dev":
        raise ValueError(f"{path}: suite must be honeyspace_attack_overlays_dev")

    channel = as_nonempty_str(data.get("channel"), "channel", path)
    if channel not in ALLOWED_CHANNELS:
        raise ValueError(f"{path}: channel {channel!r} is not allowed")
    if channel not in bases[base_task_id]["channels"]:
        raise ValueError(f"{path}: channel {channel!r} is not declared in base task {base_task_id}")

    objectives = as_str_list(data.get("objective_classes"), "objective_classes", path)
    unknown_objectives = sorted(set(objectives) - ALLOWED_OBJECTIVES)
    if unknown_objectives:
        raise ValueError(f"{path}: unknown objective classes: {unknown_objectives}")
    if not set(objectives).issubset(bases[base_task_id]["objectives"]):
        raise ValueError(f"{path}: objectives must be a subset of the base task attack-slot objectives")

    modifiers = as_str_list(data.get("modifiers"), "modifiers", path, allow_empty=True)
    unknown_modifiers = sorted(set(modifiers) - ALLOWED_MODIFIERS)
    if unknown_modifiers:
        raise ValueError(f"{path}: unknown modifiers: {unknown_modifiers}")

    injection = data.get("injection")
    if not isinstance(injection, dict):
        raise ValueError(f"{path}: injection must be a mapping")
    as_nonempty_str(injection.get("type"), "injection.type", path)
    as_nonempty_str(injection.get("target"), "injection.target", path)
    as_nonempty_str(injection.get("payload"), "injection.payload", path)

    expected = data.get("expected_no_defense_failure")
    if not isinstance(expected, dict):
        raise ValueError(f"{path}: expected_no_defense_failure must be a mapping")
    compromised = as_str_list(expected.get("compromised_objects"), "expected_no_defense_failure.compromised_objects", path)
    missing_protected = sorted(set(compromised) - bases[base_task_id]["protected_ids"])
    if missing_protected:
        raise ValueError(f"{path}: compromised objects are not protected by base task: {missing_protected}")
    unsafe_events = expected.get("unsafe_events")
    if not isinstance(unsafe_events, list) or not unsafe_events:
        raise ValueError(f"{path}: expected_no_defense_failure.unsafe_events must be non-empty")

    return {
        "path": path,
        "overlay_id": overlay_id,
        "base_task_id": base_task_id,
        "channel": channel,
        "objectives": set(objectives),
        "modifiers": set(modifiers),
    }


def validate_manifest(path: Path, bases: dict[str, dict[str, Any]], strict_phase1: bool) -> None:
    manifest = load_yaml(path)
    rows = manifest.get("scenarios")
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path}: scenarios must be a non-empty list")

    manifest_ids = []
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}: scenarios[{idx}] must be a mapping")
        task_id = as_nonempty_str(row.get("task_id"), f"scenarios[{idx}].task_id", path)
        manifest_ids.append(task_id)
        if task_id not in bases:
            raise ValueError(f"{path}: manifest task_id not found in base_dir: {task_id}")
        channel = as_nonempty_str(row.get("primary_channel"), f"scenarios[{idx}].primary_channel", path)
        if channel not in bases[task_id]["channels"]:
            raise ValueError(f"{path}: manifest channel {channel!r} is not declared by {task_id}")
        objectives = as_str_list(row.get("objective_classes"), f"scenarios[{idx}].objective_classes", path)
        if not set(objectives).issubset(bases[task_id]["objectives"]):
            raise ValueError(f"{path}: manifest objectives for {task_id} are not declared by base task")

    duplicate_manifest_ids = [task_id for task_id, count in Counter(manifest_ids).items() if count > 1]
    if duplicate_manifest_ids:
        raise ValueError(f"{path}: duplicate manifest task ids: {duplicate_manifest_ids}")

    base_ids = set(bases)
    manifest_id_set = set(manifest_ids)
    missing = sorted(base_ids - manifest_id_set)
    extra = sorted(manifest_id_set - base_ids)
    if missing or extra:
        raise ValueError(f"{path}: manifest/base mismatch; missing={missing}, extra={extra}")

    if not strict_phase1:
        return

    targets = manifest.get("phase1_targets")
    if not isinstance(targets, dict) or not targets:
        raise ValueError(f"{path}: phase1_targets must be a non-empty mapping in strict mode")
    for group, target in targets.items():
        if not isinstance(target, dict):
            raise ValueError(f"{path}: phase1_targets.{group} must be a mapping")
        min_count = int(target.get("min_count") or 0)
        scenarios = as_str_list(target.get("scenarios"), f"phase1_targets.{group}.scenarios", path)
        if len(scenarios) < min_count:
            raise ValueError(f"{path}: phase1 target {group} has {len(scenarios)} scenarios, needs {min_count}")
        unknown = sorted(set(scenarios) - base_ids)
        if unknown:
            raise ValueError(f"{path}: phase1 target {group} references unknown base tasks: {unknown}")


def print_summary(bases: dict[str, dict[str, Any]], overlays: list[dict[str, Any]]) -> None:
    channel_counts = Counter()
    objective_counts = Counter()
    modifier_counts = Counter()
    for base in bases.values():
        channel_counts.update(base["channels"])
        objective_counts.update(base["objectives"])
        modifier_counts.update(base["modifiers"])

    overlay_channel_counts = Counter(overlay["channel"] for overlay in overlays)
    overlays_by_base: dict[str, list[str]] = defaultdict(list)
    for overlay in overlays:
        overlays_by_base[overlay["base_task_id"]].append(overlay["overlay_id"])

    print(f"BASE_TASKS {len(bases)}")
    print(f"ATTACK_OVERLAYS {len(overlays)}")
    print("BASE_CHANNELS " + dict_to_compact(channel_counts))
    print("BASE_OBJECTIVES " + dict_to_compact(objective_counts))
    print("BASE_MODIFIERS " + dict_to_compact(modifier_counts))
    print("OVERLAY_CHANNELS " + dict_to_compact(overlay_channel_counts))

    missing_overlays = sorted(task_id for task_id in bases if task_id not in overlays_by_base)
    if missing_overlays:
        print("BASES_WITHOUT_OVERLAY " + ",".join(missing_overlays))


def dict_to_compact(counter: Counter[str]) -> str:
    return ",".join(f"{key}={counter[key]}" for key in sorted(counter)) or "none"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate HoneySpace clean base tasks and attack overlays.")
    parser.add_argument("--base-dir", type=Path, default=DEFAULT_BASE_DIR)
    parser.add_argument("--overlay-dir", type=Path, default=DEFAULT_OVERLAY_DIR)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--strict-phase1", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        base_paths = collect_yaml_files(args.base_dir)
        if not base_paths:
            raise FileNotFoundError(f"no base task YAML files found in {args.base_dir}")
        bases = {}
        for path in base_paths:
            base = validate_base_task(path)
            task_id = base["task_id"]
            if task_id in bases:
                raise ValueError(f"duplicate base task_id {task_id}: {bases[task_id]['path']} and {path}")
            bases[task_id] = base

        overlay_paths = collect_yaml_files(args.overlay_dir)
        overlays = []
        seen_overlay_ids = {}
        for path in overlay_paths:
            overlay = validate_overlay(path, bases)
            overlay_id = overlay["overlay_id"]
            if overlay_id in seen_overlay_ids:
                raise ValueError(f"duplicate overlay_id {overlay_id}: {seen_overlay_ids[overlay_id]} and {path}")
            seen_overlay_ids[overlay_id] = path
            overlays.append(overlay)

        validate_manifest(args.manifest, bases, args.strict_phase1)
        print_summary(bases, overlays)
        print("HONEYSPACE_DATASET_OK")
    except Exception as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
