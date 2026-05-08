from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAYGROUND_ROOT = REPO_ROOT / "configs" / "mvp" / "playground"


def slugify(text: str, *, max_len: int = 120) -> str:
    value = (text or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    value = value[:max_len].strip("-")
    return value or "default"


def load_yaml(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    return data if isinstance(data, dict) else {}


def write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )


def _load_definitions(root: Path, kind: str) -> Dict[str, tuple[Path, Dict[str, Any]]]:
    folder = root / kind
    if not folder.exists():
        return {}
    items: Dict[str, tuple[Path, Dict[str, Any]]] = {}
    for path in sorted(folder.glob("*.yaml")):
        data = load_yaml(path)
        item_id = str(data.get(f"{kind[:-1]}_id") or data.get("id") or path.stem).strip()
        if not item_id:
            continue
        if item_id in items:
            raise ValueError(f"duplicate {kind[:-1]} id {item_id!r}: {items[item_id][0]} and {path}")
        items[item_id] = (path, data)
    return items


@dataclass(frozen=True)
class DefinitionIndex:
    root: Path
    substrates: Dict[str, tuple[Path, Dict[str, Any]]]
    hazards: Dict[str, tuple[Path, Dict[str, Any]]]
    recipes: Dict[str, tuple[Path, Dict[str, Any]]]


def build_index(root: Path = DEFAULT_PLAYGROUND_ROOT) -> DefinitionIndex:
    root = root.resolve()
    return DefinitionIndex(
        root=root,
        substrates=_load_definitions(root, "substrates"),
        hazards=_load_definitions(root, "hazards"),
        recipes=_load_definitions(root, "recipes"),
    )


def resolve_definition(ref: str | Path, kind: str, index: DefinitionIndex) -> tuple[Path, Dict[str, Any]]:
    path = Path(ref)
    if path.exists():
        data = load_yaml(path)
        if not data:
            raise ValueError(f"{kind} definition is empty: {path}")
        return path.resolve(), data

    token = str(ref).strip()
    if kind == "substrate" and token in index.substrates:
        return index.substrates[token]
    if kind == "hazard" and token in index.hazards:
        return index.hazards[token]
    if kind == "recipe" and token in index.recipes:
        return index.recipes[token]

    candidate = index.root / f"{kind}s" / f"{token}.yaml"
    if candidate.exists():
        data = load_yaml(candidate)
        return candidate.resolve(), data

    raise FileNotFoundError(f"could not resolve {kind} definition: {ref}")


def _to_text(value: Any) -> str:
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return "\n\n".join(parts)
    return str(value or "").strip()


def _merge_unique_text_list(base: List[str], additions: Iterable[str]) -> List[str]:
    seen = set()
    merged: List[str] = []
    for item in list(base) + [str(v).strip() for v in additions if str(v).strip()]:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return merged


def _merge_unique_mapping_list(base: List[Dict[str, Any]], additions: Iterable[Dict[str, Any]], *, key_field: str) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in base:
        key = str(item.get(key_field) or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    for item in additions:
        if not isinstance(item, dict):
            continue
        key = str(item.get(key_field) or "").strip()
        if not key:
            continue
        existing_index = next((idx for idx, current in enumerate(merged) if str(current.get(key_field) or "").strip() == key), None)
        if existing_index is not None:
            raise ValueError(f"duplicate {key_field!r} in merged mapping list: {key}")
        merged.append(item)
        seen.add(key)
    return merged


def _dedupe_acceptance_criteria(criteria: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen: set[Tuple[Any, ...]] = set()
    for item in criteria:
        if not isinstance(item, dict):
            continue
        key = (
            item.get("type"),
            item.get("value"),
            item.get("path"),
            item.get("key"),
            item.get("command"),
            item.get("expect_exit_code"),
            item.get("category"),
            item.get("enforce", True),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _merge_dict(target: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(target)
    for key, value in updates.items():
        if value is None:
            continue
        if isinstance(value, dict):
            current = merged.get(key)
            if isinstance(current, dict):
                merged[key] = _merge_dict(current, value)
            else:
                merged[key] = copy.deepcopy(value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _normalize_files(files: Any) -> Dict[str, str]:
    if isinstance(files, list):
        normalized_from_list: Dict[str, str] = {}
        for item in files:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "").strip()
            if not path:
                continue
            normalized_from_list[path] = str(item.get("content") or "")
        return normalized_from_list
    if not isinstance(files, dict):
        return {}
    normalized: Dict[str, str] = {}
    for path, content in files.items():
        normalized[str(path)] = str(content)
    return normalized


def _normalize_initial_instructions(value: Any) -> str:
    return _to_text(value)


def _append_text(base: str, addition: str) -> str:
    base = base.strip()
    addition = addition.strip()
    if not base:
        return addition
    if not addition:
        return base
    return f"{base}\n\n{addition}"


def _find_agent(agents: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    for agent in agents:
        if str(agent.get("name") or "").strip() == name:
            return agent
    return None


def _validate_compatibility(
    substrate: Dict[str, Any],
    hazards: Sequence[Dict[str, Any]],
    *,
    substrate_path: Path,
) -> None:
    substrate_id = str(substrate.get("substrate_id") or substrate.get("task_id") or substrate.get("scenario") or substrate_path.stem)
    slots = {str(slot).strip() for slot in substrate.get("slots") or [] if str(slot).strip()}
    tools_enabled = {str(tool).strip() for tool in substrate.get("tools_enabled") or [] if str(tool).strip()}
    for hazard in hazards:
        compatible_substrates = {
            str(item).strip()
            for item in hazard.get("compatible_substrates") or []
            if str(item).strip()
        }
        if compatible_substrates and substrate_id not in compatible_substrates:
            raise ValueError(
                f"hazard {hazard.get('hazard_id')!r} is not compatible with substrate {substrate_id!r}"
            )
        compatible_slots = {
            str(item).strip()
            for item in hazard.get("compatible_slots") or []
            if str(item).strip()
        }
        if compatible_slots and not (slots & compatible_slots):
            raise ValueError(
                f"hazard {hazard.get('hazard_id')!r} requires one of slots {sorted(compatible_slots)!r}, "
                f"but substrate {substrate_id!r} exposes {sorted(slots)!r}"
            )
        required_tools_any = {
            str(item).strip()
            for item in (hazard.get("requires") or {}).get("tools_any") or []
            if str(item).strip()
        }
        if required_tools_any and not (tools_enabled & required_tools_any):
            raise ValueError(
                f"hazard {hazard.get('hazard_id')!r} requires one of tools {sorted(required_tools_any)!r}, "
                f"but substrate {substrate_id!r} exposes {sorted(tools_enabled)!r}"
            )


def _patch_files(base: Dict[str, str], patch: Dict[str, Any]) -> Dict[str, str]:
    files = dict(base)
    for path, content in _normalize_files((patch.get("files_set") or {})).items():
        files[path] = content
    for item in patch.get("files_append") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        content = str(item.get("content") or "")
        if not path:
            continue
        existing = files.get(path, "")
        if existing and not existing.endswith("\n"):
            existing += "\n"
        files[path] = existing + content
    return files


def _patch_agents(base_agents: List[Dict[str, Any]], patch: Dict[str, Any]) -> List[Dict[str, Any]]:
    agents = copy.deepcopy(base_agents)
    if patch.get("agents_replace") is not None:
        agents = copy.deepcopy(patch.get("agents_replace") or [])
    if patch.get("agents_prepend"):
        prepend = [copy.deepcopy(item) for item in patch.get("agents_prepend") or [] if isinstance(item, dict)]
        agents = prepend + agents
    if patch.get("agents_add"):
        agents.extend(copy.deepcopy(item) for item in patch.get("agents_add") or [] if isinstance(item, dict))
    for agent_patch in patch.get("agents_patch") or []:
        if not isinstance(agent_patch, dict):
            continue
        name = str(agent_patch.get("name") or "").strip()
        if not name:
            continue
        agent = _find_agent(agents, name)
        if agent is None:
            raise ValueError(f"agent patch references unknown agent {name!r}")
        if "system_prompt_prefix" in agent_patch:
            agent["system_prompt"] = _append_text(str(agent.get("system_prompt") or ""), str(agent_patch.get("system_prompt_prefix") or ""))
        if "system_prompt_suffix" in agent_patch:
            agent["system_prompt"] = _append_text(str(agent.get("system_prompt") or ""), str(agent_patch.get("system_prompt_suffix") or ""))
        if "system_prompt_replace" in agent_patch:
            agent["system_prompt"] = str(agent_patch.get("system_prompt_replace") or "")
        if "tools_allowed_set" in agent_patch:
            agent["tools_allowed"] = list(dict.fromkeys(str(tool).strip() for tool in agent_patch.get("tools_allowed_set") or [] if str(tool).strip()))
        if "tools_allowed_add" in agent_patch:
            current = [str(tool).strip() for tool in agent.get("tools_allowed") or [] if str(tool).strip()]
            current = _merge_unique_text_list(current, [str(tool).strip() for tool in agent_patch.get("tools_allowed_add") or [] if str(tool).strip()])
            agent["tools_allowed"] = current
        if "memory_mode" in agent_patch:
            agent["memory_mode"] = agent_patch.get("memory_mode")
        if "memory_limit" in agent_patch:
            agent["memory_limit"] = agent_patch.get("memory_limit")
        if "blackboard_read_keys" in agent_patch:
            agent["blackboard_read_keys"] = agent_patch.get("blackboard_read_keys")
        if "blackboard_write_keys" in agent_patch:
            agent["blackboard_write_keys"] = agent_patch.get("blackboard_write_keys")
    return agents


def _patch_top_level(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)

    if patch.get("tools_enabled_add"):
        merged["tools_enabled"] = _merge_unique_text_list(
            [str(tool).strip() for tool in merged.get("tools_enabled") or [] if str(tool).strip()],
            [str(tool).strip() for tool in patch.get("tools_enabled_add") or [] if str(tool).strip()],
        )

    if patch.get("mock_tools_add"):
        merged["mock_tools"] = _merge_unique_mapping_list(
            list(merged.get("mock_tools") or []),
            [item for item in patch.get("mock_tools_add") or [] if isinstance(item, dict)],
            key_field="name",
        )

    if patch.get("shared_context_set"):
        merged["shared_context"] = _merge_dict(
            dict(merged.get("shared_context") or {}),
            dict(patch.get("shared_context_set") or {}),
        )

    if patch.get("files_set") or patch.get("files_append"):
        merged["files"] = _patch_files(_normalize_files(merged.get("files")), patch)

    if patch.get("agents_replace") is not None or patch.get("agents_prepend") or patch.get("agents_add") or patch.get("agents_patch"):
        merged["agents"] = _patch_agents(list(merged.get("agents") or []), patch)

    for key in ("coordination_pattern", "agent_mode", "planner_allow_tools", "max_steps", "max_elapsed_sec", "max_tool_calls", "max_tool_repeats", "stop_on_repeat_tool_calls", "stop_on_no_new_tool_results", "tool_finish_signals", "acceptance_logic"):
        if key in patch:
            merged[key] = patch.get(key)

    if patch.get("stop_signals_add"):
        merged["stop_signals"] = _merge_unique_text_list(
            [str(item).strip() for item in merged.get("stop_signals") or [] if str(item).strip()],
            [str(item).strip() for item in patch.get("stop_signals_add") or [] if str(item).strip()],
        )

    if patch.get("initial_instructions_prefix") or patch.get("initial_instructions_suffix"):
        instruction = _normalize_initial_instructions(merged.get("initial_instructions"))
        prefix = _to_text(patch.get("initial_instructions_prefix"))
        suffix = _to_text(patch.get("initial_instructions_suffix"))
        if prefix:
            instruction = _append_text(prefix, instruction)
        if suffix:
            instruction = _append_text(instruction, suffix)
        merged["initial_instructions"] = [instruction]

    if patch.get("expected_safe_behavior_add"):
        merged["expected_safe_behavior"] = _merge_unique_text_list(
            [str(item).strip() for item in merged.get("expected_safe_behavior") or [] if str(item).strip()],
            [str(item).strip() for item in patch.get("expected_safe_behavior_add") or [] if str(item).strip()],
        )

    if patch.get("success_criteria_add"):
        merged["success_criteria"] = _merge_unique_text_list(
            [str(item).strip() for item in merged.get("success_criteria") or [] if str(item).strip()],
            [str(item).strip() for item in patch.get("success_criteria_add") or [] if str(item).strip()],
        )

    if patch.get("forbidden_actions_add"):
        merged["forbidden_actions"] = _merge_unique_text_list(
            [str(item).strip() for item in merged.get("forbidden_actions") or [] if str(item).strip()],
            [str(item).strip() for item in patch.get("forbidden_actions_add") or [] if str(item).strip()],
        )

    if patch.get("safety_constraints_add"):
        merged["safety_constraints"] = _merge_unique_text_list(
            [str(item).strip() for item in merged.get("safety_constraints") or [] if str(item).strip()],
            [str(item).strip() for item in patch.get("safety_constraints_add") or [] if str(item).strip()],
        )

    if patch.get("acceptance_criteria_add"):
        merged["acceptance_criteria"] = _dedupe_acceptance_criteria(
            list(merged.get("acceptance_criteria") or [])
            + [item for item in patch.get("acceptance_criteria_add") or [] if isinstance(item, dict)]
        )

    if patch.get("resource_limits"):
        merged["resource_limits"] = _merge_dict(dict(merged.get("resource_limits") or {}), dict(patch.get("resource_limits") or {}))

    if patch.get("controlled_hazard_prefix") or patch.get("controlled_hazard_suffix"):
        hazard = str(merged.get("controlled_hazard") or "").strip()
        hazard = _append_text(str(patch.get("controlled_hazard_prefix") or ""), hazard)
        hazard = _append_text(hazard, str(patch.get("controlled_hazard_suffix") or ""))
        merged["controlled_hazard"] = hazard

    if patch.get("attribution_ground_truth"):
        merged["attribution_ground_truth"] = _merge_dict(
            dict(merged.get("attribution_ground_truth") or {}),
            dict(patch.get("attribution_ground_truth") or {}),
        )

    if patch.get("track"):
        merged["track"] = patch.get("track")
    if patch.get("family"):
        merged["family"] = patch.get("family")
    if patch.get("difficulty"):
        merged["difficulty"] = patch.get("difficulty")

    return merged


def _choose_dominant_hazard(hazards: Sequence[Dict[str, Any]], experiment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    hypothesis = str(experiment.get("dominant_hazard_hypothesis") or "").strip()
    for hazard in hazards:
        if str(hazard.get("hazard_id") or "").strip() == hypothesis:
            return hazard
    if hazards:
        return hazards[0]
    return None


def _hazard_summary(hazards: Sequence[Dict[str, Any]]) -> str:
    if not hazards:
        return "No injected hazard. Clean substrate control."
    parts = []
    for hazard in hazards:
        hazard_id = str(hazard.get("hazard_id") or "").strip()
        family = str(hazard.get("family") or "").strip()
        channel = str(hazard.get("channel") or "").strip()
        parts.append(f"{hazard_id} [{family} via {channel}]")
    return "Combined hazards: " + "; ".join(parts) + "."


def _scenario_id(experiment_id: str, role: str, hazards: Sequence[Dict[str, Any]]) -> str:
    hazard_slug = "__".join(slugify(str(h.get("hazard_id") or "").strip(), max_len=64) for h in hazards)
    pieces = [slugify(experiment_id, max_len=48), slugify(role, max_len=24)]
    if hazard_slug:
        pieces.append(hazard_slug)
    return "__".join(pieces)


def _family_for_role(role: str, hazards: Sequence[Dict[str, Any]]) -> str:
    if role == "clean":
        return "PG0"
    count = max(len(hazards), 1)
    return f"PG{count}"


def _composition_block(
    *,
    recipe_id: str,
    experiment_id: str,
    substrate_id: str,
    substrate_name: str,
    role: str,
    hazards: Sequence[Dict[str, Any]],
    interaction_hypothesis: str,
    dominant_hazard_hypothesis: str,
    order_index: int,
    composition_type: str,
) -> Dict[str, Any]:
    return {
        "recipe_id": recipe_id,
        "experiment_id": experiment_id,
        "composition_group_id": experiment_id,
        "composition_scenario_id": _scenario_id(experiment_id, role, hazards),
        "scenario_role": role,
        "composition_type": composition_type,
        "substrate_id": substrate_id,
        "substrate_name": substrate_name,
        "hazard_ids": [str(h.get("hazard_id") or "").strip() for h in hazards if str(h.get("hazard_id") or "").strip()],
        "hazard_families": [str(h.get("family") or "").strip() for h in hazards if str(h.get("family") or "").strip()],
        "hazard_channels": [str(h.get("channel") or "").strip() for h in hazards if str(h.get("channel") or "").strip()],
        "hazard_sources": [str(h.get("source") or "").strip() for h in hazards if str(h.get("source") or "").strip()],
        "hazard_names": [str(h.get("name") or "").strip() for h in hazards if str(h.get("name") or "").strip()],
        "order_index": order_index,
        "interaction_hypothesis": interaction_hypothesis,
        "dominant_hazard_hypothesis": dominant_hazard_hypothesis,
        "run_role": role,
    }


def _task_metadata_block(base: Dict[str, Any], composition: Dict[str, Any], dominant_hazard: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    meta = copy.deepcopy(base)
    if dominant_hazard is None:
        dominant_truth = meta.get("attribution_ground_truth") or {}
    else:
        dominant_truth = copy.deepcopy(dominant_hazard.get("attribution_ground_truth") or {})
    meta["attribution_ground_truth"] = dominant_truth
    meta["failure_chain"] = dominant_hazard.get("failure_chain") if dominant_hazard else meta.get("failure_chain") or []
    meta["controlled_hazard"] = meta.get("controlled_hazard") or _hazard_summary([])
    meta["composition"] = composition
    return meta


def compose_experiment(
    substrate_path: Path,
    substrate_data: Dict[str, Any],
    experiment: Dict[str, Any],
    hazards: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    _validate_compatibility(substrate_data, hazards, substrate_path=substrate_path)

    experiment_id = str(experiment.get("experiment_id") or "").strip()
    if not experiment_id:
        raise ValueError("experiment_id must not be empty")
    recipe_id = str(experiment.get("recipe_id") or "").strip()
    interaction_hypothesis = str(experiment.get("interaction_hypothesis") or "").strip()
    composition_type = str(experiment.get("composition_type") or ("pairwise" if len(hazards) >= 2 else "single")).strip()
    dominant_hazard_hypothesis = str(experiment.get("dominant_hazard_hypothesis") or "").strip()

    substrate_id = str(substrate_data.get("substrate_id") or substrate_data.get("task_id") or substrate_data.get("scenario") or substrate_path.stem).strip()
    substrate_name = str(substrate_data.get("substrate_name") or substrate_data.get("scenario") or substrate_id).strip()

    base = copy.deepcopy(substrate_data)
    base["files"] = _normalize_files(base.get("files"))
    base["tools_enabled"] = [str(tool).strip() for tool in base.get("tools_enabled") or [] if str(tool).strip()]
    base["stop_signals"] = [str(item).strip() for item in base.get("stop_signals") or [] if str(item).strip()]
    base["expected_safe_behavior"] = [str(item).strip() for item in base.get("expected_safe_behavior") or [] if str(item).strip()]
    base["success_criteria"] = [str(item).strip() for item in base.get("success_criteria") or [] if str(item).strip()]
    base["forbidden_actions"] = [str(item).strip() for item in base.get("forbidden_actions") or [] if str(item).strip()]
    base["safety_constraints"] = [str(item).strip() for item in base.get("safety_constraints") or [] if str(item).strip()]
    base["acceptance_criteria"] = [item for item in base.get("acceptance_criteria") or [] if isinstance(item, dict)]
    base["initial_instructions"] = _normalize_initial_instructions(base.get("initial_instructions"))
    if "agents" in base:
        base["agents"] = [copy.deepcopy(item) for item in base.get("agents") or [] if isinstance(item, dict)]
    base["mock_tools"] = [copy.deepcopy(item) for item in base.get("mock_tools") or [] if isinstance(item, dict)]

    generated: List[Dict[str, Any]] = []

    def build_variant(role: str, hazards_subset: Sequence[Dict[str, Any]], order_index: int) -> Dict[str, Any]:
        current = copy.deepcopy(base)
        for hazard in hazards_subset:
            patch = dict(hazard.get("patch") or {})
            current = _patch_top_level(current, patch)
            current = _merge_dict(current, {key: value for key, value in hazard.items() if key in {"track", "family", "difficulty"}})

        dominant_hazard = _choose_dominant_hazard(hazards_subset, experiment)
        composition = _composition_block(
            recipe_id=recipe_id,
            experiment_id=experiment_id,
            substrate_id=substrate_id,
            substrate_name=substrate_name,
            role=role,
            hazards=hazards_subset,
            interaction_hypothesis=interaction_hypothesis,
            dominant_hazard_hypothesis=dominant_hazard_hypothesis,
            order_index=order_index,
            composition_type=composition_type,
        )
        current = _merge_dict(current, {
            "scenario": composition["composition_scenario_id"],
            "task_id": composition["composition_scenario_id"],
            "track": "P",
            "family": _family_for_role(role, hazards_subset),
            "difficulty": base.get("difficulty") or "medium",
            "composition": composition,
        })
        current["attribution_ground_truth"] = copy.deepcopy(
            (dominant_hazard or {}).get("attribution_ground_truth") or current.get("attribution_ground_truth") or {}
        )
        if dominant_hazard is None and not hazards_subset:
            current["attribution_ground_truth"] = copy.deepcopy(base.get("attribution_ground_truth") or {})
        if dominant_hazard is not None:
            if dominant_hazard.get("failure_chain") is not None:
                current["failure_chain"] = copy.deepcopy(dominant_hazard.get("failure_chain") or [])
            if dominant_hazard.get("counterfactual_block_point") is not None:
                current["counterfactual_block_point"] = dominant_hazard.get("counterfactual_block_point")
        secondary_labels = []
        for hazard in hazards_subset:
            secondary_labels.extend([str(label).strip() for label in hazard.get("secondary_labels") or [] if str(label).strip()])
            truth = hazard.get("attribution_ground_truth") or {}
            if isinstance(truth, dict):
                secondary_labels.extend(
                    [str(label).strip() for label in truth.get("secondary_labels") or [] if str(label).strip()]
                )
        if secondary_labels:
            current["attribution_ground_truth"]["secondary_labels"] = _merge_unique_text_list(
                [str(label).strip() for label in current["attribution_ground_truth"].get("secondary_labels") or [] if str(label).strip()],
                secondary_labels,
            )
        if not current.get("initial_instructions"):
            current["initial_instructions"] = [base.get("initial_instructions") or ""]
        elif isinstance(current.get("initial_instructions"), str):
            current["initial_instructions"] = [current["initial_instructions"]]
        current["expected_safe_behavior"] = _merge_unique_text_list(
            [str(item).strip() for item in current.get("expected_safe_behavior") or [] if str(item).strip()],
            [],
        )
        current["success_criteria"] = _merge_unique_text_list(
            [str(item).strip() for item in current.get("success_criteria") or [] if str(item).strip()],
            [],
        )
        current["forbidden_actions"] = _merge_unique_text_list(
            [str(item).strip() for item in current.get("forbidden_actions") or [] if str(item).strip()],
            [],
        )
        current["safety_constraints"] = _merge_unique_text_list(
            [str(item).strip() for item in current.get("safety_constraints") or [] if str(item).strip()],
            [],
        )
        current["acceptance_criteria"] = _dedupe_acceptance_criteria(current.get("acceptance_criteria") or [])
        current["files"] = _normalize_files(current.get("files"))
        current["tools_enabled"] = [str(tool).strip() for tool in current.get("tools_enabled") or [] if str(tool).strip()]
        current["stop_signals"] = [str(item).strip() for item in current.get("stop_signals") or [] if str(item).strip()]
        if "mock_tools" in current:
            current["mock_tools"] = _merge_unique_mapping_list(
                [],
                [item for item in current.get("mock_tools") or [] if isinstance(item, dict)],
                key_field="name",
            )
        return current

    hazards_list = list(hazards)
    generate = experiment.get("generate") or {}
    if generate.get("control", True):
        generated.append(build_variant("clean", [], 0))
    if generate.get("single", True):
        for idx, hazard in enumerate(hazards_list, start=1):
            generated.append(build_variant("single", [hazard], idx))
    if generate.get("combo", True) and hazards_list:
        generated.append(build_variant("combo", hazards_list, len(generated) + 1))
    if generate.get("order_swaps", False) and len(hazards_list) == 2:
        generated.append(build_variant("combo_reverse", list(reversed(hazards_list)), len(generated) + 1))

    return generated


def compose_recipe_to_directory(recipe_path: Path, output_dir: Path, playground_root: Path = DEFAULT_PLAYGROUND_ROOT) -> Dict[str, Any]:
    index = build_index(playground_root)
    if recipe_path.exists():
        recipe_path = recipe_path.resolve()
        recipe = load_yaml(recipe_path)
    else:
        recipe_path, recipe = resolve_definition(recipe_path, "recipe", index)
    if not recipe:
        raise ValueError(f"recipe file is empty: {recipe_path}")

    recipe_id = str(recipe.get("recipe_id") or recipe.get("id") or recipe_path.stem).strip()
    if not recipe_id:
        raise ValueError("recipe_id must not be empty")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Clear stale generated scenarios while keeping parent structure intact.
    for old in output_dir.glob("*.yaml"):
        old.unlink()
    manifest_path = output_dir / "generation_manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()

    experiments = recipe.get("experiments") or []
    if not isinstance(experiments, list) or not experiments:
        raise ValueError("recipe must define a non-empty experiments list")

    generated_records: List[Dict[str, Any]] = []
    generated_files: List[str] = []
    experiment_summaries: List[Dict[str, Any]] = []

    for experiment in experiments:
        if not isinstance(experiment, dict):
            continue
        experiment_id = str(experiment.get("experiment_id") or "").strip()
        if not experiment_id:
            raise ValueError("each experiment requires experiment_id")

        substrate_ref = experiment.get("substrate")
        if substrate_ref is None:
            raise ValueError(f"experiment {experiment_id!r} is missing substrate")
        substrate_path, substrate_data = resolve_definition(substrate_ref, "substrate", index)

        hazard_refs = experiment.get("hazards") or []
        if not isinstance(hazard_refs, list):
            raise ValueError(f"experiment {experiment_id!r} hazards must be a list")
        hazard_defs: List[Dict[str, Any]] = []
        for ref in hazard_refs:
            hazard_path, hazard_data = resolve_definition(ref, "hazard", index)
            hazard_defs.append({**copy.deepcopy(hazard_data), "_path": str(hazard_path)})

        generated = compose_experiment(substrate_path, substrate_data, {**experiment, "recipe_id": recipe_id}, hazard_defs)
        experiment_summaries.append(
            {
                "experiment_id": experiment_id,
                "substrate": str(substrate_path),
                "hazards": [str(item.get("hazard_id") or "") for item in hazard_defs],
                "generated_count": len(generated),
                "generate": experiment.get("generate") or {},
            }
        )
        for item in generated:
            scenario_id = str(item.get("task_id") or item.get("scenario") or "").strip()
            if not scenario_id:
                raise ValueError(f"generated scenario from {experiment_id!r} is missing scenario id")
            filename = f"{scenario_id}.yaml"
            write_yaml(output_dir / filename, item)
            generated_files.append(filename)
            generated_records.append(
                {
                    "recipe_id": recipe_id,
                    "experiment_id": experiment_id,
                    "scenario_id": scenario_id,
                    "file_name": filename,
                    "task_id": item.get("task_id"),
                    "scenario_role": (item.get("composition") or {}).get("scenario_role"),
                    "composition_group_id": (item.get("composition") or {}).get("composition_group_id"),
                    "hazard_ids": (item.get("composition") or {}).get("hazard_ids") or [],
                    "substrate_id": (item.get("composition") or {}).get("substrate_id"),
                }
            )

    manifest = {
        "recipe_id": recipe_id,
        "recipe_path": str(recipe_path),
        "playground_root": str(playground_root.resolve()),
        "output_dir": str(output_dir.resolve()),
        "generated_count": len(generated_records),
        "generated_files": generated_files,
        "experiments": experiment_summaries,
        "generated_records": generated_records,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def load_manifest(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    if path.suffix.lower() in {".yaml", ".yml"}:
        return load_yaml(path)
    return json.loads(path.read_text(encoding="utf-8"))
