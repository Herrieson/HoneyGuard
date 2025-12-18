from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib import error, request

import yaml


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Config file must be a mapping")

    scenario = data.get("scenario")
    if not scenario:
        raise ValueError("Config missing required field: scenario")

    files = data.get("files") or {}
    if not isinstance(files, dict):
        raise ValueError("files must be a mapping of path -> content")

    tools_enabled = data.get("tools_enabled") or []
    if tools_enabled and not isinstance(tools_enabled, list):
        raise ValueError("tools_enabled must be a list")

    mock_tools = data.get("mock_tools") or []
    if mock_tools and not isinstance(mock_tools, list):
        raise ValueError("mock_tools must be a list when provided")
    normalized_mocks = []
    seen_mock_names = set()
    for idx, item in enumerate(mock_tools):
        if not isinstance(item, dict):
            raise ValueError(f"mock_tools[{idx}] must be a mapping")
        name = item.get("name")
        output = item.get("output")
        description = item.get("description")
        if not isinstance(name, str) or not name:
            raise ValueError(f"mock_tools[{idx}].name must be a non-empty string")
        if not isinstance(output, str):
            raise ValueError(f"mock_tools[{idx}].output must be a string")
        if description is not None and not isinstance(description, str):
            raise ValueError(f"mock_tools[{idx}].description must be a string when provided")
        if name in seen_mock_names:
            raise ValueError(f"mock_tools contains duplicate name: {name}")
        seen_mock_names.add(name)
        normalized_mocks.append({"name": name, "output": output, "description": description})

    # Ensure mock tools are enabled so they can be built.
    for mock in normalized_mocks:
        if mock["name"] not in tools_enabled:
            tools_enabled.append(mock["name"])

    agent_mode = (data.get("agent_mode") or "rule").lower()
    if agent_mode not in {"rule", "llm"}:
        raise ValueError("agent_mode must be either 'rule' or 'llm'")

    coordination_pattern = (data.get("coordination_pattern") or "sequential").lower()
    if coordination_pattern not in {"sequential", "round_robin", "planner_executor_verifier", "parallel"}:
        raise ValueError("coordination_pattern must be one of sequential, round_robin, planner_executor_verifier, parallel")
    max_cycles = int(data.get("max_cycles") or 1)
    if max_cycles < 1:
        raise ValueError("max_cycles must be >= 1")

    llm_config = data.get("llm_config") or {}
    if llm_config and not isinstance(llm_config, dict):
        raise ValueError("llm_config must be a mapping when provided")

    graph_template = data.get("graph_template")
    if graph_template is not None and not isinstance(graph_template, str):
        raise ValueError("graph_template must be a string when provided")

    stop_signals = data.get("stop_signals") or ["done"]
    if isinstance(stop_signals, str):
        stop_signals = [stop_signals]
    if stop_signals and not isinstance(stop_signals, list):
        raise ValueError("stop_signals must be a string or list of strings")
    for idx, sig in enumerate(stop_signals):
        if not isinstance(sig, str):
            raise ValueError(f"stop_signals[{idx}] must be a string")

    max_elapsed_sec = data.get("max_elapsed_sec")
    if max_elapsed_sec is not None:
        try:
            max_elapsed_sec = float(max_elapsed_sec)
        except Exception as exc:
            raise ValueError("max_elapsed_sec must be numeric") from exc
        if max_elapsed_sec <= 0:
            raise ValueError("max_elapsed_sec must be > 0 when provided")

    initial_instructions = data.get("initial_instructions") or []
    if isinstance(initial_instructions, str):
        initial_instructions = [initial_instructions]
    if initial_instructions and not isinstance(initial_instructions, list):
        raise ValueError("initial_instructions must be a string or list of strings when provided")
    for idx, item in enumerate(initial_instructions):
        if not isinstance(item, str):
            raise ValueError(f"initial_instructions[{idx}] must be a string")

    agents = data.get("agents") or []
    if agents and not isinstance(agents, list):
        raise ValueError("agents must be a list of {name, mode}")
    normalized_agents = []
    for item in agents:
        if not isinstance(item, dict):
            raise ValueError("each agent entry must be a mapping")
        name = item.get("name")
        mode = (item.get("mode") or "rule").lower()
        if not name:
            raise ValueError("each agent needs a name")
        if mode not in {"rule", "llm"}:
            raise ValueError("agent.mode must be 'rule' or 'llm'")
        system_prompt = item.get("system_prompt")
        tools_allowed = item.get("tools_allowed")
        if tools_allowed is not None and not isinstance(tools_allowed, list):
            raise ValueError("tools_allowed must be a list when provided")
        impl = item.get("impl")
        tool_timeout_sec = item.get("tool_timeout_sec")
        llm_cfg = item.get("llm_config")
        if llm_cfg is not None and not isinstance(llm_cfg, dict):
            raise ValueError("agent.llm_config must be a mapping when provided")
        memory_mode = (item.get("memory_mode") or "window").lower()
        if memory_mode not in {"window", "none"}:
            raise ValueError("agent.memory_mode must be 'window' or 'none'")
        bb_read = item.get("blackboard_read_keys")
        if bb_read is not None and not isinstance(bb_read, list):
            raise ValueError("blackboard_read_keys must be a list when provided")
        bb_write = item.get("blackboard_write_keys")
        if bb_write is not None and not isinstance(bb_write, list):
            raise ValueError("blackboard_write_keys must be a list when provided")
        normalized_agents.append(
            {
                "name": name,
                "mode": mode,
                "system_prompt": system_prompt,
                "tools_allowed": tools_allowed,
                "impl": impl,
                "tool_timeout_sec": tool_timeout_sec,
                "llm_config": llm_cfg,
                "memory_mode": memory_mode,
                "blackboard_read_keys": bb_read,
                "blackboard_write_keys": bb_write,
            }
        )

    shared_context = data.get("shared_context") or {}
    if shared_context and not isinstance(shared_context, dict):
        raise ValueError("shared_context must be a mapping when provided")

    acceptance_logic = (data.get("acceptance_logic") or "all").lower()
    if acceptance_logic not in {"all", "any"}:
        raise ValueError("acceptance_logic must be 'all' or 'any'")
    acceptance_criteria = data.get("acceptance_criteria") or []
    if acceptance_criteria and not isinstance(acceptance_criteria, list):
        raise ValueError("acceptance_criteria must be a list when provided")
    normalized_criteria = []
    for idx, crit in enumerate(acceptance_criteria):
        if not isinstance(crit, dict):
            raise ValueError(f"acceptance_criteria[{idx}] must be a mapping")
        ctype = crit.get("type")
        valid_types = {
            "response_contains",
            "tool_output_contains",
            "shared_context_equals",
            "file_contains",
            "file_not_contains",
            "file_hash_equals",
            "file_changed",
            "command_exit_code",
            "command_output_contains",
        }
        if ctype not in valid_types:
            raise ValueError(f"acceptance_criteria[{idx}].type must be one of {sorted(valid_types)}")
        value = crit.get("value")
        if not isinstance(value, str):
            raise ValueError(f"acceptance_criteria[{idx}].value must be a string")
        key = crit.get("key")
        path = crit.get("path")
        command = crit.get("command")
        expect_exit_code = crit.get("expect_exit_code")
        if ctype == "shared_context_equals":
            if not isinstance(key, str):
                raise ValueError(f"acceptance_criteria[{idx}].key must be a string for shared_context_equals")
        if ctype in {"file_contains", "file_not_contains", "file_hash_equals", "file_changed"}:
            if not isinstance(path, str) or not path:
                raise ValueError(f"acceptance_criteria[{idx}].path is required for file-based checks")
        if ctype in {"command_exit_code", "command_output_contains"}:
            if not isinstance(command, str) or not command:
                raise ValueError(f"acceptance_criteria[{idx}].command is required for command checks")
            if ctype == "command_exit_code" and expect_exit_code is not None:
                try:
                    expect_exit_code = int(expect_exit_code)
                except Exception:
                    raise ValueError(f"acceptance_criteria[{idx}].expect_exit_code must be int when provided")
        normalized_criteria.append(
            {
                "type": ctype,
                "value": value,
                "key": key,
                "path": path,
                "command": command,
                "expect_exit_code": expect_exit_code,
            }
        )

    return {
        "scenario": scenario,
        "files": files,
        "tools_enabled": tools_enabled,
        "mock_tools": normalized_mocks,
        "agent_mode": agent_mode,
        "agents": normalized_agents,
        "coordination_pattern": coordination_pattern,
        "max_cycles": max_cycles,
        "llm_config": llm_config,
        "initial_instructions": initial_instructions,
        "graph_template": graph_template,
        "stop_signals": stop_signals,
        "max_elapsed_sec": max_elapsed_sec,
        "shared_context": shared_context,
        "acceptance_criteria": normalized_criteria,
        "acceptance_logic": acceptance_logic,
    }


def initialize_environment(base_url: str, payload: dict) -> dict:
    url = base_url.rstrip("/") + "/v1/environment/initialize"
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with request.urlopen(req) as resp:
        resp_body = resp.read().decode("utf-8")
        return json.loads(resp_body)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialize an HSE environment from a YAML config file."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the YAML config describing scenario/files/tools.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Base URL of the running HSE API (default: http://127.0.0.1:8000).",
    )
    args = parser.parse_args()

    try:
        payload = load_config(Path(args.config))
        resp = initialize_environment(args.base_url, payload)
    except error.HTTPError as exc:
        sys.stderr.write(f"HTTP error {exc.code}: {exc.read().decode()}\n")
        return 1
    except error.URLError as exc:
        sys.stderr.write(f"Failed to reach server: {exc.reason}\n")
        return 1
    except Exception as exc:  # pragma: no cover - CLI error path
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    session_id = resp.get("session_id")
    if not session_id:
        sys.stderr.write(f"Unexpected response: {resp}\n")
        return 1

    print(f"Session initialized: {session_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
