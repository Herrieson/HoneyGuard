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

    agent_mode = (data.get("agent_mode") or "rule").lower()
    if agent_mode not in {"rule", "llm"}:
        raise ValueError("agent_mode must be either 'rule' or 'llm'")

    coordination_pattern = (data.get("coordination_pattern") or "sequential").lower()
    if coordination_pattern not in {"sequential", "round_robin"}:
        raise ValueError("coordination_pattern must be 'sequential' or 'round_robin'")
    max_cycles = int(data.get("max_cycles") or 1)
    if max_cycles < 1:
        raise ValueError("max_cycles must be >= 1")

    llm_config = data.get("llm_config") or {}
    if llm_config and not isinstance(llm_config, dict):
        raise ValueError("llm_config must be a mapping when provided")

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
        normalized_agents.append(
            {
                "name": name,
                "mode": mode,
                "system_prompt": system_prompt,
                "tools_allowed": tools_allowed,
                "impl": impl,
                "tool_timeout_sec": tool_timeout_sec,
                "llm_config": llm_cfg,
            }
        )

    return {
        "scenario": scenario,
        "files": files,
        "tools_enabled": tools_enabled,
        "agent_mode": agent_mode,
        "agents": normalized_agents,
        "coordination_pattern": coordination_pattern,
        "max_cycles": max_cycles,
        "llm_config": llm_config,
        "initial_instructions": initial_instructions,
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
