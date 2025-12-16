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

    return {
        "scenario": scenario,
        "files": files,
        "tools_enabled": tools_enabled,
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
