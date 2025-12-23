#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, request

import yaml


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run all scenarios in a directory and log results to JSONL and SQLite.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="HoneyGuard API base URL")
    parser.add_argument("--target", default="configs/generated_scenarios_asb_v2", help="Path to a scenario YAML file or directory")
    parser.add_argument("--instruction", default="", help="Override user instruction (otherwise uses config.initial_instructions)")
    parser.add_argument("--limit", type=int, default=0, help="Max number of scenarios to run (0 means no limit)")
    parser.add_argument("--timeout", type=float, default=30, help="HTTP request timeout in seconds")
    parser.add_argument("--token-env", default="HSE_API_TOKEN", help="Env var name for API token; empty to skip auth header")
    parser.add_argument("--output", default="logs/asb_v2_test_results.jsonl", help="Path to JSONL log file")
    parser.add_argument("--db-path", default="logs/hse.db", help="Path to SQLite DB for recording results")
    return parser.parse_args()


def collect_configs(target: Path) -> List[Path]:
    if target.is_dir():
        return sorted(target.glob("*.yaml"))
    if target.is_file():
        return [target]
    return []


def load_config(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scenario_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_path TEXT NOT NULL,
            session_id TEXT,
            status TEXT NOT NULL,
            base_url TEXT,
            instruction TEXT,
            init_response TEXT,
            run_response TEXT,
            error TEXT,
            started_at TEXT,
            ended_at TEXT
        );
        """
    )
    conn.commit()


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def insert_db(conn: sqlite3.Connection, record: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO scenario_runs
        (config_path, session_id, status, base_url, instruction, init_response, run_response, error, started_at, ended_at)
        VALUES (:config_path, :session_id, :status, :base_url, :instruction, :init_response, :run_response, :error, :started_at, :ended_at)
        """,
        record,
    )
    conn.commit()


def build_headers(token_env: str) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = os.getenv(token_env) if token_env else None
    if token:
        headers["X-API-Token"] = token
    return headers


def http_request(url: str, payload: Optional[Dict[str, Any]], headers: Dict[str, str], timeout: float, method: str) -> Tuple[int, str]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = request.Request(url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return resp.getcode(), body


def run_scenario(
    config_path: Path,
    base_url: str,
    instruction: str,
    headers: Dict[str, str],
    timeout: float,
) -> Dict[str, Any]:
    started_at = now_iso()
    record: Dict[str, Any] = {
        "config_path": str(config_path),
        "session_id": None,
        "status": "pending",
        "base_url": base_url,
        "instruction": instruction,
        "init_response": None,
        "run_response": None,
        "error": None,
        "started_at": started_at,
        "ended_at": None,
    }

    try:
        cfg = load_config(config_path)
    except Exception as exc:
        record.update(status="config_load_failed", error=str(exc), ended_at=now_iso())
        return record

    try:
        code, init_text = http_request(f"{base_url}/v1/environment/initialize", cfg, headers, timeout, method="POST")
        record["init_response"] = init_text
        init_json = json.loads(init_text) if init_text else {}
        session_id = init_json.get("session_id")
        record["session_id"] = session_id
        if code >= 400 or not session_id:
            raise RuntimeError(f"init failed: status={code}, session_id={session_id}")
    except Exception as exc:
        record.update(status="init_failed", error=str(exc), ended_at=now_iso())
        return record

    try:
        payload = {"session_id": record["session_id"]}
        if instruction:
            payload["user_instruction"] = instruction
        code, run_text = http_request(f"{base_url}/v1/environment/run_step", payload, headers, timeout, method="POST")
        record["run_response"] = run_text
        if code >= 400:
            record.update(status="api_error", error=f"run_step http {code}")
        else:
            try:
                run_json = json.loads(run_text or "{}")
            except Exception as exc:  # malformed JSON
                record.update(status="run_failed", error=f"invalid run_step json: {exc}")
            else:
                if run_json.get("acceptance_passed") is True:
                    record["status"] = "passed"
                elif run_json.get("detail"):
                    record["status"] = "api_error"
                    record["error"] = str(run_json.get("detail"))
                else:
                    record["status"] = "failed"
                    record["error"] = run_json.get("error") or "acceptance not passed"
    except Exception as exc:
        record.update(status="run_failed", error=str(exc))

    cleanup_session(base_url, record["session_id"], headers, timeout)
    if not record.get("ended_at"):
        record["ended_at"] = now_iso()
    return record


def cleanup_session(base_url: str, session_id: Optional[str], headers: Dict[str, str], timeout: float) -> None:
    if not session_id:
        return
    try:
        http_request(f"{base_url}/v1/environment/{session_id}", None, headers, timeout, method="DELETE")
    except Exception:
        pass


def main() -> int:
    args = parse_args()
    target = Path(args.target)
    configs = collect_configs(target)
    if not configs:
        print(f"No scenario configs found under {target}", file=sys.stderr)
        return 1

    if args.limit and args.limit > 0:
        configs = configs[: args.limit]

    headers = build_headers(args.token_env)
    jsonl_path = Path(args.output)
    db_path = Path(args.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    ensure_db(conn)

    success = 0
    for idx, cfg_path in enumerate(configs, start=1):
        print(f"[{idx}/{len(configs)}] Running {cfg_path} ...")
        record = run_scenario(cfg_path, args.base_url, args.instruction, headers, args.timeout)
        if record["status"] == "passed":
            success += 1
            print(f"  ✔ passed (session_id={record['session_id']})")
        else:
            print(f"  ✖ {record['status']}: {record.get('error')}")
        append_jsonl(jsonl_path, record)
        insert_db(conn, record)

    print(f"Done. {success}/{len(configs)} scenarios passed acceptance. JSONL: {jsonl_path}, DB: {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
