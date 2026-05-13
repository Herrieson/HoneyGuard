#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error, request

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.experiments.mvp.common import (  # noqa: E402
    DEFAULT_OUTPUT_ROOT,
    SERVER_RUNTIME_METADATA_PATH,
    build_api_headers,
    now_utc_compact,
    quote_command,
    slugify,
)


BATCH_OUTPUT_ROOT = DEFAULT_OUTPUT_ROOT / "batch_runs"
MODEL_IDENTIFIER_ENV_KEYS = ("OPENAI_MODEL", "MODEL", "MODEL_NAME", "AZURE_OPENAI_DEPLOYMENT")
SECRET_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class ModelSpec:
    label: str
    env: Dict[str, str]


@dataclass
class JobSpec:
    suite: str
    split: str
    baseline: str
    tag: str
    recipe: str = ""


@dataclass
class RunningServer:
    proc: subprocess.Popen[str]
    stdout_handle: Any
    stderr_handle: Any
    command: List[str]
    stdout_path: Path
    stderr_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run TraceProbe MVP experiments across multiple models by starting one API "
            "server per model and invoking the existing experiment runners."
        )
    )
    parser.add_argument("--models", nargs="*", default=[], help="Model labels to run. Overrides models from --matrix.")
    parser.add_argument("--matrix", default="", help="Optional YAML file with models and jobs.")
    parser.add_argument(
        "--job",
        action="append",
        default=[],
        help=(
            "Repeatable job spec. Prefer comma key/value form, e.g. "
            "suite=outcome,split=v0_2_test,baseline=naive,tag=v0_2 or "
            "suite=playground,recipe=configs/mvp/playground/recipes/v0_2_compositional_playground.yaml,"
            "baseline=naive,tag=v0_2_compositional_playground. "
            "Also accepts outcome:<split>:<baseline>:<tag> and playground:<recipe>:<baseline>:<tag>."
        ),
    )
    parser.add_argument("--suite", choices=("outcome", "playground"), default="outcome", help="Default suite if --job is not supplied.")
    parser.add_argument("--split", default="v0_2_test", help="Default outcome split if --job is not supplied.")
    parser.add_argument(
        "--baseline",
        action="append",
        choices=("naive", "guarded"),
        default=[],
        help="Default baseline if --job is not supplied. Repeat to run several baselines on the same server.",
    )
    parser.add_argument("--tag", default="v0_2", help="Default tag if --job is not supplied.")
    parser.add_argument(
        "--recipe",
        default="configs/mvp/playground/recipes/v0_2_compositional_playground.yaml",
        help="Default playground recipe if --job is not supplied and --suite=playground.",
    )
    parser.add_argument("--server-host", default="127.0.0.1", help="Host passed to uvicorn.")
    parser.add_argument("--client-host", default="127.0.0.1", help="Host used in client --base-url.")
    parser.add_argument("--port", type=int, default=8000, help="Starting port for the per-model API server.")
    parser.add_argument(
        "--fixed-port",
        action="store_true",
        help="Use --port exactly instead of searching for the next free port.",
    )
    parser.add_argument("--port-search-window", type=int, default=100, help="Number of ports to scan when --fixed-port is not set.")
    parser.add_argument("--server-timeout", type=float, default=120.0, help="Seconds to wait for API runtime metadata.")
    parser.add_argument("--shutdown-timeout", type=float, default=20.0, help="Seconds to wait before killing a stopped server.")
    parser.add_argument("--scenario-timeout", type=float, default=120.0, help="Timeout passed to scenario runners.")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT), help="Root directory for experiment run outputs.")
    parser.add_argument("--batch-output-root", default=str(BATCH_OUTPUT_ROOT), help="Root directory for batch manifests and logs.")
    parser.add_argument("--uvicorn-app", default="api:app", help="ASGI app passed to uvicorn.")
    parser.add_argument("--token-env", default="HSE_API_TOKEN", help="API token env var used by readiness checks and runners.")
    parser.add_argument(
        "--require-model-match",
        dest="require_model_match",
        action="store_true",
        help="Require the server runtime model identifier to match the model label. Enabled by default.",
    )
    parser.add_argument(
        "--no-require-model-match",
        dest="require_model_match",
        action="store_false",
        help="Disable runtime-model consistency checks. Use only for exceptional compatibility cases.",
    )
    parser.add_argument("--continue-on-error", action="store_true", help="Continue with later jobs/models after a failure.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned server/client commands without starting the server.")
    parser.set_defaults(require_model_match=True)
    return parser.parse_args()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_suite(raw: str) -> str:
    value = str(raw or "").strip().lower().replace("_", "-")
    if value in {"outcome", "mvp-outcome", "mvp-outcome-benchmark"}:
        return "outcome"
    if value in {"playground", "compositional", "compositional-playground", "mvp-compositional-playground"}:
        return "playground"
    raise SystemExit(f"Unknown job suite: {raw!r}")


def expand_env_value(value: Any, *, context: str) -> str:
    text = "" if value is None else str(value)

    def replace(match: re.Match[str]) -> str:
        env_name = match.group(1) or match.group(2)
        resolved = os.getenv(env_name)
        if resolved is None:
            raise SystemExit(f"{context} references missing environment variable {env_name!r}")
        return resolved

    return ENV_REF_RE.sub(replace, text)


def redact_env(env: Dict[str, str]) -> Dict[str, str]:
    redacted: Dict[str, str] = {}
    for key, value in sorted(env.items()):
        if any(marker in key.upper() for marker in SECRET_ENV_MARKERS):
            redacted[key] = "<set>" if value else ""
        else:
            redacted[key] = value
    return redacted


def normalize_model_item(item: Any, *, source: str) -> ModelSpec:
    if isinstance(item, str):
        label = item.strip()
        if not label:
            raise SystemExit(f"Empty model label in {source}")
        return ModelSpec(label=label, env={})
    if not isinstance(item, dict):
        raise SystemExit(f"Model entries in {source} must be strings or mappings.")
    label = str(item.get("label") or item.get("model") or item.get("name") or "").strip()
    if not label:
        raise SystemExit(f"Model mapping in {source} is missing label/model/name.")
    raw_env = item.get("env") or {}
    if not isinstance(raw_env, dict):
        raise SystemExit(f"Model env for {label!r} in {source} must be a mapping.")
    env = {str(key): expand_env_value(value, context=f"model {label!r}") for key, value in raw_env.items()}
    return ModelSpec(label=label, env=env)


def load_matrix(path: str) -> tuple[List[ModelSpec], List[JobSpec]]:
    if not path.strip():
        return [], []
    matrix_path = Path(path).expanduser().resolve()
    payload = yaml.safe_load(matrix_path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise SystemExit(f"Matrix must contain a YAML mapping: {matrix_path}")
    raw_models = payload.get("models") or []
    raw_jobs = payload.get("jobs") or []
    if not isinstance(raw_models, list):
        raise SystemExit(f"matrix models must be a list: {matrix_path}")
    if not isinstance(raw_jobs, list):
        raise SystemExit(f"matrix jobs must be a list: {matrix_path}")
    models = [normalize_model_item(item, source=str(matrix_path)) for item in raw_models]
    jobs = [normalize_job_mapping(item, source=str(matrix_path)) for item in raw_jobs]
    return models, jobs


def normalize_job_mapping(item: Any, *, source: str) -> JobSpec:
    if isinstance(item, str):
        return parse_job_string(item)
    if not isinstance(item, dict):
        raise SystemExit(f"Job entries in {source} must be strings or mappings.")
    suite = normalize_suite(str(item.get("suite") or item.get("kind") or "outcome"))
    baseline = str(item.get("baseline") or "").strip()
    if baseline not in {"naive", "guarded"}:
        raise SystemExit(f"Job in {source} has invalid baseline: {baseline!r}")
    tag = str(item.get("tag") or "").strip()
    if suite == "outcome":
        split = str(item.get("split") or "v0_2_test").strip()
        if not split:
            raise SystemExit(f"Outcome job in {source} is missing split.")
        return JobSpec(suite=suite, split=split, baseline=baseline, tag=tag, recipe="")
    recipe = str(item.get("recipe") or "").strip()
    if not recipe:
        raise SystemExit(f"Playground job in {source} is missing recipe.")
    return JobSpec(suite=suite, split="", baseline=baseline, tag=tag, recipe=recipe)


def parse_job_string(raw: str) -> JobSpec:
    text = raw.strip()
    if not text:
        raise SystemExit("Empty --job spec.")
    if "=" in text:
        pairs: Dict[str, str] = {}
        for chunk in text.split(","):
            key, sep, value = chunk.partition("=")
            if not sep:
                raise SystemExit(f"Invalid --job key/value chunk: {chunk!r}")
            pairs[key.strip()] = value.strip()
        return normalize_job_mapping(pairs, source="--job")

    suite_part, sep, rest = text.partition(":")
    if not sep:
        raise SystemExit(f"Invalid --job spec: {raw!r}")
    suite = normalize_suite(suite_part)
    parts = rest.split(":")
    if suite == "outcome":
        if len(parts) < 3:
            raise SystemExit("Outcome --job format is outcome:<split>:<baseline>:<tag>.")
        split, baseline, tag = parts[0], parts[1], ":".join(parts[2:])
        return normalize_job_mapping({"suite": suite, "split": split, "baseline": baseline, "tag": tag}, source="--job")
    if len(parts) < 3:
        raise SystemExit("Playground --job format is playground:<recipe>:<baseline>:<tag>.")
    recipe, baseline, tag = parts[0], parts[1], ":".join(parts[2:])
    return normalize_job_mapping({"suite": suite, "recipe": recipe, "baseline": baseline, "tag": tag}, source="--job")


def resolve_models(args: argparse.Namespace, matrix_models: List[ModelSpec]) -> List[ModelSpec]:
    if args.models:
        models = [normalize_model_item(item, source="--models") for item in args.models]
    else:
        models = matrix_models
    if not models:
        raise SystemExit("No models specified. Pass --models or provide models in --matrix.")
    return models


def resolve_jobs(args: argparse.Namespace, matrix_jobs: List[JobSpec]) -> List[JobSpec]:
    if args.job:
        jobs = [parse_job_string(item) for item in args.job]
    elif matrix_jobs:
        jobs = matrix_jobs
    else:
        baselines = args.baseline or ["naive"]
        jobs = []
        suite = normalize_suite(args.suite)
        for baseline in baselines:
            if suite == "outcome":
                jobs.append(JobSpec(suite="outcome", split=args.split, baseline=baseline, tag=args.tag, recipe=""))
            else:
                jobs.append(JobSpec(suite="playground", split="", baseline=baseline, tag=args.tag, recipe=args.recipe))
    if not jobs:
        raise SystemExit("No jobs resolved.")
    return jobs


def build_server_env(model: ModelSpec) -> tuple[Dict[str, str], Dict[str, str]]:
    env = os.environ.copy()
    for key in MODEL_IDENTIFIER_ENV_KEYS:
        env.pop(key, None)

    overrides = dict(model.env)
    if not any(key in overrides for key in MODEL_IDENTIFIER_ENV_KEYS):
        overrides["OPENAI_MODEL"] = model.label

    env.update(overrides)
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env, overrides


def is_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def choose_port(host: str, start_port: int, window: int, fixed: bool) -> int:
    if fixed:
        return start_port
    for port in range(start_port, start_port + max(1, window)):
        if is_port_available(host, port):
            return port
    raise SystemExit(f"No free port found on {host!r} in range {start_port}-{start_port + max(1, window) - 1}.")


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def start_server(command: List[str], env: Dict[str, str], log_dir: Path) -> RunningServer:
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / "server.stdout.log"
    stderr_path = log_dir / "server.stderr.log"
    stdout_handle = stdout_path.open("w", encoding="utf-8")
    stderr_handle = stderr_path.open("w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            command,
            cwd=str(REPO_ROOT),
            env=env,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            start_new_session=True,
        )
    except Exception:
        stdout_handle.close()
        stderr_handle.close()
        raise
    return RunningServer(
        proc=proc,
        stdout_handle=stdout_handle,
        stderr_handle=stderr_handle,
        command=command,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def stop_server(server: RunningServer, timeout: float) -> None:
    proc = server.proc
    try:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except Exception:
                    proc.kill()
                proc.wait(timeout=5)
    finally:
        server.stdout_handle.close()
        server.stderr_handle.close()


def fetch_runtime_payload(base_url: str, token_env: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + SERVER_RUNTIME_METADATA_PATH
    req = request.Request(url, headers=build_api_headers(token_env), method="GET")
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError(f"runtime metadata must be a JSON object, got {type(payload).__name__}")
    return payload


def wait_for_runtime(
    *,
    server: RunningServer,
    base_url: str,
    model_label: str,
    token_env: str,
    timeout: float,
    require_model_match: bool,
) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        returncode = server.proc.poll()
        if returncode is not None:
            raise RuntimeError(
                f"API server exited before readiness with code {returncode}. "
                f"See {server.stderr_path} and {server.stdout_path}."
            )
        try:
            payload = fetch_runtime_payload(base_url, token_env, timeout=5.0)
            runtime_identifier = str(payload.get("runtime_model_identifier") or "").strip()
            if require_model_match and slugify(runtime_identifier) != slugify(model_label):
                raise RuntimeError(
                    f"runtime model mismatch: model label {model_label!r}, "
                    f"server runtime identifier {runtime_identifier!r}"
                )
            return payload
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            last_error = f"HTTP {exc.code}: {body}"
            if exc.code in {401, 403}:
                raise RuntimeError(f"Readiness check is not authorized: {last_error}") from exc
        except Exception as exc:
            last_error = str(exc)
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for API server at {base_url}. Last error: {last_error}")


def pump_stream(stream: Any, log_handle: Any, printer: Any) -> None:
    try:
        for line in iter(stream.readline, ""):
            if not line:
                break
            log_handle.write(line)
            log_handle.flush()
            printer(line)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def run_logged_command(parts: List[str], *, env: Dict[str, str], log_dir: Path, log_name: str) -> int:
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / f"{log_name}.stdout.log"
    stderr_path = log_dir / f"{log_name}.stderr.log"
    with stdout_path.open("w", encoding="utf-8") as stdout_log, stderr_path.open("w", encoding="utf-8") as stderr_log:
        proc = subprocess.Popen(
            parts,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        assert proc.stdout is not None
        assert proc.stderr is not None
        stdout_thread = threading.Thread(
            target=pump_stream,
            args=(proc.stdout, stdout_log, lambda line: print(line, end="", flush=True)),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=pump_stream,
            args=(proc.stderr, stderr_log, lambda line: print(line, end="", file=sys.stderr, flush=True)),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        returncode = proc.wait()
        stdout_thread.join()
        stderr_thread.join()
    return returncode


def build_client_command(job: JobSpec, *, base_url: str, model_label: str, args: argparse.Namespace) -> List[str]:
    if job.suite == "outcome":
        command = [
            "uv",
            "run",
            "python",
            "scripts/experiments/mvp/run_mvp_outcome_benchmark.py",
            "--base-url",
            base_url,
            "--split",
            job.split,
            "--baseline",
            job.baseline,
            "--model-label",
            model_label,
            "--tag",
            job.tag,
            "--output-root",
            args.output_root,
            "--timeout",
            str(args.scenario_timeout),
        ]
    else:
        command = [
            "uv",
            "run",
            "python",
            "scripts/experiments/mvp/run_mvp_compositional_playground.py",
            "--base-url",
            base_url,
            "--recipe",
            job.recipe,
            "--baseline",
            job.baseline,
            "--model-label",
            model_label,
            "--tag",
            job.tag,
            "--output-root",
            args.output_root,
            "--timeout",
            str(args.scenario_timeout),
        ]
    if not args.require_model_match:
        command.append("--no-require-model-match")
    return command


def batch_run_name(models: List[ModelSpec], jobs: List[JobSpec]) -> str:
    model_part = f"{len(models)}models"
    if len(models) == 1:
        model_part = f"model-{slugify(models[0].label)}"
    suite_part = "-".join(sorted({job.suite for job in jobs}))
    baseline_part = "-".join(sorted({job.baseline for job in jobs}))
    return "__".join([now_utc_compact(), model_part, f"suite-{suite_part}", f"baseline-{baseline_part}"])


def dry_run(models: List[ModelSpec], jobs: List[JobSpec], args: argparse.Namespace) -> int:
    print("DRY_RUN true")
    for model_index, model in enumerate(models, start=1):
        server_env, overrides = build_server_env(model)
        port = args.port if args.fixed_port else args.port + model_index - 1
        base_url = f"http://{args.client_host}:{port}"
        server_command = ["uv", "run", "uvicorn", args.uvicorn_app, "--host", args.server_host, "--port", str(port)]
        print(f"\nMODEL {model_index}/{len(models)} {model.label}")
        print(f"SERVER_ENV_OVERRIDES {json.dumps(redact_env(overrides), ensure_ascii=True, sort_keys=True)}")
        print(f"SERVER_COMMAND {quote_command(server_command)}")
        for job_index, job in enumerate(jobs, start=1):
            client_command = build_client_command(job, base_url=base_url, model_label=model.label, args=args)
            print(f"JOB {job_index}/{len(jobs)} {json.dumps(asdict(job), ensure_ascii=True, sort_keys=True)}")
            print(f"CLIENT_COMMAND {quote_command(client_command)}")
        _ = server_env
    return 0


def main() -> int:
    args = parse_args()
    matrix_models, matrix_jobs = load_matrix(args.matrix)
    models = resolve_models(args, matrix_models)
    jobs = resolve_jobs(args, matrix_jobs)

    if args.dry_run:
        return dry_run(models, jobs, args)

    batch_dir = Path(args.batch_output_root) / batch_run_name(models, jobs)
    manifest_path = batch_dir / "batch_manifest.json"
    manifest: Dict[str, Any] = {
        "created_at": utc_now_iso(),
        "repo_root": str(REPO_ROOT),
        "batch_dir": str(batch_dir),
        "require_model_match": args.require_model_match,
        "server": {
            "uvicorn_app": args.uvicorn_app,
            "server_host": args.server_host,
            "client_host": args.client_host,
            "starting_port": args.port,
            "fixed_port": args.fixed_port,
        },
        "models": [{"label": model.label, "env_overrides": redact_env(model.env)} for model in models],
        "jobs": [asdict(job) for job in jobs],
        "runs": [],
    }
    write_json(manifest_path, manifest)
    print(f"BATCH_RUN_DIR {batch_dir}")

    failures = 0
    used_ports: set[int] = set()
    for model_index, model in enumerate(models, start=1):
        model_slug = slugify(model.label)
        print(f"\n=== MODEL {model_index}/{len(models)} {model.label} ===", flush=True)
        server_env, env_overrides = build_server_env(model)
        port_start = args.port if args.fixed_port else args.port + len(used_ports)
        port = choose_port(args.server_host, port_start, args.port_search_window, args.fixed_port)
        used_ports.add(port)
        base_url = f"http://{args.client_host}:{port}"
        model_log_dir = batch_dir / "logs" / model_slug
        server_command = ["uv", "run", "uvicorn", args.uvicorn_app, "--host", args.server_host, "--port", str(port)]
        run_record: Dict[str, Any] = {
            "model_label": model.label,
            "model_slug": model_slug,
            "status": "running",
            "started_at": utc_now_iso(),
            "port": port,
            "base_url": base_url,
            "server_command": quote_command(server_command),
            "env_overrides": redact_env(env_overrides),
            "jobs": [],
        }
        manifest["runs"].append(run_record)
        write_json(manifest_path, manifest)

        server: Optional[RunningServer] = None
        try:
            server = start_server(server_command, server_env, model_log_dir)
            runtime_payload = wait_for_runtime(
                server=server,
                base_url=base_url,
                model_label=model.label,
                token_env=args.token_env,
                timeout=args.server_timeout,
                require_model_match=args.require_model_match,
            )
            run_record["server_runtime_metadata"] = runtime_payload
            print(
                "SERVER_READY "
                f"{base_url} runtime={runtime_payload.get('runtime_model_identifier', '')!r}",
                flush=True,
            )
            write_json(manifest_path, manifest)

            for job_index, job in enumerate(jobs, start=1):
                job_name = f"{job_index:02d}_{job.suite}_{job.baseline}"
                if job.suite == "outcome":
                    job_name += f"_{slugify(job.split)}"
                else:
                    job_name += f"_{slugify(Path(job.recipe).stem)}"
                print(f"--- JOB {job_index}/{len(jobs)} {job_name} ---", flush=True)
                command = build_client_command(job, base_url=base_url, model_label=model.label, args=args)
                job_record: Dict[str, Any] = {
                    "job": asdict(job),
                    "status": "running",
                    "started_at": utc_now_iso(),
                    "command": quote_command(command),
                }
                run_record["jobs"].append(job_record)
                write_json(manifest_path, manifest)

                returncode = run_logged_command(command, env=server_env, log_dir=model_log_dir, log_name=job_name)
                job_record["returncode"] = returncode
                job_record["ended_at"] = utc_now_iso()
                if returncode == 0:
                    job_record["status"] = "completed"
                else:
                    failures += 1
                    job_record["status"] = "failed"
                    run_record["status"] = "failed"
                    write_json(manifest_path, manifest)
                    if not args.continue_on_error:
                        raise RuntimeError(f"Job failed with return code {returncode}: {quote_command(command)}")
                write_json(manifest_path, manifest)
        except KeyboardInterrupt:
            run_record["status"] = "interrupted"
            run_record["ended_at"] = utc_now_iso()
            write_json(manifest_path, manifest)
            raise
        except Exception as exc:
            failures += 1
            run_record["status"] = "failed"
            run_record["error"] = str(exc)
            print(f"MODEL_FAILED {model.label}: {exc}", file=sys.stderr, flush=True)
            if not args.continue_on_error:
                raise SystemExit(1) from exc
        finally:
            if server is not None:
                stop_server(server, args.shutdown_timeout)
            if run_record.get("status") == "running":
                run_record["status"] = "completed"
            run_record["ended_at"] = utc_now_iso()
            write_json(manifest_path, manifest)

    manifest["ended_at"] = utc_now_iso()
    manifest["status"] = "completed" if failures == 0 else "completed_with_failures"
    manifest["failure_count"] = failures
    write_json(manifest_path, manifest)
    print(f"\nBATCH_MANIFEST {manifest_path}")
    if failures:
        print(f"BATCH_COMPLETED_WITH_FAILURES {failures}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
