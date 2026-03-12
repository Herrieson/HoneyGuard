#!/usr/bin/env bash
set -euo pipefail

# 运行攻击场景的便捷脚本。
# 默认流程:
# 1) 读取 YAML 配置并初始化 session
# 2) 连续调用 run_step
# 3) 默认自动清理 session（可通过 --keep-session 保留）

usage() {
  cat <<'EOF'
Usage:
  scripts/run_attack_scenario.sh [options]

Options:
  --config PATH          Scenario YAML path (default: configs/attack/attack_auto_insider_01.yaml)
  --base-url URL         API base url (default: http://127.0.0.1:8000)
  --steps N              Number of run_step calls (default: 1)
  --instruction TEXT     Optional instruction for the first step
  --session-id ID        Reuse existing session (skip initialize)
  --keep-session         Do not auto cleanup session
  -h, --help             Show help

Notes:
  - If HSE_API_TOKEN is set, requests will include X-API-Token automatically.
  - When --instruction is omitted, run_step will consume initial_instructions from config (if any).
EOF
}

CONFIG="configs/attack/attack_auto_insider_01.yaml"
BASE_URL="http://127.0.0.1:8000"
STEPS=1
INSTRUCTION=""
SESSION_ID=""
KEEP_SESSION=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="${2:-}"
      shift 2
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --steps)
      STEPS="${2:-}"
      shift 2
      ;;
    --instruction)
      INSTRUCTION="${2:-}"
      shift 2
      ;;
    --session-id)
      SESSION_ID="${2:-}"
      shift 2
      ;;
    --keep-session)
      KEEP_SESSION=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! [[ "${STEPS}" =~ ^[0-9]+$ ]] || [[ "${STEPS}" -lt 1 ]]; then
  echo "Error: --steps must be an integer >= 1" >&2
  exit 1
fi

AUTH_HEADERS=()
if [[ -n "${HSE_API_TOKEN:-}" ]]; then
  AUTH_HEADERS=(-H "X-API-Token: ${HSE_API_TOKEN}")
fi

if [[ -z "${SESSION_ID}" ]]; then
  echo "[1/3] Initializing session from config: ${CONFIG}"
  INIT_OUT="$(uv run python scripts/init_from_config.py --config "${CONFIG}" --base-url "${BASE_URL}")"
  echo "${INIT_OUT}"
  SESSION_ID="$(printf '%s\n' "${INIT_OUT}" | awk '/Session initialized:/ {print $3}')"
  if [[ -z "${SESSION_ID}" ]]; then
    echo "Error: failed to parse session_id from init output" >&2
    exit 1
  fi
else
  echo "[1/3] Reusing existing session: ${SESSION_ID}"
fi

cleanup() {
  if [[ "${KEEP_SESSION}" -eq 1 ]]; then
    echo "[3/3] Keeping session (no cleanup): ${SESSION_ID}"
    return
  fi
  if [[ -n "${SESSION_ID}" ]]; then
    echo "[3/3] Cleaning up session: ${SESSION_ID}"
    curl -s -X DELETE "${BASE_URL}/v1/environment/${SESSION_ID}" "${AUTH_HEADERS[@]}" >/dev/null || true
  fi
}
trap cleanup EXIT

echo "[2/3] Running ${STEPS} step(s)..."
for ((i=1; i<=STEPS; i++)); do
  if [[ "${i}" -eq 1 && -n "${INSTRUCTION}" ]]; then
    PAYLOAD="$(uv run python - "${SESSION_ID}" "${INSTRUCTION}" <<'PY'
import json, sys
print(json.dumps({"session_id": sys.argv[1], "user_instruction": sys.argv[2]}, ensure_ascii=False))
PY
)"
  else
    PAYLOAD="$(uv run python - "${SESSION_ID}" <<'PY'
import json, sys
print(json.dumps({"session_id": sys.argv[1]}, ensure_ascii=False))
PY
)"
  fi

  RESP="$(curl -s -X POST "${BASE_URL}/v1/environment/run_step" \
    -H "Content-Type: application/json" \
    "${AUTH_HEADERS[@]}" \
    -d "${PAYLOAD}")"

  echo "----- step ${i} -----"
  printf '%s\n' "${RESP}"
  printf '%s\n' "${RESP}" | uv run python - <<'PY'
import json, sys
text = sys.stdin.read().strip()
if not text:
    print("[warn] empty response")
    raise SystemExit(0)
try:
    data = json.loads(text)
except Exception:
    print("[warn] non-json response")
    raise SystemExit(0)
agent = data.get("agent_response")
tool_calls = data.get("tool_calls") or []
trace_id = data.get("trace_id")
if isinstance(agent, str):
    preview = agent.replace("\n", " ").strip()
    if len(preview) > 220:
        preview = preview[:220] + "..."
    print(f"[agent_response] {preview}")
print(f"[tool_calls] {len(tool_calls)}")
if trace_id:
    print(f"[trace_id] {trace_id}")
PY
done

echo "Session: ${SESSION_ID}"
