#!/usr/bin/env bash
set -euo pipefail

# Run end-to-end against all ASB-generated scenarios (or a specific config).
# Usage:
#   ./test/run_asb_scenarios.sh [base_url] [config_path_or_dir] [user_instruction]
# Defaults:
#   base_url="http://127.0.0.1:8000"
#   config_path_or_dir="configs/generated_scenarios_asb_v2"
#   user_instruction="" (empty to consume initial_instructions from config)

BASE_URL="${1:-http://127.0.0.1:8000}"
TARGET="${2:-configs/generated_scenarios_asb_v2}"
INSTRUCTION="${3-}"

if [[ -d "${TARGET}" ]]; then
  CONFIGS=("${TARGET}"/*.yaml)
else
  CONFIGS=("${TARGET}")
fi

if [[ ${#CONFIGS[@]} -eq 0 ]]; then
  echo "No configs found under ${TARGET}" >&2
  exit 1
fi

JQ_BIN="$(command -v jq || true)"

for CONFIG_PATH in "${CONFIGS[@]}"; do
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "Skipping missing file: ${CONFIG_PATH}" >&2
    continue
  fi

  echo "=== Initializing session from ${CONFIG_PATH} against ${BASE_URL} ==="
  SESSION_ID=$(uv run python scripts/init_from_config.py --config "${CONFIG_PATH}" --base-url "${BASE_URL}" | awk '{print $3}')
  echo "Session initialized: ${SESSION_ID}"

  cleanup() {
    echo "Cleaning up session ${SESSION_ID} ..."
    curl -s -X DELETE "${BASE_URL}/v1/environment/${SESSION_ID}" >/dev/null || true
  }
  trap cleanup EXIT

  if [[ -n "${INSTRUCTION}" ]]; then
    echo "Running step with instruction: ${INSTRUCTION}"
    PAYLOAD=$(printf '{"session_id":"%s","user_instruction":"%s"}' "${SESSION_ID}" "${INSTRUCTION}")
  else
    echo "Running step using config.initial_instructions"
    PAYLOAD=$(printf '{"session_id":"%s"}' "${SESSION_ID}")
  fi

  RESPONSE=$(curl -s -X POST "${BASE_URL}/v1/environment/run_step" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}")

  if [[ -n "${JQ_BIN}" ]]; then
    echo "${RESPONSE}" | "${JQ_BIN}" .
  else
    echo "${RESPONSE}"
  fi

  cleanup
  trap - EXIT
  echo "=== Done: ${CONFIG_PATH} ==="
done
