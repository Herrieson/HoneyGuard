#!/usr/bin/env bash
set -euo pipefail

# End-to-end helper: initialize a session, run one step, then clean up.
# Usage:
#   ./test/run_end_to_end.sh [user_instruction] [base_url] [config_path]
# Defaults:
#   user_instruction="读取 report.txt"
#   base_url="http://127.0.0.1:8000"
#   config_path="configs/minimal.yaml"

INSTRUCTION="${1:-读取 report.txt}"
BASE_URL="${2:-http://127.0.0.1:8000}"
CONFIG_PATH="${3:-configs/minimal.yaml}"

echo "Initializing session from ${CONFIG_PATH} against ${BASE_URL} ..."
SESSION_ID=$(uv run python scripts/init_from_config.py --config "${CONFIG_PATH}" --base-url "${BASE_URL}" | awk '{print $3}')
echo "Session initialized: ${SESSION_ID}"

cleanup() {
  echo "Cleaning up session ${SESSION_ID} ..."
  curl -s -X DELETE "${BASE_URL}/v1/environment/${SESSION_ID}" >/dev/null || true
}
trap cleanup EXIT

echo "Running step with instruction: ${INSTRUCTION}"
curl -s -X POST "${BASE_URL}/v1/environment/run_step" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"${SESSION_ID}\",\"user_instruction\":\"${INSTRUCTION}\"}" | jq .

echo "Done."
