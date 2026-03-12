#!/usr/bin/env bash
set -euo pipefail

# 一键攻击场景流水线脚本。
# 步骤:
# 1) 生成 baseline 环境 (env_builder.py)
# 2) 基于 baseline 生成攻击配置 (build_attack_config.py)
# 3) 对攻击配置做质量检查 (attack_config_lint.py)
# 4) 可选调用 API 初始化会话 (init_from_config.py)
#
# 适合“从 domain context 到可运行攻击场景”的快速自动化。

usage() {
  cat <<'EOF'
Usage:
  scripts/generate_attack_scenario.sh [options]

Description:
  Build a full HoneyGuard attack scenario in 4 steps:
  1) Generate baseline workspace via env_builder.py
  2) Generate attack config YAML via build_attack_config.py
     (default outputs workspace reference + files_overrides, not huge inline files)
     (acceptance_template defaults to five_metric_v1: 5 categories)
  3) Lint attack config quality via attack_config_lint.py
  4) Optionally initialize session via init_from_config.py

Options:
  --scenario-name NAME        Scenario name (default: attack_auto_insider_01)
  --attack-style STYLE        insider_exfiltration | malicious_coder_backdoor | indirect_prompt_injection
                              (default: insider_exfiltration)
  --domain-context TEXT       Domain context for environment generation (required)
  --provider PROVIDER         openai | azure (default: azure)
  --model MODEL               Model/deployment name (default: gpt-4o)
  --base-url URL              HoneyGuard API base URL (default: http://127.0.0.1:8000)
  --baseline-dir DIR          Baseline output directory
                              (default: configs/scenario/baseline_auto_01)
  --attack-yaml PATH          Attack yaml output path
                              (default: configs/attack/<scenario-name>.yaml)
  --baseline-max-files N      Max baseline files carried into attack config (default: 24)
                              (mainly used with --inline-files legacy mode)
  --acceptance-logic MODE     auto | any | all (default: auto)
                              auto: insider/prompt=any, backdoor=all
  --max-assets N              Max target assets in attack plan (default: 4)
  --temperature FLOAT         LLM sampling temperature for both generators (default: 0.2)
  --inline-files              Legacy mode: inline baseline files into YAML
  --no-llm-plan               Disable --use-llm for build_attack_config.py (heuristic only)
  --skip-lint                 Skip attack config lint step
  --skip-init                 Skip init_from_config.py step
  -h, --help                  Show help

Examples:
  scripts/generate_attack_scenario.sh \
    --scenario-name attack_auto_insider_01 \
    --attack-style insider_exfiltration \
    --domain-context "A fintech ops environment with nginx, python backend, postgres, redis."

  scripts/generate_attack_scenario.sh \
    --scenario-name attack_auto_backdoor_01 \
    --attack-style malicious_coder_backdoor \
    --provider openai \
    --model gpt-4o \
    --domain-context "A SaaS coding assistant environment." \
    --skip-init
EOF
}

SCENARIO_NAME="attack_auto_insider_01"
ATTACK_STYLE="insider_exfiltration"
DOMAIN_CONTEXT=""
PROVIDER="azure"
MODEL="gpt-4o"
BASE_URL="http://127.0.0.1:8000"
BASELINE_DIR="configs/scenario/baseline_auto_01"
ATTACK_YAML=""
BASELINE_MAX_FILES=24
MAX_ASSETS=4
ACCEPTANCE_LOGIC="auto"
TEMPERATURE="0.2"
USE_LLM_PLAN=1
SKIP_INIT=0
SKIP_LINT=0
INLINE_FILES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario-name)
      SCENARIO_NAME="${2:-}"
      shift 2
      ;;
    --attack-style)
      ATTACK_STYLE="${2:-}"
      shift 2
      ;;
    --domain-context)
      DOMAIN_CONTEXT="${2:-}"
      shift 2
      ;;
    --provider)
      PROVIDER="${2:-}"
      shift 2
      ;;
    --model)
      MODEL="${2:-}"
      shift 2
      ;;
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --baseline-dir)
      BASELINE_DIR="${2:-}"
      shift 2
      ;;
    --attack-yaml)
      ATTACK_YAML="${2:-}"
      shift 2
      ;;
    --baseline-max-files)
      BASELINE_MAX_FILES="${2:-}"
      shift 2
      ;;
    --max-assets)
      MAX_ASSETS="${2:-}"
      shift 2
      ;;
    --acceptance-logic)
      ACCEPTANCE_LOGIC="${2:-}"
      shift 2
      ;;
    --temperature)
      TEMPERATURE="${2:-}"
      shift 2
      ;;
    --inline-files)
      INLINE_FILES=1
      shift
      ;;
    --no-llm-plan)
      USE_LLM_PLAN=0
      shift
      ;;
    --skip-init)
      SKIP_INIT=1
      shift
      ;;
    --skip-lint)
      SKIP_LINT=1
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

if [[ -z "${DOMAIN_CONTEXT}" ]]; then
  echo "Error: --domain-context is required." >&2
  usage
  exit 1
fi

if [[ -z "${ATTACK_YAML}" ]]; then
  ATTACK_YAML="configs/attack/${SCENARIO_NAME}.yaml"
fi

if [[ "${ATTACK_STYLE}" != "insider_exfiltration" && "${ATTACK_STYLE}" != "malicious_coder_backdoor" && "${ATTACK_STYLE}" != "indirect_prompt_injection" ]]; then
  echo "Error: --attack-style must be one of insider_exfiltration|malicious_coder_backdoor|indirect_prompt_injection." >&2
  exit 1
fi

if [[ "${PROVIDER}" != "openai" && "${PROVIDER}" != "azure" ]]; then
  echo "Error: --provider must be openai|azure." >&2
  exit 1
fi
if [[ "${ACCEPTANCE_LOGIC}" != "auto" && "${ACCEPTANCE_LOGIC}" != "any" && "${ACCEPTANCE_LOGIC}" != "all" ]]; then
  echo "Error: --acceptance-logic must be auto|any|all." >&2
  exit 1
fi

echo "[1/4] Building baseline workspace: ${BASELINE_DIR}"
uv run python scripts/env_builder.py \
  --provider "${PROVIDER}" \
  --model "${MODEL}" \
  --domain-context "${DOMAIN_CONTEXT}" \
  --output-dir "${BASELINE_DIR}" \
  --temperature "${TEMPERATURE}"

echo "[2/4] Building attack config: ${ATTACK_YAML}"
ATTACK_CMD=(
  uv run python scripts/build_attack_config.py
  --scenario-name "${SCENARIO_NAME}"
  --attack-style "${ATTACK_STYLE}"
  --domain-context "${DOMAIN_CONTEXT}"
  --baseline-manifest "${BASELINE_DIR}/_manifest.json"
  --baseline-dir "${BASELINE_DIR}"
  --baseline-max-files "${BASELINE_MAX_FILES}"
  --acceptance-logic "${ACCEPTANCE_LOGIC}"
  --max-assets "${MAX_ASSETS}"
  --provider "${PROVIDER}"
  --model "${MODEL}"
  --temperature "${TEMPERATURE}"
  --output "${ATTACK_YAML}"
)

if [[ "${USE_LLM_PLAN}" -eq 1 ]]; then
  ATTACK_CMD+=(--use-llm)
fi
if [[ "${INLINE_FILES}" -eq 1 ]]; then
  ATTACK_CMD+=(--inline-files)
fi

"${ATTACK_CMD[@]}"

if [[ "${SKIP_LINT}" -eq 0 ]]; then
  echo "[3/4] Linting attack config quality rules"
  uv run python scripts/attack_config_lint.py --config "${ATTACK_YAML}"
else
  echo "[3/4] Skipped lint step (--skip-lint)"
fi

if [[ "${SKIP_INIT}" -eq 0 ]]; then
  echo "[4/4] Initializing HoneyGuard session via API: ${BASE_URL}"
  uv run python scripts/init_from_config.py \
    --config "${ATTACK_YAML}" \
    --base-url "${BASE_URL}"
else
  echo "[4/4] Skipped init step (--skip-init)"
fi

echo "Done."
echo "Baseline: ${BASELINE_DIR}"
echo "Attack YAML: ${ATTACK_YAML}"
