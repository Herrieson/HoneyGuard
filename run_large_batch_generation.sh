#!/usr/bin/env bash
set -euo pipefail

# HoneyGuard 大规模攻击场景批量生成入口脚本。
# 封装 scripts/generate_attack_batch.sh，提供：
# - 常用默认参数（CIA v2）
# - API 环境变量检查
# - 规模预估与运行摘要

usage() {
  cat <<'USAGE'
Usage:
  ./run_large_batch_generation.sh [options]

Options:
  --batch-name NAME            批次名（默认: large_cia_v2_YYYYmmdd_HHMMSS）
  --domains PRESET             domain preset: matrix_v1 | core | comprehensive (默认: matrix_v1)
  --domain-file PATH           自定义 domain 文件（每行: domain_id|domain_context）
  --styles CSV                 风格列表（默认: CIA v2 六风格）
  --samples-per-combo N        每个 (domain, style) 采样数（默认: 5）
  --max-domains N              限制 domain 数（默认: 0=不限制）
  --matrix-version N           矩阵版本（默认: 2）
  --provider PROVIDER          azure | openai（默认: azure）
  --model MODEL                模型/部署名（默认: gpt-4o）
  --temperature FLOAT          采样温度（默认: 0.2）
  --acceptance-logic MODE      auto | any | all（默认: auto）
  --max-assets N               每场景目标资产上限（默认: 4）
  --no-llm-plan                关闭 LLM 规划（更快、更便宜）
  --skip-lint                  跳过配置 lint（更快，质量校验更弱）
  --stop-on-error              出错即停（默认: continue-on-error）
  --dry-run                    仅打印命令和规模估算，不执行
  -h, --help                   显示帮助

Examples:
  ./run_large_batch_generation.sh

  ./run_large_batch_generation.sh \
    --batch-name paper_cia_v2_n5 \
    --samples-per-combo 5 \
    --provider azure \
    --model gpt-4o

  ./run_large_batch_generation.sh \
    --domains core \
    --max-domains 2 \
    --samples-per-combo 1 \
    --no-llm-plan \
    --stop-on-error
USAGE
}

default_batch_name() {
  date +"large_cia_v2_%Y%m%d_%H%M%S"
}

# Defaults
BATCH_NAME="$(default_batch_name)"
DOMAINS="matrix_v1"
DOMAIN_FILE=""
STYLES="c_secret_harvest,c_bulk_exfiltration,i_config_tamper,i_code_backdoor,a_resource_exhaustion,a_workflow_disruption"
SAMPLES_PER_COMBO=5
MAX_DOMAINS=0
MATRIX_VERSION=2
PROVIDER="azure"
MODEL="gpt-4o"
TEMPERATURE="0.2"
ACCEPTANCE_LOGIC="auto"
MAX_ASSETS=4
USE_LLM_PLAN=1
SKIP_LINT=0
CONTINUE_ON_ERROR=1
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --batch-name)
      BATCH_NAME="${2:-}"
      shift 2
      ;;
    --domains)
      DOMAINS="${2:-}"
      shift 2
      ;;
    --domain-file)
      DOMAIN_FILE="${2:-}"
      shift 2
      ;;
    --styles)
      STYLES="${2:-}"
      shift 2
      ;;
    --samples-per-combo)
      SAMPLES_PER_COMBO="${2:-}"
      shift 2
      ;;
    --max-domains)
      MAX_DOMAINS="${2:-}"
      shift 2
      ;;
    --matrix-version)
      MATRIX_VERSION="${2:-}"
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
    --temperature)
      TEMPERATURE="${2:-}"
      shift 2
      ;;
    --acceptance-logic)
      ACCEPTANCE_LOGIC="${2:-}"
      shift 2
      ;;
    --max-assets)
      MAX_ASSETS="${2:-}"
      shift 2
      ;;
    --no-llm-plan)
      USE_LLM_PLAN=0
      shift
      ;;
    --skip-lint)
      SKIP_LINT=1
      shift
      ;;
    --stop-on-error)
      CONTINUE_ON_ERROR=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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

if ! [[ "${SAMPLES_PER_COMBO}" =~ ^[0-9]+$ ]] || [[ "${SAMPLES_PER_COMBO}" -lt 1 ]]; then
  echo "Error: --samples-per-combo must be integer >= 1" >&2
  exit 1
fi
if ! [[ "${MAX_DOMAINS}" =~ ^[0-9]+$ ]] || [[ "${MAX_DOMAINS}" -lt 0 ]]; then
  echo "Error: --max-domains must be integer >= 0" >&2
  exit 1
fi
if ! [[ "${MATRIX_VERSION}" =~ ^[0-9]+$ ]] || [[ "${MATRIX_VERSION}" -lt 1 ]]; then
  echo "Error: --matrix-version must be integer >= 1" >&2
  exit 1
fi
if ! [[ "${MAX_ASSETS}" =~ ^[0-9]+$ ]] || [[ "${MAX_ASSETS}" -lt 1 ]]; then
  echo "Error: --max-assets must be integer >= 1" >&2
  exit 1
fi
if [[ "${PROVIDER}" != "azure" && "${PROVIDER}" != "openai" ]]; then
  echo "Error: --provider must be azure|openai" >&2
  exit 1
fi
if [[ "${ACCEPTANCE_LOGIC}" != "auto" && "${ACCEPTANCE_LOGIC}" != "any" && "${ACCEPTANCE_LOGIC}" != "all" ]]; then
  echo "Error: --acceptance-logic must be auto|any|all" >&2
  exit 1
fi

if [[ ! -x "scripts/generate_attack_batch.sh" ]]; then
  echo "Error: scripts/generate_attack_batch.sh not found or not executable" >&2
  exit 1
fi

if [[ "${DRY_RUN}" -eq 0 ]]; then
  if [[ "${PROVIDER}" == "azure" ]]; then
    missing=0
    for key in AZURE_OPENAI_API_KEY AZURE_OPENAI_ENDPOINT AZURE_OPENAI_API_VERSION; do
      if [[ -z "${!key:-}" ]]; then
        echo "Error: missing env ${key}" >&2
        missing=1
      fi
    done
    if [[ -z "${AZURE_OPENAI_DEPLOYMENT:-}" ]]; then
      echo "[warn] AZURE_OPENAI_DEPLOYMENT not set; will use --model ${MODEL}" >&2
    fi
    if [[ "${missing}" -ne 0 ]]; then
      exit 1
    fi
  fi

  if [[ "${PROVIDER}" == "openai" ]]; then
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
      echo "Error: missing env OPENAI_API_KEY" >&2
      exit 1
    fi
  fi
fi

count_domains() {
  local n=0
  if [[ -n "${DOMAIN_FILE}" ]]; then
    if [[ ! -f "${DOMAIN_FILE}" ]]; then
      echo "Error: --domain-file not found: ${DOMAIN_FILE}" >&2
      exit 1
    fi
    n="$(grep -v '^[[:space:]]*$' "${DOMAIN_FILE}" | grep -v '^[[:space:]]*#' | wc -l | tr -d ' ')"
  else
    case "${DOMAINS}" in
      core)
        n=4
        ;;
      comprehensive|matrix_v1)
        if [[ -f "configs/matrix/domain_matrix_v1.txt" ]]; then
          n="$(grep -v '^[[:space:]]*$' configs/matrix/domain_matrix_v1.txt | grep -v '^[[:space:]]*#' | wc -l | tr -d ' ')"
        else
          echo "Error: configs/matrix/domain_matrix_v1.txt not found" >&2
          exit 1
        fi
        ;;
      *)
        echo "Error: unsupported --domains preset: ${DOMAINS}" >&2
        exit 1
        ;;
    esac
  fi

  if [[ "${MAX_DOMAINS}" -gt 0 && "${MAX_DOMAINS}" -lt "${n}" ]]; then
    n="${MAX_DOMAINS}"
  fi
  echo "${n}"
}

count_styles() {
  awk -F',' '{print NF}' <<<"${STYLES}"
}

DOMAIN_COUNT="$(count_domains)"
STYLE_COUNT="$(count_styles)"
TOTAL=$(( DOMAIN_COUNT * STYLE_COUNT * SAMPLES_PER_COMBO ))

echo "[plan] batch_name=${BATCH_NAME}"
echo "[plan] domains=${DOMAIN_COUNT}, styles=${STYLE_COUNT}, n=${SAMPLES_PER_COMBO}"
echo "[plan] estimated_total_scenarios=${TOTAL}"
echo "[plan] provider=${PROVIDER}, model=${MODEL}, matrix_version=${MATRIX_VERSION}"

CMD=(
  bash scripts/generate_attack_batch.sh
  --batch-name "${BATCH_NAME}"
  --domains "${DOMAINS}"
  --styles "${STYLES}"
  --samples-per-combo "${SAMPLES_PER_COMBO}"
  --max-domains "${MAX_DOMAINS}"
  --matrix-version "${MATRIX_VERSION}"
  --provider "${PROVIDER}"
  --model "${MODEL}"
  --temperature "${TEMPERATURE}"
  --acceptance-logic "${ACCEPTANCE_LOGIC}"
  --max-assets "${MAX_ASSETS}"
)

if [[ -n "${DOMAIN_FILE}" ]]; then
  CMD+=(--domain-file "${DOMAIN_FILE}")
fi
if [[ "${USE_LLM_PLAN}" -eq 0 ]]; then
  CMD+=(--no-llm-plan)
fi
if [[ "${SKIP_LINT}" -eq 1 ]]; then
  CMD+=(--skip-lint)
fi
if [[ "${CONTINUE_ON_ERROR}" -eq 0 ]]; then
  CMD+=(--stop-on-error)
else
  CMD+=(--continue-on-error)
fi

printf '[cmd] '
printf '%q ' "${CMD[@]}"
printf '\n'

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[dry-run] no execution"
  exit 0
fi

"${CMD[@]}"

echo "[done] summary -> logs/batch_generation/${BATCH_NAME}_summary.json"
echo "[done] details -> logs/batch_generation/${BATCH_NAME}_details.jsonl"
