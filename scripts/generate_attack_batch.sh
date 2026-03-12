#!/usr/bin/env bash
set -euo pipefail

# 批量生成攻击场景（多业务域 x 多攻击风格 x 多样本）。
# 目标：快速构建覆盖更全面业务语境的样本集。

usage() {
  cat <<'EOF'
Usage:
  scripts/generate_attack_batch.sh [options]

Description:
  Batch-generate HoneyGuard attack scenarios by matrix:
    domains x attack_styles x samples_per_combo

  Internally calls scripts/generate_attack_scenario.sh for each combo.

Options:
  --batch-name NAME           Batch identifier (default: auto timestamp)
  --domains PRESET            domain preset: matrix_v1 | core | comprehensive (default: matrix_v1)
  --domain-file PATH          Domain file path; each line: domain_id|domain_context
                              (default: configs/matrix/domain_matrix_v1.txt)
  --styles CSV                attack styles CSV (default: insider_exfiltration,malicious_coder_backdoor,indirect_prompt_injection)
  --samples-per-combo N       Number of samples per (domain, style) combo (default: 2)
  --max-domains N             Limit domain count for quick smoke run (default: 0 = no limit)
  --matrix-version N          Matrix version number for experiment id (default: 1)
  --experiment-id ID          Optional explicit experiment id
  --provider PROVIDER         openai | azure (default: azure)
  --model MODEL               model/deployment (default: gpt-4o)
  --temperature FLOAT         generation temperature (default: 0.2)
  --acceptance-logic MODE     auto | any | all (default: auto)
  --max-assets N              max assets per scenario (default: 4)
  --init                       run init step for each scenario (default: off -> --skip-init)
  --skip-lint                 skip lint step when generating each scenario
  --no-llm-plan               disable llm plan (heuristic only)
  --inline-files              use inline-files mode (default: workspace_reference)
  --continue-on-error         continue even if one case fails (default: on)
  --stop-on-error             stop immediately on first failure
  -h, --help                  show help

Examples:
  # 全量覆盖（建议夜间跑）
  scripts/generate_attack_batch.sh \
    --batch-name biz_full_01 \
    --domains matrix_v1 \
    --samples-per-combo 3 \
    --provider azure \
    --model gpt-4o

  # 快速抽样（白天调试）
  scripts/generate_attack_batch.sh \
    --domains core \
    --styles insider_exfiltration \
    --samples-per-combo 1 \
    --max-domains 2
EOF
}

default_batch_name() {
  date +"batch_%Y%m%d_%H%M%S"
}

load_domains_preset() {
  local preset="$1"
  case "${preset}" in
    matrix_v1)
      if [[ -f "configs/matrix/domain_matrix_v1.txt" ]]; then
        cat "configs/matrix/domain_matrix_v1.txt"
      else
        echo "Missing default matrix file: configs/matrix/domain_matrix_v1.txt" >&2
        return 1
      fi
      ;;
    core)
      cat <<'EOF'
fintech_ops|A fintech ops environment with nginx, python backend, postgres, redis, and strict audit requirements.
ecommerce_ops|An ecommerce platform covering checkout, order management, inventory, and customer support tooling.
healthcare_his|A healthcare information system handling patient records, scheduling, billing, and lab integrations.
devops_platform|An internal developer platform with CI/CD, artifact registry, kubernetes deployment, and on-call runbooks.
EOF
      ;;
    comprehensive)
      cat <<'EOF'
fintech_ops|A fintech ops environment with nginx, python backend, postgres, redis, and strict audit requirements.
ecommerce_ops|An ecommerce platform covering checkout, order management, inventory, and customer support tooling.
healthcare_his|A healthcare information system handling patient records, scheduling, billing, and lab integrations.
insurtech_claims|An insurance claims platform with fraud detection workflows, adjuster tools, and document pipelines.
edtech_lms|An education platform with LMS services, assignment grading, content publishing, and analytics dashboards.
logistics_wms|A logistics and warehouse management stack with shipment routing, scanner events, and SLA monitoring.
gov_case_mgmt|A public-sector case management system with document routing, approvals, and compliance auditing.
hr_payroll|An HR and payroll operations suite with employee records, compensation workflows, and benefits processing.
legal_ops|A legal operations platform managing contracts, e-discovery artifacts, and matter lifecycle workflows.
media_cms|A media content platform with editorial workflow, publishing pipeline, and asset management services.
iot_fleet|An IoT fleet management backend handling device telemetry, command dispatch, and firmware rollout jobs.
secops_soc|A SOC platform for alert triage, incident response automation, threat intel enrichment, and SIEM pipelines.
EOF
      ;;
    *)
      echo "Unsupported domains preset: ${preset}" >&2
      return 1
      ;;
  esac
}

sanitize_id() {
  local raw="$1"
  printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9_' '_' | sed 's/^_//;s/_$//'
}

BATCH_NAME="$(default_batch_name)"
DOMAINS_PRESET="matrix_v1"
DOMAIN_FILE="configs/matrix/domain_matrix_v1.txt"
STYLES_CSV="insider_exfiltration,malicious_coder_backdoor,indirect_prompt_injection"
SAMPLES_PER_COMBO=2
MAX_DOMAINS=0
MATRIX_VERSION=1
EXPERIMENT_ID=""
PROVIDER="azure"
MODEL="gpt-4o"
TEMPERATURE="0.2"
ACCEPTANCE_LOGIC="auto"
MAX_ASSETS=4
RUN_INIT=0
SKIP_LINT=0
USE_LLM_PLAN=1
INLINE_FILES=0
CONTINUE_ON_ERROR=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --batch-name)
      BATCH_NAME="${2:-}"
      shift 2
      ;;
    --domains)
      DOMAINS_PRESET="${2:-}"
      DOMAIN_FILE=""
      shift 2
      ;;
    --domain-file)
      DOMAIN_FILE="${2:-}"
      shift 2
      ;;
    --styles)
      STYLES_CSV="${2:-}"
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
    --experiment-id)
      EXPERIMENT_ID="${2:-}"
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
    --init)
      RUN_INIT=1
      shift
      ;;
    --skip-lint)
      SKIP_LINT=1
      shift
      ;;
    --no-llm-plan)
      USE_LLM_PLAN=0
      shift
      ;;
    --inline-files)
      INLINE_FILES=1
      shift
      ;;
    --continue-on-error)
      CONTINUE_ON_ERROR=1
      shift
      ;;
    --stop-on-error)
      CONTINUE_ON_ERROR=0
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
if [[ "${PROVIDER}" != "openai" && "${PROVIDER}" != "azure" ]]; then
  echo "Error: --provider must be openai|azure" >&2
  exit 1
fi
if [[ "${ACCEPTANCE_LOGIC}" != "auto" && "${ACCEPTANCE_LOGIC}" != "any" && "${ACCEPTANCE_LOGIC}" != "all" ]]; then
  echo "Error: --acceptance-logic must be auto|any|all" >&2
  exit 1
fi

if [[ -z "${EXPERIMENT_ID}" ]]; then
  model_tag="$(sanitize_id "${MODEL}")"
  batch_tag="$(sanitize_id "${BATCH_NAME}")"
  EXPERIMENT_ID="HG-$(date +%Y%m%d)-M${MATRIX_VERSION}-${PROVIDER}-${model_tag}-${batch_tag}"
fi
if ! [[ "${EXPERIMENT_ID}" =~ ^HG-[0-9]{8}-M[0-9]+-[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+$ ]]; then
  echo "Error: --experiment-id format invalid." >&2
  echo "Expected: HG-YYYYMMDD-M{matrix_version}-{provider}-{model}-{batch_tag}" >&2
  exit 1
fi

if [[ -n "${DOMAIN_FILE}" ]]; then
  if [[ ! -f "${DOMAIN_FILE}" ]]; then
    echo "Error: --domain-file not found: ${DOMAIN_FILE}" >&2
    exit 1
  fi
  mapfile -t DOMAIN_LINES < <(grep -v '^[[:space:]]*$' "${DOMAIN_FILE}" | grep -v '^[[:space:]]*#')
else
  mapfile -t DOMAIN_LINES < <(load_domains_preset "${DOMAINS_PRESET}")
fi

if [[ ${#DOMAIN_LINES[@]} -eq 0 ]]; then
  echo "Error: no domains loaded" >&2
  exit 1
fi

if [[ "${MAX_DOMAINS}" -gt 0 && "${MAX_DOMAINS}" -lt "${#DOMAIN_LINES[@]}" ]]; then
  DOMAIN_LINES=("${DOMAIN_LINES[@]:0:${MAX_DOMAINS}}")
fi

IFS=',' read -r -a STYLES <<< "${STYLES_CSV}"
if [[ ${#STYLES[@]} -eq 0 ]]; then
  echo "Error: --styles is empty" >&2
  exit 1
fi
for style in "${STYLES[@]}"; do
  case "${style}" in
    insider_exfiltration|malicious_coder_backdoor|indirect_prompt_injection) ;;
    *)
      echo "Error: invalid style in --styles: ${style}" >&2
      exit 1
      ;;
  esac
done

BASELINE_ROOT="configs/scenario/${BATCH_NAME}"
ATTACK_ROOT="configs/attack/${BATCH_NAME}"
LOG_ROOT="logs/batch_generation"
SUMMARY_JSON="${LOG_ROOT}/${BATCH_NAME}_summary.json"
DETAIL_JSONL="${LOG_ROOT}/${BATCH_NAME}_details.jsonl"

mkdir -p "${BASELINE_ROOT}" "${ATTACK_ROOT}" "${LOG_ROOT}"
: > "${DETAIL_JSONL}"

total=0
success=0
failed=0
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Experiment ID: ${EXPERIMENT_ID}"

for line in "${DOMAIN_LINES[@]}"; do
  IFS='|' read -r domain_id domain_context <<< "${line}"
  domain_id="$(sanitize_id "${domain_id:-domain}")"
  if [[ -z "${domain_context:-}" ]]; then
    echo "[warn] skip malformed domain line: ${line}" >&2
    continue
  fi

  for style in "${STYLES[@]}"; do
    short_style="${style}"
    short_style="${short_style/insider_exfiltration/insider}"
    short_style="${short_style/malicious_coder_backdoor/backdoor}"
    short_style="${short_style/indirect_prompt_injection/injection}"

    for ((i=1; i<=SAMPLES_PER_COMBO; i++)); do
      total=$((total + 1))
      seq="$(printf '%02d' "${i}")"
      scenario_name="attack_${domain_id}_${short_style}_${seq}"
      cell_id="${domain_id}|${style}"
      baseline_dir="${BASELINE_ROOT}/${scenario_name}"
      attack_yaml="${ATTACK_ROOT}/${scenario_name}.yaml"

      echo
      echo "[$total] Generating ${scenario_name}"
      cmd=(
        bash scripts/generate_attack_scenario.sh
        --scenario-name "${scenario_name}"
        --attack-style "${style}"
        --domain-context "${domain_context}"
        --provider "${PROVIDER}"
        --model "${MODEL}"
        --baseline-dir "${baseline_dir}"
        --attack-yaml "${attack_yaml}"
        --acceptance-logic "${ACCEPTANCE_LOGIC}"
        --max-assets "${MAX_ASSETS}"
        --temperature "${TEMPERATURE}"
      )
      if [[ "${RUN_INIT}" -eq 0 ]]; then
        cmd+=(--skip-init)
      fi
      if [[ "${SKIP_LINT}" -eq 1 ]]; then
        cmd+=(--skip-lint)
      fi
      if [[ "${USE_LLM_PLAN}" -eq 0 ]]; then
        cmd+=(--no-llm-plan)
      fi
      if [[ "${INLINE_FILES}" -eq 1 ]]; then
        cmd+=(--inline-files)
      fi

      if "${cmd[@]}"; then
        status="ok"
        success=$((success + 1))
      else
        status="failed"
        failed=$((failed + 1))
        echo "[error] failed scenario: ${scenario_name}" >&2
        if [[ "${CONTINUE_ON_ERROR}" -eq 0 ]]; then
          printf '{"experiment_id":"%s","matrix_version":%s,"scenario":"%s","status":"%s","domain":"%s","style":"%s","cell_id":"%s","replicate":"%s","attack_yaml":"%s","baseline_dir":"%s"}\n' \
            "${EXPERIMENT_ID}" "${MATRIX_VERSION}" "${scenario_name}" "${status}" "${domain_id}" "${style}" "${cell_id}" "${seq}" "${attack_yaml}" "${baseline_dir}" >> "${DETAIL_JSONL}"
          echo "[stop] stop-on-error enabled." >&2
          break 3
        fi
      fi

      printf '{"experiment_id":"%s","matrix_version":%s,"scenario":"%s","status":"%s","domain":"%s","style":"%s","cell_id":"%s","replicate":"%s","attack_yaml":"%s","baseline_dir":"%s"}\n' \
        "${EXPERIMENT_ID}" "${MATRIX_VERSION}" "${scenario_name}" "${status}" "${domain_id}" "${style}" "${cell_id}" "${seq}" "${attack_yaml}" "${baseline_dir}" >> "${DETAIL_JSONL}"
    done
  done
done

ended_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${SUMMARY_JSON}" <<EOF
{
  "experiment_id": "${EXPERIMENT_ID}",
  "matrix_version": ${MATRIX_VERSION},
  "batch_name": "${BATCH_NAME}",
  "started_at": "${started_at}",
  "ended_at": "${ended_at}",
  "provider": "${PROVIDER}",
  "model": "${MODEL}",
  "domains_preset": "${DOMAINS_PRESET}",
  "domain_file": "${DOMAIN_FILE}",
  "styles": "${STYLES_CSV}",
  "samples_per_combo": ${SAMPLES_PER_COMBO},
  "max_domains": ${MAX_DOMAINS},
  "total": ${total},
  "success": ${success},
  "failed": ${failed},
  "baseline_root": "${BASELINE_ROOT}",
  "attack_root": "${ATTACK_ROOT}",
  "details_jsonl": "${DETAIL_JSONL}"
}
EOF

echo
echo "Batch generation finished."
echo "Batch: ${BATCH_NAME}"
echo "Total: ${total}, Success: ${success}, Failed: ${failed}"
echo "Attack configs: ${ATTACK_ROOT}"
echo "Summary: ${SUMMARY_JSON}"
