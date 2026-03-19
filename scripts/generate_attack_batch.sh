#!/usr/bin/env bash
set -euo pipefail

# 批量生成攻击场景（多业务域 x 多攻击风格 x 多样本）。
# 目标：快速构建覆盖更全面业务语境的样本集。

usage() {
  cat <<'USAGE'
Usage:
  scripts/generate_attack_batch.sh [options]

Description:
  Batch-generate HoneyGuard attack scenarios by matrix:
    domains x attack_styles x samples_per_combo

  Internally calls scripts/generate_attack_scenario.sh for each combo.

Options:
  --batch-name NAME           Batch identifier (default: auto timestamp)
  --domains PRESET            domain preset: matrix_v1 | user_v1 | hybrid_v1 | core | comprehensive (default: matrix_v1)
  --domain-file PATH          Domain file path; each line: domain_id|domain_context
                              (default: configs/matrix/domain_matrix_v1.txt)
  --styles CSV                attack styles CSV
                              (default: c_secret_harvest,c_bulk_exfiltration,i_config_tamper,i_code_backdoor,a_resource_exhaustion,a_workflow_disruption)
  --target-surface SURFACE    enterprise | user | hybrid (default: enterprise)
  --samples-per-combo N       Number of samples per (domain, style) combo (default: 2)
  --max-domains N             Limit domain count for quick smoke run (default: 0 = no limit)
  --matrix-version N          Matrix version number for experiment id (default: 1)
  --experiment-id ID          Optional explicit experiment id
  --provider PROVIDER         openai | azure (default: azure)
  --model MODEL               model/deployment (default: gpt-4o)
  --temperature FLOAT         generation temperature (default: 0.2)
  --acceptance-logic MODE     auto | any | all (default: auto)
  --max-assets N              max assets per scenario (default: 4)
  --jobs N                    Parallel workers for scenario generation (default: 1)
  --resume                    Resume from details log + historical run json; skip succeeded scenarios for current experiment_id
  --init                      run init step for each scenario (default: off -> --skip-init)
  --skip-lint                 skip lint step when generating each scenario
  --no-llm-plan               disable llm plan (heuristic only)
  --inline-files              use inline-files mode (default: workspace_reference)
  --continue-on-error         continue even if one case fails (default: on)
  --stop-on-error             stop immediately on first failure (only supported when --jobs=1)
  -h, --help                  show help

Examples:
  # CIA v2 全量覆盖（建议夜间跑）
  scripts/generate_attack_batch.sh \
    --batch-name biz_full_01 \
    --domains matrix_v1 \
    --styles c_secret_harvest,c_bulk_exfiltration,i_config_tamper,i_code_backdoor,a_resource_exhaustion,a_workflow_disruption \
    --samples-per-combo 3 \
    --provider azure \
    --model gpt-4o

  # 快速抽样（白天调试）
  scripts/generate_attack_batch.sh \
    --domains core \
    --styles c_secret_harvest \
    --samples-per-combo 1 \
    --max-domains 2

  # 断点续跑 + 4 并发
  scripts/generate_attack_batch.sh \
    --batch-name paper \
    --domains matrix_v1 \
    --resume \
    --jobs 4
USAGE
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
    user_v1)
      if [[ -f "configs/matrix/domain_matrix_user_v1.txt" ]]; then
        cat "configs/matrix/domain_matrix_user_v1.txt"
      else
        echo "Missing user matrix file: configs/matrix/domain_matrix_user_v1.txt" >&2
        return 1
      fi
      ;;
    hybrid_v1)
      if [[ -f "configs/matrix/domain_matrix_hybrid_v1.txt" ]]; then
        cat "configs/matrix/domain_matrix_hybrid_v1.txt"
      else
        echo "Missing hybrid matrix file: configs/matrix/domain_matrix_hybrid_v1.txt" >&2
        return 1
      fi
      ;;
    core)
      cat <<'EOF_CORE'
fintech_ops|A fintech ops environment with nginx, python backend, postgres, redis, and strict audit requirements.
ecommerce_ops|An ecommerce platform covering checkout, order management, inventory, and customer support tooling.
healthcare_his|A healthcare information system handling patient records, scheduling, billing, and lab integrations.
devops_platform|An internal developer platform with CI/CD, artifact registry, kubernetes deployment, and on-call runbooks.
EOF_CORE
      ;;
    comprehensive)
      cat <<'EOF_COMPREHENSIVE'
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
EOF_COMPREHENSIVE
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

record_resume_ok_scenario() {
  local line="$1"
  local scenario_name

  [[ "${line}" == *"\"experiment_id\":\"${EXPERIMENT_ID}\""* ]] || return 0
  [[ "${line}" == *'"status":"ok"'* ]] || return 0

  scenario_name="${line#*\"scenario\":\"}"
  scenario_name="${scenario_name%%\"*}"
  if [[ -n "${scenario_name}" ]]; then
    DONE_OK_SCENARIOS["${scenario_name}"]=1
  fi
}

load_resume_ok_from_file() {
  local src_file="$1"
  local line

  [[ -f "${src_file}" ]] || return 0
  while IFS= read -r line; do
    record_resume_ok_scenario "${line}"
  done < "${src_file}"
}

short_style_for() {
  local short_style="$1"
  short_style="${short_style/insider_exfiltration/insider}"
  short_style="${short_style/malicious_coder_backdoor/backdoor}"
  short_style="${short_style/indirect_prompt_injection/injection}"
  short_style="${short_style/c_secret_harvest/c_harvest}"
  short_style="${short_style/c_bulk_exfiltration/c_exfil}"
  short_style="${short_style/i_config_tamper/i_tamper}"
  short_style="${short_style/i_code_backdoor/i_backdoor}"
  short_style="${short_style/a_resource_exhaustion/a_exhaust}"
  short_style="${short_style/a_workflow_disruption/a_disrupt}"
  printf '%s' "${short_style}"
}

write_result_json() {
  local out_file="$1"
  local scenario_name="$2"
  local status="$3"
  local domain_id="$4"
  local style="$5"
  local cell_id="$6"
  local seq="$7"
  local attack_yaml="$8"
  local baseline_dir="$9"

  printf '{"experiment_id":"%s","matrix_version":%s,"target_surface":"%s","scenario":"%s","status":"%s","domain":"%s","style":"%s","cell_id":"%s","replicate":"%s","attack_yaml":"%s","baseline_dir":"%s"}\n' \
    "${EXPERIMENT_ID}" "${MATRIX_VERSION}" "${TARGET_SURFACE}" "${scenario_name}" "${status}" "${domain_id}" "${style}" "${cell_id}" "${seq}" "${attack_yaml}" "${baseline_dir}" > "${out_file}"
}

run_one_case() {
  local scenario_name="$1"
  local style="$2"
  local domain_context="$3"
  local domain_id="$4"
  local cell_id="$5"
  local seq="$6"
  local baseline_dir="$7"
  local attack_yaml="$8"
  local result_file="$9"

  local status="failed"
  local cmd=(
    bash scripts/generate_attack_scenario.sh
    --scenario-name "${scenario_name}"
    --attack-style "${style}"
    --domain-context "${domain_context}"
    --target-surface "${TARGET_SURFACE}"
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
  else
    status="failed"
  fi

  write_result_json "${result_file}" "${scenario_name}" "${status}" "${domain_id}" "${style}" "${cell_id}" "${seq}" "${attack_yaml}" "${baseline_dir}"
  [[ "${status}" == "ok" ]]
}

append_result_file() {
  local result_file="$1"
  local line

  if [[ ! -f "${result_file}" ]]; then
    echo "[error] missing result file: ${result_file}" >&2
    total=$((total + 1))
    failed=$((failed + 1))
    return
  fi

  line="$(cat "${result_file}")"
  printf '%s\n' "${line}" >> "${DETAIL_JSONL}"

  total=$((total + 1))
  if [[ "${line}" == *'"status":"ok"'* ]]; then
    success=$((success + 1))
  else
    failed=$((failed + 1))
  fi
}

BATCH_NAME="$(default_batch_name)"
DOMAINS_PRESET="matrix_v1"
DOMAIN_FILE="configs/matrix/domain_matrix_v1.txt"
STYLES_CSV="c_secret_harvest,c_bulk_exfiltration,i_config_tamper,i_code_backdoor,a_resource_exhaustion,a_workflow_disruption"
TARGET_SURFACE="enterprise"
SAMPLES_PER_COMBO=2
MAX_DOMAINS=0
MATRIX_VERSION=1
EXPERIMENT_ID=""
PROVIDER="azure"
MODEL="gpt-4o"
TEMPERATURE="0.2"
ACCEPTANCE_LOGIC="auto"
MAX_ASSETS=4
JOBS=1
RESUME=0
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
    --target-surface)
      TARGET_SURFACE="${2:-}"
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
    --jobs)
      JOBS="${2:-}"
      shift 2
      ;;
    --resume)
      RESUME=1
      shift
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
if ! [[ "${JOBS}" =~ ^[0-9]+$ ]] || [[ "${JOBS}" -lt 1 ]]; then
  echo "Error: --jobs must be integer >= 1" >&2
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
if [[ "${TARGET_SURFACE}" != "enterprise" && "${TARGET_SURFACE}" != "user" && "${TARGET_SURFACE}" != "hybrid" ]]; then
  echo "Error: --target-surface must be enterprise|user|hybrid" >&2
  exit 1
fi
if [[ "${CONTINUE_ON_ERROR}" -eq 0 && "${JOBS}" -gt 1 ]]; then
  echo "Error: --stop-on-error is only supported when --jobs=1" >&2
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

declare -a RAW_DOMAIN_LINES=()
if [[ -n "${DOMAIN_FILE}" ]]; then
  if [[ ! -f "${DOMAIN_FILE}" ]]; then
    echo "Error: --domain-file not found: ${DOMAIN_FILE}" >&2
    exit 1
  fi
  mapfile -t RAW_DOMAIN_LINES < "${DOMAIN_FILE}"
else
  mapfile -t RAW_DOMAIN_LINES < <(load_domains_preset "${DOMAINS_PRESET}")
fi

declare -a DOMAIN_LINES=()
for raw_line in "${RAW_DOMAIN_LINES[@]}"; do
  line="${raw_line#"${raw_line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "${line}" ]] && continue
  [[ "${line}" == \#* ]] && continue
  DOMAIN_LINES+=("${line}")
done

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
    insider_exfiltration|malicious_coder_backdoor|indirect_prompt_injection|c_secret_harvest|c_bulk_exfiltration|i_config_tamper|i_code_backdoor|a_resource_exhaustion|a_workflow_disruption) ;;
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
RUN_TMP_DIR="${LOG_ROOT}/${BATCH_NAME}_run_$(date +%Y%m%d_%H%M%S)"

mkdir -p "${BASELINE_ROOT}" "${ATTACK_ROOT}" "${LOG_ROOT}" "${RUN_TMP_DIR}"

if [[ "${RESUME}" -eq 0 ]]; then
  : > "${DETAIL_JSONL}"
else
  touch "${DETAIL_JSONL}"
fi

declare -A DONE_OK_SCENARIOS=()
resume_ok_loaded=0
if [[ "${RESUME}" -eq 1 ]]; then
  load_resume_ok_from_file "${DETAIL_JSONL}"
  shopt -s nullglob
  for result_json in "${LOG_ROOT}/${BATCH_NAME}"_run_*/*.json; do
    load_resume_ok_from_file "${result_json}"
  done
  shopt -u nullglob
  resume_ok_loaded="${#DONE_OK_SCENARIOS[@]}"
fi

declare -a TASK_SCENARIOS=()
declare -a TASK_STYLES=()
declare -a TASK_CONTEXTS=()
declare -a TASK_DOMAINS=()
declare -a TASK_CELL_IDS=()
declare -a TASK_SEQS=()
declare -a TASK_BASELINES=()
declare -a TASK_ATTACK_YAMLS=()
skipped=0

for line in "${DOMAIN_LINES[@]}"; do
  IFS='|' read -r domain_id domain_context <<< "${line}"
  domain_id="$(sanitize_id "${domain_id:-domain}")"
  if [[ -z "${domain_context:-}" ]]; then
    echo "[warn] skip malformed domain line: ${line}" >&2
    continue
  fi

  for style in "${STYLES[@]}"; do
    short_style="$(short_style_for "${style}")"
    for ((i=1; i<=SAMPLES_PER_COMBO; i++)); do
      seq="$(printf '%02d' "${i}")"
      scenario_name="attack_${domain_id}_${short_style}_${seq}"
      if [[ "${RESUME}" -eq 1 && -n "${DONE_OK_SCENARIOS[${scenario_name}]:-}" ]]; then
        skipped=$((skipped + 1))
        continue
      fi

      cell_id="${domain_id}|${style}"
      baseline_dir="${BASELINE_ROOT}/${scenario_name}"
      attack_yaml="${ATTACK_ROOT}/${scenario_name}.yaml"

      TASK_SCENARIOS+=("${scenario_name}")
      TASK_STYLES+=("${style}")
      TASK_CONTEXTS+=("${domain_context}")
      TASK_DOMAINS+=("${domain_id}")
      TASK_CELL_IDS+=("${cell_id}")
      TASK_SEQS+=("${seq}")
      TASK_BASELINES+=("${baseline_dir}")
      TASK_ATTACK_YAMLS+=("${attack_yaml}")
    done
  done
done

planned_total="${#TASK_SCENARIOS[@]}"

total=0
success=0
failed=0
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "Experiment ID: ${EXPERIMENT_ID}"
echo "Parallel jobs: ${JOBS}"
if [[ "${RESUME}" -eq 1 ]]; then
  echo "Resume: enabled (already-successful: ${resume_ok_loaded}, skipped-now: ${skipped})"
else
  echo "Resume: disabled"
fi
echo "Planned scenarios this run: ${planned_total}"

declare -a RESULT_FILES=()
if [[ "${JOBS}" -eq 1 ]]; then
  stop_requested=0
  for ((idx=0; idx<planned_total; idx++)); do
    display_index=$((idx + 1))
    scenario_name="${TASK_SCENARIOS[idx]}"
    result_file="${RUN_TMP_DIR}/$(printf '%06d' "${display_index}")_${scenario_name}.json"

    echo
    echo "[${display_index}/${planned_total}] Generating ${scenario_name}"

    case_failed=0
    if run_one_case \
      "${TASK_SCENARIOS[idx]}" \
      "${TASK_STYLES[idx]}" \
      "${TASK_CONTEXTS[idx]}" \
      "${TASK_DOMAINS[idx]}" \
      "${TASK_CELL_IDS[idx]}" \
      "${TASK_SEQS[idx]}" \
      "${TASK_BASELINES[idx]}" \
      "${TASK_ATTACK_YAMLS[idx]}" \
      "${result_file}"; then
      case_failed=0
    else
      case_failed=1
    fi

    append_result_file "${result_file}"

    if [[ "${case_failed}" -eq 1 ]]; then
      echo "[error] failed scenario: ${scenario_name}" >&2
      if [[ "${CONTINUE_ON_ERROR}" -eq 0 ]]; then
        echo "[stop] stop-on-error enabled." >&2
        stop_requested=1
        break
      fi
    fi
  done

  if [[ "${stop_requested}" -eq 1 ]]; then
    planned_total="${total}"
  fi
else
  for ((idx=0; idx<planned_total; idx++)); do
    display_index=$((idx + 1))
    scenario_name="${TASK_SCENARIOS[idx]}"
    result_file="${RUN_TMP_DIR}/$(printf '%06d' "${display_index}")_${scenario_name}.json"
    log_file="${RUN_TMP_DIR}/$(printf '%06d' "${display_index}")_${scenario_name}.log"
    RESULT_FILES+=("${result_file}")

    echo
    echo "[${display_index}/${planned_total}] Queue ${scenario_name}"

    run_one_case \
      "${TASK_SCENARIOS[idx]}" \
      "${TASK_STYLES[idx]}" \
      "${TASK_CONTEXTS[idx]}" \
      "${TASK_DOMAINS[idx]}" \
      "${TASK_CELL_IDS[idx]}" \
      "${TASK_SEQS[idx]}" \
      "${TASK_BASELINES[idx]}" \
      "${TASK_ATTACK_YAMLS[idx]}" \
      "${result_file}" > "${log_file}" 2>&1 &

    while [[ "$(jobs -rp | wc -l)" -ge "${JOBS}" ]]; do
      wait -n || true
    done
  done

  wait || true

  for result_file in "${RESULT_FILES[@]}"; do
    append_result_file "${result_file}"
  done
fi

ended_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${SUMMARY_JSON}" <<EOF_SUMMARY
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
  "target_surface": "${TARGET_SURFACE}",
  "samples_per_combo": ${SAMPLES_PER_COMBO},
  "max_domains": ${MAX_DOMAINS},
  "jobs": ${JOBS},
  "resume": ${RESUME},
  "resume_ok_loaded": ${resume_ok_loaded},
  "skipped": ${skipped},
  "planned": ${planned_total},
  "total": ${total},
  "success": ${success},
  "failed": ${failed},
  "baseline_root": "${BASELINE_ROOT}",
  "attack_root": "${ATTACK_ROOT}",
  "details_jsonl": "${DETAIL_JSONL}",
  "run_tmp_dir": "${RUN_TMP_DIR}"
}
EOF_SUMMARY

echo
echo "Batch generation finished."
echo "Batch: ${BATCH_NAME}"
echo "Target surface: ${TARGET_SURFACE}"
echo "Total: ${total}, Success: ${success}, Failed: ${failed}, Skipped: ${skipped}"
echo "Attack configs: ${ATTACK_ROOT}"
echo "Summary: ${SUMMARY_JSON}"
echo "Per-scenario logs/results: ${RUN_TMP_DIR}"
