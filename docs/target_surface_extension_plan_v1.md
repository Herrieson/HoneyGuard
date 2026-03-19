# HoneyGuard Target Surface Extension Plan v1

## 1) Background

Current batch generation and attack config pipelines are primarily optimized for enterprise/ops-side attack surfaces:

- Domain matrix focuses on enterprise operation systems.
- Asset/path defaults are Linux host filesystem centric (`/etc`, `/var`, `/srv`, `/opt`, `/home`, ...).
- Goal/instruction templates are mostly maintenance/ops narratives.

This creates a structural bias where user-side attack scenarios are underrepresented.

## 2) Objective

Extend scenario generation from single-surface (enterprise) to multi-surface:

- `enterprise`: current default behavior.
- `user`: end-user journey and user-data impact centered scenarios.
- `hybrid`: cross-surface chains (user-facing entry + enterprise-side impact).

Design requirement: keep existing commands reproducible and backward compatible.

## 3) Non-goals

- Do not break existing v2 CIA style experiments.
- Do not change current default output unless new flags are explicitly enabled.
- Do not redesign the evaluation metric system in this phase (reuse five-metric v1).

## 4) High-level Design

Introduce a first-class config dimension: `target_surface`.

- CLI layer (`generate_attack_batch.sh`, `generate_attack_scenario.sh`, `build_attack_config.py`) accepts and passes through `target_surface`.
- YAML schema carries `target_surface` metadata.
- Planning/hardening/lint/aggregation logic branches by surface.
- Domain matrices can be selected per surface profile.

## 4.1) Progress Tracker

Last updated: 2026-03-18

- [x] Phase 1: Add `--target-surface` in `generate_attack_batch.sh` and pass through to scenario generation.
- [x] Phase 1: Add `--target-surface` in `generate_attack_scenario.sh` and pass through to attack config builder.
- [x] Phase 1: Add `--target-surface` in `build_attack_config.py` and emit `target_surface` in output YAML.
- [x] Phase 1: Add `target_surface` to build summary JSON output.
- [x] Phase 1: Add `by_surface` and `by_surface_style` slices in `aggregate_attack_reports.py`.
- [x] Phase 1: Add `target_surface` column to aggregate CSV output.
- [x] Phase 1: Keep backward compatibility for old configs via `target_surface=unknown` fallback in aggregation.
- [x] Phase 2: Surface-aware candidate ranking/hardening/instruction strategy in `build_attack_config.py` (initial version).
- [x] Phase 2: Add `configs/matrix/domain_matrix_user_v1.txt`.
- [x] Phase 2: Add `configs/matrix/domain_matrix_hybrid_v1.txt` (optional but recommended).
- [x] Phase 2: Extend domain preset selection to include user/hybrid presets.
- [x] Phase 2: Extend `env_builder.py` prompts/contracts for user/hybrid artifacts (initial version).
- [x] Phase 3: Add surface-aware lint rules in `attack_config_lint.py`.
- [x] Phase 3: Run enterprise parity regression smoke checks and document deltas (default vs explicit enterprise: no diff in sample).

## 5) Planned Changes by Module

### 5.1 `scripts/generate_attack_batch.sh`

- Add flag: `--target-surface enterprise|user|hybrid` (default: `enterprise`).
- Extend `--domains` presets to support user/hybrid profiles (or keep `--domain-file` as primary for user/hybrid).
- Pass `--target-surface` into each `generate_attack_scenario.sh` call.
- Add `target_surface` into detail/summary logs.

### 5.2 `scripts/generate_attack_scenario.sh`

- Add flag: `--target-surface enterprise|user|hybrid` (default: `enterprise`).
- Pass through to `build_attack_config.py`.
- Keep current defaults unchanged if the flag is omitted.

### 5.3 `scripts/build_attack_config.py`

- Add flag: `--target-surface enterprise|user|hybrid` (default: `enterprise`).
- Add `target_surface` to generated YAML top-level metadata.
- Surface-aware behavior:
  - Candidate asset ranking.
  - Fallback asset injection (`_ensure_asset_diversity`).
  - Goal/instruction templates.
  - Path injection/hardening behavior.
- Keep current enterprise defaults as-is for backward compatibility.

### 5.4 `scripts/env_builder.py`

- Extend contract/skeleton prompts so user/hybrid scenarios can include user-side entities:
  - user roles/personas
  - user journey artifacts
  - user-impactful data entities
- Ensure generated files can represent user-facing workflows, not only ops configs/logs.

### 5.5 `scripts/init_from_config.py`

- Keep secure defaults for workspace constraints.
- Make workspace path policy optionally surface-aware and configurable via YAML fields.
- Preserve current behavior when new fields are absent.

### 5.6 `scripts/attack_config_lint.py`

- Add surface-aware lint checks:
  - `user`: require user-side process/evidence criteria.
  - `hybrid`: require both user-side and enterprise-side evidence.
  - warn if scenario surface and target assets are semantically mismatched.

### 5.7 `scripts/aggregate_attack_reports.py`

- Read `target_surface` from config metadata.
- Add reporting slices:
  - `by_surface`
  - `by_surface_style`
- Keep old reports valid (`target_surface=unknown` fallback when missing).

## 6) Data Contract Additions (YAML)

Proposed top-level optional fields:

- `target_surface`: `enterprise|user|hybrid`
- `surface_profile`: optional profile id/version

Backward compatibility:

- If missing, default to `enterprise`.

## 7) New Matrix/Data Files

Planned files:

- `configs/matrix/domain_matrix_user_v1.txt`
- `configs/matrix/domain_matrix_hybrid_v1.txt` (optional in phase 1, recommended in phase 2)

Format remains:

`domain_id|domain_context`

## 8) Migration and Compatibility Strategy

1. Default behavior unchanged.
2. New behavior enabled only by explicit flags/new domain files.
3. Old generated configs continue to run and aggregate.
4. Old reports remain comparable (surface defaults to `enterprise`/`unknown`).

## 9) Implementation Phases

### Phase 1: Plumbing (safe)

- Add CLI flags and metadata pass-through.
- Add aggregation support for surface slices.
- No major strategy changes in attack planning.

### Phase 2: Strategy Upgrade

- Surface-aware candidate ranking, hardening, and instruction generation.
- Introduce user/hybrid domain matrices.

### Phase 3: Quality Guardrails

- Surface-aware lint rules.
- Regression checks for enterprise baseline parity.

## 10) Acceptance Criteria

- Existing `matrix_v1` enterprise runs produce equivalent behavior by default.
- User/hybrid runs can be generated end-to-end without manual edits.
- Aggregation outputs include `by_surface` and `by_surface_style`.
- Lint can detect obvious surface mismatches.
- Surface taxonomy and metric interpretation notes are documented for paper use.

## 11) Risks and Mitigations

- Risk: enterprise benchmark drift.
  - Mitigation: strict default compatibility + golden sample diffs.
- Risk: weak user-surface realism.
  - Mitigation: curate dedicated user/hybrid domain matrices and targeted lint checks.
- Risk: report fragmentation.
  - Mitigation: preserve common five-metric schema and add surface as an extra slice only.

## 12) Open Questions

- Should `hybrid` be required in core benchmark, or remain optional extension?
- Should we introduce surface-specific sub-metrics later, or keep only five-metric v1?
- Which minimal user-side domain set should be considered baseline-representative?

## 13) Next Execution Step

Phase 1 is in place. Next step is Phase 2 strategy upgrades (surface-aware generation behavior + user/hybrid domain matrices), then Phase 3 lint/quality guardrails.

## 14) Supporting Design Notes

- `docs/target_surface_taxonomy_v1.md` (surface definitions + labeling rubric)
- `docs/surface_metric_validity_v1.md` (metric interpretation by surface)
