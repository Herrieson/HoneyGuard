# HoneyGuard Target Surface Taxonomy v1

## 1) Purpose

Define a consistent, auditable labeling standard for `target_surface`:

- `enterprise`
- `user`
- `hybrid`

This taxonomy is used by scenario generation, lint checks, aggregation slices, and paper reporting.

## 2) Core Definitions

### 2.1 `enterprise`

Primary risk and action path is on enterprise-side system internals, such as:

- infrastructure/runtime configuration
- deployment keys and service credentials
- scheduler/queue/ops workflow internals
- backend code/config/log operational controls

Typical impact: backend integrity/availability or enterprise secret exposure.

### 2.2 `user`

Primary risk and action path is on end-user-facing data/workflows, such as:

- account/session/profile artifacts
- order/payment/cart/customer support traces
- user-visible workflow manipulation or data leakage

Typical impact: direct user data exposure or user-journey disruption.

### 2.3 `hybrid`

Scenario requires both surfaces in a meaningful chain:

- user-facing entry/impact plus enterprise-side pivot or persistence, or
- enterprise-side change that directly drives user-facing compromise evidence.

Typical impact: cross-surface blast radius.

## 3) Labeling Rule (Normative)

Use this precedence:

1. If both user-side and enterprise-side evidence are required for success criteria, label `hybrid`.
2. Else if required evidence is primarily user-side, label `user`.
3. Else label `enterprise`.

"Required evidence" means criteria with `enforce=true` and scenario-defining compromise checks.

## 4) Evidence Rubric

### 4.1 User-side evidence signals

- paths/tokens around: `session`, `profile`, `account`, `order`, `payment`, `cart`, `customer`, `ticket`, `otp`, `mfa`
- criteria values indicating user data artifacts
- user-facing workflow state mutation checks

### 4.2 Enterprise-side evidence signals

- paths/tokens around: `/etc`, `/var`, `/usr`, `/opt`, `/srv`, `.ssh`, `cron`, `systemd`, `policy`, `config`, `kube`, `vault`
- backend config/code/log mutation checks
- service-level runtime/scheduler control checks

### 4.3 Hybrid minimum condition

At least one meaningful user-side signal and one meaningful enterprise-side signal must both be present in scenario evidence.

## 5) Borderline Cases

### Case A: user word appears only in domain text, criteria all ops-side

Label: `enterprise`.
Reason: evidence path is enterprise-only.

### Case B: enterprise path appears as decoy, all enforced criteria are user-side

Label: `user`.
Reason: enforced evidence path is user-side.

### Case C: user-side data read + backend scheduler tamper both required

Label: `hybrid`.
Reason: cross-surface required compromise path.

## 6) Mapping to Current Tooling

- Generation metadata field: `target_surface`.
- Lint:
  - `user` requires user-side evidence hints.
  - `hybrid` requires both user and enterprise evidence hints.
- Aggregation:
  - report `by_surface` and `by_surface_style`.

## 7) Reporting Guidance

In paper tables:

- report overall + by-surface slices
- keep taxonomy version in appendix: `target_surface_taxonomy_v1`
- explicitly state that labels are scenario-design labels, not post-hoc classifier outputs

## 8) Versioning

- Version: `v1`
- Date: `2026-03-18`
- Breaking change policy: any definition/rubric change requires `v2` and should not be merged into old experiment IDs.
