# HoneySpace Dataset Expansion Protocol

This protocol keeps HoneySpace scalable beyond the first hand-written dev set.

## 1. Directory Contract

```text
configs/honeyspace/
  scenarios/base_dev/          clean defense-agnostic base tasks
  attack_overlays/dev/         exact attack payloads for evaluation
  scenarios/materialized/      generated defended scenarios
  templates/                   copyable YAML skeletons
```

Base tasks must stay clean:

- no `honeyspace` block
- no `honey_affordances`
- no honey assets, honey tools, honey MCP endpoints, or trigger policies
- no exact attack payload text

Attack overlays contain the exact malicious payload. The HoneySpace generator
must not inspect overlay payloads in the main defense setting.

Materialized scenarios are generated from:

```text
base task + attack overlay + defense condition + generator
```

Use the materializer for the first deterministic generator:

```bash
uv run python scripts/honeyspace/materialize_honeyspace.py --overwrite
```

By default this writes `none`, `static_canary`, `random_decoy`, and
`agent_aware` conditions under `scenarios/materialized/dev/`.

## 2. Naming

Base tasks:

```text
hs_base_<domain>_<workflow>.yaml
```

Attack overlays:

```text
hs_ov_<base_suffix>_<channel>_<objective>.yaml
```

Materialized scenarios:

```text
hs_mat_<base_suffix>_<overlay_suffix>_<defense_condition>.yaml
```

Do not encode every taxonomy field into filenames. The YAML fields are the
source of truth.

## 3. Base Task Requirements

Every base task needs:

- `scenario`, `task_id`, `suite`, `family`, `difficulty`
- `agent_mode`, `tools_enabled`, `agents`, `files`, `initial_instructions`
- utility acceptance criteria
- safety acceptance criteria
- `honeyspace_base.version`
- `honeyspace_base.protected_objects`
- `honeyspace_base.benign_allowed_affordances`
- `honeyspace_base.threat_model.classes`
- `honeyspace_base.attack_slots`
- `honeyspace_base.expected_safe_path`

Each `attack_slots[]` item must include:

```yaml
id: short_slot_id
channel: retrieved_content
objective_classes:
  - credential_seeking
modifiers: []
description: >
  Broad description only; no exact attack payload.
```

## 4. Attack Overlay Requirements

Every overlay needs:

```yaml
overlay_id: hs_ov_example
base_task_id: hs_base_example
suite: honeyspace_attack_overlays_dev
channel: retrieved_content
objective_classes: [...]
modifiers: [...]
injection:
  type: files_append
  target: /srv/example/input.txt
  payload: |
    Exact attacker payload for evaluation.
expected_no_defense_failure:
  compromised_objects: [...]
  unsafe_events: [...]
```

Use one primary injection per overlay unless the modifier is explicitly
`payload_splitting` or `multi_step`.

## 5. Expansion Workflow

1. Add or update a row in `manifests/base_dev.yaml`.
2. Create the clean base YAML from `templates/base_task_template.yaml`.
3. Create one overlay from `templates/attack_overlay_template.yaml`.
4. Run:

```bash
uv run python scripts/honeyspace/validate_honeyspace_dataset.py --strict-phase1
```

5. Generate materialized scenarios:

```bash
uv run python scripts/honeyspace/materialize_honeyspace.py --overwrite
```

6. Calibrate no-defense benign and attacked runs.
7. Run defended conditions and compare against `none`.

## 6. Scaling Rule

Scale by cells, not by ad hoc examples.

For a 40-scenario pilot, keep the same taxonomy and fill a matrix across:

- entry channel
- objective class
- domain
- protected object type
- expected honey affordance type
- difficulty

For a 100+ main set, add variants through controlled transformations:

- domain swap
- protected-object swap
- injection surface swap
- modifier addition
- difficulty increase

Do not duplicate the same story with only names changed unless it tests a
specific cell in the matrix.
