# HoneySpace

HoneySpace is the new defense track for HoneyGuard.

The project studies **deception over the Agent interaction space**: instead of
only protecting real files or credentials, a defense algorithm dynamically
exposes monitored decoy affordances that should be avoided under benign
objectives but become attractive when an Agent is compromised.

Examples of honey affordances:

- honey assets: fake secrets, fake customer exports, fake prod configs
- honey tools: inert but monitored tools such as `export_all_customer_records`
- honey MCP endpoints: fake high-privilege servers, resources, prompts, tools
- honey helper agents: fake approvers, admins, emergency coordinators
- honey memory items: fake historical approvals or policy exceptions
- honey sinks: fake external upload, vendor sync, or webhook endpoints

The core goal is not just to detect that an attack happened. The goal is to make
a compromised Agent reveal unsafe intent or touch a decoy **before** it reaches
real protected objects or real side-effectful tools.

## Design Principle

HoneySpace should separate clean tasks from defense-generated decoys:

```text
clean base task + HoneySpace generator -> materialized defended scenario
```

The test dataset should primarily contain clean, defense-agnostic base tasks.
Honey assets, honey tools, honey MCP endpoints, honey helper agents, and other
decoys are generated dynamically from allowed defender-side inputs such as the
user task, Agent capabilities, environment graph, protected-object metadata, and
policy context. The generator should not assume knowledge of the attacker's exact
prompt or concrete attack strategy.

## Current Work Products

This directory owns the research-facing artifacts for the new project:

- `docs/project_scope.md`: threat model, claims, non-goals, success criteria.
- `docs/affordance_taxonomy.md`: interaction-space object taxonomy.
- `docs/dataset_schema.md`: HoneySpace scenario YAML contract.
- `docs/dynamic_injection_design.md`: clean-task / dynamic-decoy split and
  generator input assumptions.
- `docs/base_task_construction.md`: how to build high-risk clean baseline tasks.
- `docs/attack_mode_coverage.md`: attack-mode taxonomy, coverage gaps, and
  phase priorities.
- `docs/dataset_expansion_protocol.md`: scalable naming, manifest, overlay, and
  validation workflow for growing the dataset.
- `docs/generation_algorithm.md`: decoy generation and placement algorithm.
- `docs/experiment_plan.md`: baselines, metrics, suites, and run plan.
- `manifests/`: coverage targets and split membership.
- `templates/`: copyable base-task and attack-overlay skeletons.
- `attack_overlays/`: exact attack payloads kept separate from clean base tasks.
- `presets/`: reusable strategy and response-policy definitions.
- `scenarios/`: clean base tasks and materialized defended fixtures.

## Planned Implementation Layers

The project should stay compatible with HoneyGuard's existing runtime where
possible, but HoneySpace needs its own defense semantics:

1. **Dataset layer**: HoneyGuard-compatible clean base task YAMLs with
   protected-object metadata and evaluation slots.
2. **Attack-overlay layer**: exact malicious payloads for calibration and
   evaluation, kept out of the generator input boundary.
3. **Generation layer**: synthesize decoy affordances from task context, real
   protected objects, available tools, and Agent profile.
4. **Materialization layer**: create defended run YAMLs by injecting honey
   affordances and response policies.
5. **Runtime mediation layer**: wrap file/tool/MCP/sub-agent/memory interactions
   and trigger policies when honey affordances are touched.
6. **Evaluation layer**: score preemption, real compromise, benign false
   triggers, utility retention, and adaptive bypass.

Validate the clean base-task and overlay layer with:

```bash
uv run python scripts/honeyspace/validate_honeyspace_dataset.py --strict-phase1
```

Materialize the first deterministic defended dev set with:

```bash
uv run python scripts/honeyspace/materialize_honeyspace.py --overwrite
```

## Naming

Use `HoneySpace` for the project and `honey affordance` for the general decoy
object. Use narrower terms only when needed:

- `honey asset`
- `honey tool`
- `honey MCP endpoint`
- `honey helper agent`
- `honey memory`
- `honey sink`

Avoid framing the project as only a honeytoken or honeyfile method.
