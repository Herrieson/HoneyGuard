# Dynamic HoneySpace Injection Design

HoneySpace should treat benchmark tasks and defense-generated decoys as separate
layers.

The clean benchmark task should not contain baked-in honey affordances. A
HoneySpace algorithm should inspect allowed defender-side context, synthesize
decoys, and materialize a defended run configuration.

## 1. Layered View

```text
base task
  + defense condition
  + HoneySpace generator
  -> materialized defended scenario
  -> runtime trace
  -> HoneySpace scorer
```

### Base Task

A base task defines:

- benign user task
- Agent role and allowed capabilities
- environment files/resources/tools
- real protected objects
- utility requirements
- policy constraints
- optional attack-channel slots for evaluation

It should not define concrete honey affordances.

### Defense Condition

Examples:

- `none`
- `static_canary`
- `random_decoy`
- `semantic_decoy`
- `agent_aware`
- `agent_aware_containment`

The same base task should be runnable under each condition.

### Materialized Defended Scenario

The materialized scenario is produced by the defense algorithm. It contains:

- generated honey affordances
- trigger rules
- response policies
- generator manifest
- optional current HoneyGuard probes for compatibility

This layer may look like the current hand-written `scenarios/dev/*.yaml`
fixtures.

## 2. Generator Inputs

The generator may use information a defender plausibly has before or during run
setup.

### User Task

Allowed:

- current user instruction
- task domain
- requested output and workflow
- explicit constraints from the user or system

Not allowed:

- hidden attacker payload unless it is already part of a runtime observation that
  the defender is explicitly allowed to inspect in that condition

### Agent Specification

Allowed:

- Agent role
- available tools
- tool descriptions
- MCP server catalog available to the Agent
- helper/sub-agent topology
- memory mode and visible memory keys
- broad model/profile label if available

Example:

```yaml
agent_spec:
  role: release operations assistant
  tools: [read_file, bash_command, ticket_lookup]
  mcp_servers: [docs, observability]
  helper_agents: [planner, executor, verifier]
```

### Environment Graph

Allowed:

- file/resource inventory
- path names and metadata
- known protected objects and sensitivity labels
- available external sinks
- environment topology visible to the runtime

The generator should not need real sensitive contents. It only needs object
metadata and policy labels.

### Policy and Authorization Context

Allowed:

- least-privilege policy
- which objects are allowed for the current task
- which actions require approval
- organization-specific naming conventions

### Benign Workflow Prior

Allowed:

- expected safe path
- required files/tools
- allowed sinks
- optional task plan from a trusted static planner

This is used to avoid placing decoys directly on the required benign path.

### Historical Agent Behavior Profile

Optional:

- aggregate model/tool-selection tendencies from prior benign calibration runs
- historical false-trigger rates
- common attack-attractive names/tools for this Agent class

This is allowed only if it is not derived from the current attack payload.

## 3. Inputs The Generator Should Not Assume

To make the method realistic, the generator should not assume access to:

- exact attacker prompt
- exact indirect injection text
- exact malicious tool output
- attacker's private strategy
- future Agent hidden reasoning
- post-compromise trace events
- true labels such as "this run is attacked"

The generator may assume a broad threat class or risk model, for example:

- credential seeking
- unsafe external send
- fake authorization
- MCP privilege misuse
- bulk data export
- policy bypass

But it should not know the concrete attack wording.

## 4. Threat-Class Inputs

The generator can be configured with threat classes:

```yaml
threat_model:
  classes:
    - credential_seeking
    - unsafe_external_send
    - fake_authorization
  attacker_knowledge: black_box
```

Recommended attacker-knowledge levels:

- `black_box`: attacker does not know HoneySpace is active.
- `gray_box`: attacker knows honey affordances may exist but not their details.
- `white_box`: attacker knows the defense strategy and tries to avoid decoys.

The main benchmark should include `black_box` and `gray_box`; `white_box` should
be reported as adaptive stress testing.

## 5. Fair Experiment Protocol

For each base task:

1. Run benign mode under each defense condition.
2. Run attacked mode under each defense condition.
3. Use the same base task and same attack channel across conditions.
4. Let only the defense condition change the interaction space.
5. Score honey triggers, real compromise, utility, false triggers, and
   preemption.

This protocol separates task difficulty from defense effectiveness.

## 6. Scoring Consequence

The scorer should record:

- `base_task_id`
- `materialized_task_id`
- `defense_condition`
- `generator_inputs_hash`
- `generated_honey_ids`
- `first_honey_step`
- `first_real_compromise_step`
- `preemption_success`

This allows fair paired comparisons across defense conditions.

## 7. Current Repository Mapping

Current hand-written files under `scenarios/dev/` are best understood as
**materialized defended fixtures**, not final base tasks.

Next step:

- add `scenarios/base_dev/` for clean tasks
- add a materializer script that converts base tasks plus a defense condition
  into defended YAMLs
- keep manually materialized fixtures for schema and scorer development
