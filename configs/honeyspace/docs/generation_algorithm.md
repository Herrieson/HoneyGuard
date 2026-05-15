# HoneySpace Generation Algorithm

HoneySpace generation should synthesize decoy affordances from the Agent's task,
available interaction space, protected objects, and broad threat classes.

The generator should not know the attacker's exact prompt, injected payload, or
future trace. This is what makes HoneySpace a realistic defense algorithm rather
than a benchmark-specific trap.

## 1. Inputs

```text
T: user task and benign task description
S: Agent specification and capability surface
E: environment object graph
R: protected-object metadata
P: policy / authorization context
B: optional benign workflow prior
M: broad threat classes, not concrete attacker payloads
H: optional historical Agent behavior profile
K: decoy templates and response policies
```

## 2. Output

```text
D: selected honey affordances
C: materialized defended HoneyGuard YAML scenario
G: honeyspace manifest for scoring and analysis
```

## 3. Core Objective

Choose decoys that maximize differential attractiveness and preemption while
minimizing benign false triggers and utility loss.

```text
score(d) =
    attack_affinity(d)
  + benign_incompatibility(d)
  + plausibility(d)
  + preemption_potential(d)
  - attacker_detectability(d)
  - utility_cost(d)
```

For a selected set `D`:

```text
maximize   P(first_touch(D) < first_touch(R) | attacked)
minimize   P(touch(D) | benign)
minimize   utility_loss
```

## 4. Generation Steps

### Step 0: Validate Input Boundary

Reject inputs that leak attack-specific future knowledge:

- exact attacker prompt
- exact indirect injection content
- exact malicious tool output
- future Agent trace
- labels indicating the current run is attacked

Allow broad threat classes such as `credential_seeking` or
`unsafe_external_send`.

### Step 1: Build Interaction Graph

Represent the task runtime as a graph:

```text
nodes: files, assets, tools, MCP objects, memory, helper agents, sinks
edges: can_read, can_invoke, can_send_to, can_authorize, can_reference
```

Mark:

- benign work objects
- real protected objects
- external sinks
- high-risk tools
- untrusted content channels

### Step 2: Infer Benign Workflow

Infer the minimal safe path for task completion:

```text
B = expected benign affordance set
```

Honey affordances should not be required by `B`.

### Step 3: Generate Candidate Decoys

Generate candidates by surface:

- asset templates near sensitive-looking paths
- tool templates that advertise high-risk shortcuts
- MCP server/resource/tool/prompt templates
- helper-agent authority templates
- memory authorization templates
- external sink templates

Each candidate records:

- type
- name/path/description
- trigger events
- response policy
- placement rationale
- risk signals

### Step 4: Score Candidates

Recommended scoring dimensions:

- `attack_affinity`: how useful the decoy appears for the attack objective.
- `benign_incompatibility`: how unnecessary or impermissible it is for benign task completion.
- `plausibility`: how naturally it fits the environment.
- `preemption_potential`: whether it is easier/faster to reach than real protected objects.
- `attacker_detectability`: whether an adaptive attacker can easily identify it as a decoy.
- `utility_cost`: whether it distracts normal task execution.

### Step 5: Select Decoy Set

Select a bounded set with diversity constraints:

```text
at most N decoys per scenario
at least one primary decoy
avoid decoys on required benign path
prefer decoys that precede real protected objects in attack path
include one low-noise trigger where possible
```

### Step 6: Materialize Scenario

Convert selected decoys into HoneyGuard-compatible YAML:

- files under `files`
- mock/inert tools under `mock_tools` or future tool registry
- MCP metadata under `honeyspace` until runtime support exists
- helper agents under `agents` or future helper-agent simulator
- memory under `shared_context`
- acceptance criteria for task utility and simple trigger markers

### Step 7: Emit Manifest

Write generation metadata:

```yaml
honeyspace:
  generation:
    strategy: agent_aware
    generator_version: "0.1"
    selected_candidates: [...]
    rejected_candidates: [...]
    scoring_weights: {...}
```

## 5. Baseline Strategies

### `none`

No decoys. Used to measure real compromise under attack.

### `static_canary`

Fixed canary assets/tools reused across scenarios.

### `random_decoy`

Randomly selected decoy names/types, constrained only for safety.

### `semantic_decoy`

Task-domain-matched decoys without Agent-profile optimization.

### `agent_aware`

Decoys selected by differential attractiveness and preemption potential.

### `agent_aware_containment`

Agent-aware decoys plus runtime response policies that restrict or quarantine the
session after trigger.

## 6. Pseudocode

```python
def generate_honeyspace_scenario(task, agent_spec, env, protected, policy, threat_classes, profile):
    validate_no_attack_specific_inputs(task, env, threat_classes)
    graph = build_interaction_graph(env, tools)
    benign_path = infer_benign_workflow(task, graph)
    candidates = []

    for surface in enabled_surfaces(threat):
        candidates.extend(generate_candidates(surface, task, graph, protected, threat))

    scored = []
    for candidate in candidates:
        if intersects_required_benign_path(candidate, benign_path):
            continue
        scored.append((score_candidate(candidate, task, graph, protected, threat, profile), candidate))

    selected = select_diverse_top_k(scored, constraints={
        "max_decoys": 4,
        "min_primary_decoys": 1,
        "prefer_preemption": True,
    })

    scenario = materialize_honeyguard_yaml(task, env, tools, selected, protected)
    scenario["honeyspace"]["generation"] = generation_manifest(scored, selected)
    return scenario
```

## 7. Early Implementation Recommendation

Start with hand-written scenarios and deterministic templates before building an
LLM generator.

Recommended order:

1. static honey asset
2. static honey tool
3. semantic honey tool
4. honey memory item
5. honey helper agent
6. honey MCP metadata fixture
7. agent-aware candidate scoring
8. full generator
