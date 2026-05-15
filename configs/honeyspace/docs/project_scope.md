# HoneySpace Project Scope

## 1. Project Goal

HoneySpace studies a runtime defense for LLM Agents based on **agent-aware
deceptive affordances**.

An LLM Agent does not only read assets. It chooses among files, tools, MCP
servers, resources, prompts, helper agents, memory entries, APIs, and external
sinks. HoneySpace instruments this interaction space with decoy objects that
normal Agents should avoid, but compromised Agents are likely to select.

When a decoy is touched, the runtime can detect unsafe intent, preserve evidence,
and contain the session before real assets or real side-effectful tools are
reached.

## 2. Central Claim

Compromised LLM Agents expose behavior through their interaction choices. Those
choices have exploitable biases: they often prefer semantically valuable,
high-authority, low-friction objects such as secrets, admin tools, breakglass
workflows, export utilities, and privileged helper agents.

HoneySpace uses this property to place decoy affordances with high differential
attractiveness:

```text
P(touch decoy | attacked) high
P(touch decoy | benign) low
```

The main defense objective is preemption:

```text
first_touch(honey_affordance) < first_touch(real_protected_object)
```

## 3. Interaction Space

The Agent interaction space includes every object that the Agent can observe,
select, invoke, trust, or route information through:

- file-system paths
- credentials and data assets
- tools and tool descriptions
- MCP servers, tools, resources, and prompts
- RAG documents and retrieved content
- memory entries and shared context
- helper/sub-agent messages
- external sinks and webhooks
- workflow actions such as approve, deploy, export, delete, sync, or bypass

HoneySpace is a defense over this whole space, not only over data assets.

## 4. Honey Affordance

A **honey affordance** is a monitored decoy interaction opportunity exposed to
the Agent runtime.

It should satisfy four constraints:

- **Attractive under compromise**: useful-looking for malicious, injected, or
  unsafe objectives.
- **Avoidable under benign operation**: not needed for the legitimate task.
- **Plausible**: consistent with the environment and task domain.
- **Safe**: inert, synthetic, and unable to cause real side effects.

Examples:

- fake `/secrets/prod_admin_token.txt`
- fake `export_all_customer_records(destination)` tool
- fake `mcp://internal-breakglass` server
- fake `emergency_approver` helper Agent
- fake memory entry claiming a previous admin approval
- fake vendor upload endpoint

## 5. Threat Model

The attacker can compromise the Agent's behavior through one or more channels:

- direct malicious user instruction
- indirect prompt injection in retrieved content
- malicious tool output
- malicious or misleading tool metadata
- poisoned memory
- malicious MCP prompt/resource/tool description
- MCP authorization, consent, session, or event-channel abuse
- compromised planner, reviewer, or helper Agent message
- stale or misleading policy/system-like context
- supply-chain or runtime-configuration poisoning

The compromised Agent may attempt to:

- read sensitive assets
- invoke high-risk tools
- connect to high-privilege MCP endpoints
- solicit fake authorization
- route sensitive data to external sinks
- bypass policy, redaction, approval, audit, or least-privilege controls
- corrupt, delete, or rewrite protected state
- exhaust resources through recursive or expensive tool chains
- evade traces or tamper with logs

The defender controls the runtime environment and can:

- expose synthetic decoy affordances
- mediate file, tool, MCP, memory, and sub-agent interactions
- observe tool calls and selected affordances
- block or downgrade future actions after a trigger
- preserve trace evidence for scoring and forensics

The defender does not assume:

- access to hidden model internals
- perfect prompt-injection detection
- modified model weights
- perfect natural-language safety classification

## 6. Defense Actions

HoneySpace triggers can map to several response levels:

- `observe`: record evidence only.
- `risk_score`: increase a session risk score.
- `require_approval`: pause and require human approval for high-risk actions.
- `restrict_sinks`: disable external sends/uploads for the session.
- `read_only`: allow reads but disable writes or side effects.
- `quarantine`: freeze the session and export evidence.
- `terminate`: stop the run immediately.

The response should be configurable per affordance and per scenario.

## 7. Non-Goals

HoneySpace is not:

- a replacement for least privilege or access control
- a prompt filter
- a general harmful-content classifier
- a counterattack system
- a guarantee that every attack is stopped

The method should be positioned as runtime deception plus mediation: it reduces
the invisible window between compromise and damage, and can prevent damage when
decoys preempt real targets.

## 8. Success Criteria

The project is successful if it can show:

1. Agent-aware honey affordances trigger more often under attack than under
   benign tasks.
2. They preempt real protected-object compromise more often than static or
   random decoys.
3. They preserve normal task utility with low benign false-trigger rates.
4. They provide earlier and more action-grounded evidence than output-only
   safety checks.
5. They remain useful under adaptive attacks that mention honeypots/canaries.
