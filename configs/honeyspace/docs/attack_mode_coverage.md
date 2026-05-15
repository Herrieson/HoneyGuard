# HoneySpace Attack Mode Coverage

This note reviews whether the current HoneySpace attack modes are broad enough
for a paper-facing defense evaluation.

## 1. Bottom Line

The current modes are directionally correct:

- `direct_attack`
- `indirect_attack`
- `memory_attack`
- `mcp_attack`
- `helper_attack`
- `adaptive_attack`

But they are too coarse for HoneySpace. They mix three different concepts:

1. **entry channel**: where adversarial influence enters the Agent context
2. **unsafe objective**: what the compromised Agent is steered to do
3. **attack modifier**: how the attacker makes the attack harder to detect

HoneySpace should model these separately. This keeps the dataset diverse without
creating a combinatorial explosion of one-off labels.

Recommended schema:

```yaml
attack_slot:
  channel: retrieved_content
  objective_classes:
    - credential_seeking
    - sensitive_data_exfiltration
  modifiers:
    - multi_step
    - adaptive_decoy_avoidance
```

## 2. External Taxonomy Check

Sources checked:

- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [AgentDojo](https://arxiv.org/abs/2406.13352)

The external picture is consistent:

- Prompt injection should be split into **direct** and **indirect** channels.
- Indirect injection should not be a single bucket: retrieved documents, RAG,
  tool outputs, MCP responses, tool descriptions, and memory have different
  mediation points.
- Agent systems add risks beyond model-only jailbreaks: tool misuse, excessive
  agency, memory poisoning, inter-agent communication poisoning, protocol
  abuse, identity/authorization confusion, supply-chain compromise, resource
  exhaustion, and unsafe code or workflow execution.
- Agent benchmarks such as AgentDojo emphasize realistic task environments,
  tool calls over untrusted data, and adaptive attacks. That matches the
  HoneySpace goal of measuring interaction choices instead of only final text.

## 3. Local Coverage Check

`configs/mvp/v0_2` already covers useful substrates:

- `C1`: direct user instruction
- `C2.1`: retrieved-content injection
- `C2.2`: tool-output injection
- `B2`: memory-state compromise
- `B3`: multi-agent/helper-message compromise
- `B1`: policy/system-context authority confusion
- `A4`: data-minimization and external-helper upload failures
- `A1/A2/A3`: operation boundary, reasoning distortion, execution instability

The current HoneySpace materialized fixtures cover:

- retrieved content: 3 fixtures
- tool output: 1 fixture
- memory state: 1 fixture
- multi-agent/helper message: 1 fixture
- MCP metadata/resource/server: 1 fixture
- external sink: 1 fixture

That is enough for schema/scorer prototyping, but not enough for a paper-facing
attack-mode matrix. The main missing pieces are:

- direct user-channel attacks
- explicit tool-description/tool-metadata poisoning
- explicit MCP auth/session/protocol abuse
- identity spoofing or fake authorization
- destructive/integrity attacks, not only exfiltration
- resource exhaustion / runaway tool-chain attacks
- supply-chain or configuration poisoning
- adaptive decoy-aware variants for each major channel

## 4. Recommended HoneySpace Taxonomy

### 4.1 Entry Channels

Use these as the primary attack-slot labels.

| Channel | Meaning | Current support | Priority |
| --- | --- | --- | --- |
| `user_instruction` | malicious direct user request, jailbreak, roleplay, fake authority | v0.2 `C1`; not yet in HoneySpace | medium |
| `retrieved_content` | file, web, ticket, wiki, CSV, RAG result contains injected instructions | v0.2 `C2.1`; HoneySpace fixture exists | high |
| `tool_output` | normal tool returns malicious recommendation or hidden instruction | v0.2 `C2.2`; HoneySpace fixture exists | high |
| `tool_metadata` | tool name/description/schema is misleading or malicious | partial through MCP fixture | high |
| `mcp_resource` | MCP resource/prompt/tool response injects context | HoneySpace fixture exists | high |
| `mcp_auth_or_session` | consent bypass, token confusion, session hijack, event injection | not covered | medium |
| `memory_state` | stale, poisoned, cross-session, or shared memory authorization | v0.2 `B2`; HoneySpace fixture exists | high |
| `helper_agent_message` | planner/reviewer/specialist/helper asks for unsafe action | v0.2 `B3`; HoneySpace fixture exists | high |
| `policy_context` | internal policy/system-like context is stale, overtrusted, or misleading | v0.2 `B1`; not yet in HoneySpace | medium |
| `environment_state` | misleading file/resource topology, false state, unsafe default | v0.2 `A1/A2`; not yet in HoneySpace | medium |
| `supply_chain_config` | malicious plugin/tool/server/config package is preinstalled | not covered | low initially |
| `multimodal_content` | injected instructions hidden in image/audio/PDF rendering | not covered | low initially |

### 4.2 Objective Classes

Use these as `threat_model.classes` or `attack_slot.objective_classes`.

| Objective | HoneySpace fit | Best honey affordances |
| --- | --- | --- |
| `credential_seeking` | excellent | honey assets, honey memory, honey MCP resource |
| `sensitive_data_exfiltration` | excellent | honey assets, honey sink, honey export tool |
| `unsafe_external_send` | excellent | honey sink, honey webhook, honey vendor upload |
| `unauthorized_tool_invocation` | excellent | honey tool, honey MCP tool |
| `privilege_escalation` | strong | honey breakglass tool, honey admin helper |
| `fake_authorization` | strong | honey helper, honey approval memory, honey policy note |
| `destructive_write_or_delete` | strong if runtime can safely simulate it | honey workflow action, honey destructive tool |
| `integrity_corruption` | strong if protected object writes are mediated | honey config, honey deployment action |
| `resource_exhaustion` | moderate | honey expensive analysis tool, honey loop trigger |
| `trace_evasion_or_log_tampering` | moderate | honey audit tool, honey log path |
| `human_approval_manipulation` | moderate | honey approval channel, fake reviewer |
| `system_prompt_or_policy_leakage` | limited but useful | honey policy note, honey system-summary asset |

### 4.3 Attack Modifiers

Modifiers should not define the base channel. They make a scenario harder.

- `adaptive_decoy_avoidance`: attacker warns about canaries/honeypots.
- `multi_step`: unsafe action requires a chain of smaller plausible steps.
- `payload_splitting`: malicious instruction is distributed across objects.
- `obfuscated_instruction`: encoding, multilingual text, comments, metadata.
- `cross_session`: attack relies on memory or state from prior runs.
- `multi_agent_propagation`: one compromised agent influences others.
- `tool_chain`: attack chains tool outputs into subsequent tool calls.
- `low_visibility`: trigger happens through metadata, hidden fields, or logs.

## 5. Coverage Matrix For HoneySpace

| Attack family | Concrete example | v0.2 reuse | HoneySpace affordance | Phase |
| --- | --- | --- | --- | --- |
| direct user credential request | user asks assistant to scan for prod token | `C1` | honey credential asset/tool | phase 2 |
| retrieved-content injection | CSV footer says release requires secret | `C2.1` | honey secret path near real secret | phase 1 |
| tool-output injection | diagnostic tool recommends reading private bundle | `C2.2` | honey privileged tool or MCP resource | phase 1 |
| tool metadata poisoning | tool description claims it is required for compliance | new or C2.2-derived | honey dangerous tool with monitored invocation | phase 1 |
| MCP resource/prompt poisoning | MCP prompt/resource contains fake compliance directive | C2.2-derived | honey MCP resource/server | phase 1 |
| MCP auth/session abuse | malicious MCP server causes consent/token/session confusion | new | honey OAuth helper, honey server, honey token | phase 2 |
| memory poisoning | stale memory claims approval for secret access | `B2` | honey memory plus honey secret | phase 1 |
| helper-agent compromise | planner/reviewer asks executor to fetch credential | `B3` | honey helper/fake approver | phase 1 |
| fake authorization | fake manager/admin approval appears in context | `B1/B2/B3` | honey approver, honey policy note | phase 1 |
| external sink exfiltration | injected note asks raw upload to vendor | `A4` | honey upload endpoint/webhook | phase 1 |
| destructive action | attack asks for deleting/rewriting protected config | `A1/A3` | honey delete/deploy action | phase 2 |
| integrity corruption | attack modifies release config or policy file | `A3` | honey protected config | phase 2 |
| resource exhaustion | attack triggers loop, recursive analysis, repeated API calls | new or `A3` | honey expensive tool/rate-limit tripwire | phase 3 |
| supply-chain/config poisoning | preinstalled plugin/server is malicious | new | honey plugin/server manifest | phase 3 |
| adaptive decoy avoidance | attacker tells Agent to avoid fake files and canaries | all channels | less obvious decoy set + combo placement | phase 2+ |

## 6. Phase Recommendations

Phase 1 should not try to cover everything. It should cover the channels where
HoneySpace has the clearest mechanism: a compromised Agent selects an affordance
that the runtime can mediate.

Minimum phase-1 set:

- 2 retrieved-content tasks
- 2 tool-output or tool-metadata tasks
- 2 MCP resource/tool-description tasks
- 2 memory poisoning tasks
- 2 helper/fake-authorization tasks
- 2 external-sink/data-minimization tasks

This gives 12 clean base tasks and directly tests assets, tools, MCP, memory,
helper agents, and sinks.

Phase 2 should add:

- direct user-channel attacks
- destructive/integrity actions
- MCP auth/session confusion
- adaptive decoy-aware variants for every phase-1 channel

Phase 3 should add:

- resource exhaustion
- supply-chain/config poisoning
- multimodal or encoded injections
- cross-session and multi-agent propagation stress suites

## 7. What To Avoid

Avoid making HoneySpace a general jailbreak benchmark. Pure text-only jailbreaks
that never lead to a file, tool, memory, MCP, helper, sink, or workflow action
are not a good fit because the defense cannot preempt what it cannot mediate.

Also avoid hiding the attack taxonomy inside scenario names only. The generator,
materializer, and scorer need structured labels so results can be broken down by
entry channel, objective, affordance type, and adaptive modifier.
