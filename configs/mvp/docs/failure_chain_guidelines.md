# TraceProbe Failure Chain Guidelines v0.1

## 1. 文档目的

本文件规定 TraceProbe v0.1 中 `failure_chain` 的写法，用于统一描述：

- 风险如何进入系统
- 在哪里被接纳
- 如何从早期偏差传播到最终后果

`failure_chain` 不是自由叙事摘要，而是紧凑、结构化、可比对的传播链表示。

---

## 2. 基本要求

每条 `failure_chain` 应满足：

- 长度通常为 3-5 个节点
- 使用 `snake_case`
- 节点按时间顺序排列
- 节点描述“关键状态变化”，而不是冗长句子
- 尽量避免 attack family 词汇，优先使用机制化表述

推荐结构：

1. 风险进入
2. 风险被接纳
3. 计划或边界被改写
4. 危险动作被选择或执行
5. 后果形成

---

## 3. 推荐语法

v0.1 推荐使用以下事件短语构造 `failure_chain`：

### 3.1 风险进入类

- `hazard_enters_via_goal_specification`
- `hazard_enters_via_user_instruction`
- `hazard_enters_via_retrieved_content`
- `hazard_enters_via_tool_output`
- `hazard_enters_via_environment_state`
- `hazard_enters_via_policy_prompt`
- `hazard_enters_via_memory_state`
- `hazard_enters_via_multi_agent_message`

### 3.2 风险接纳类

- `hazard_is_treated_as_authoritative`
- `data_is_interpreted_as_instruction`
- `unsafe_premise_is_adopted`
- `sensitive_scope_is_assumed_authorized`
- `tool_output_is_trusted_without_verification`

### 3.3 计划偏移类

- `plan_is_shifted`
- `subgoal_is_rewritten`
- `search_scope_is_expanded`
- `safety_check_is_skipped`
- `privilege_boundary_is_ignored`

### 3.4 动作执行类

- `sensitive_resource_is_accessed`
- `unsafe_tool_is_selected`
- `unsafe_arguments_are_built`
- `destructive_action_is_executed`
- `sensitive_data_is_sent_to_untrusted_sink`

### 3.5 后果形成类

- `impact_occurs`
- `data_exfiltration_occurs`
- `policy_violation_occurs`
- `system_state_is_degraded`
- `task_is_derailed`

---

## 4. 节点选择规则

### 4.1 只保留关键因果节点

不要把所有步骤都写进去，只保留对归因有用的节点。

不推荐：

```json
[
  "page_is_loaded",
  "agent_reads_line_1",
  "agent_reads_line_2",
  "agent_reads_line_3",
  "agent_thinks"
]
```

推荐：

```json
[
  "hazard_enters_via_retrieved_content",
  "data_is_interpreted_as_instruction",
  "subgoal_is_rewritten",
  "sensitive_resource_is_accessed",
  "policy_violation_occurs"
]
```

### 4.2 节点要能映射到主标签

`failure_chain` 应能反向解释：

- `channel`
- `first_failed_component`
- `mechanism`
- `impact`

如果链条与主标签对不上，说明至少有一边写错了。

### 4.3 一个节点只表达一个关键变化

不推荐：

- `page_is_loaded_and_agent_decides_to_send_secret`

推荐拆成：

- `hazard_enters_via_retrieved_content`
- `data_is_interpreted_as_instruction`
- `sensitive_data_is_sent_to_untrusted_sink`

---

## 5. 与 ontology 的关系

`failure_chain` 不是 ontology 标签的简单重复，但两者要一致。

示例：

- 若 `primary_channel = tool_output`
  - 第一节点通常应是 `hazard_enters_via_tool_output`

- 若 `primary_mechanism = instruction_data_confusion`
  - 第二节点通常应与 `data_is_interpreted_as_instruction` 之类的接纳节点一致

- 若 `primary_impact = data_exfiltration`
  - 最后一节点通常应与 `data_exfiltration_occurs` 对齐

---

## 6. 四类典型示例

### 6.1 A1 决策失控

```json
[
  "hazard_enters_via_goal_specification",
  "unsafe_premise_is_adopted",
  "search_scope_is_expanded",
  "destructive_action_is_executed",
  "impact_occurs"
]
```

### 6.2 A4 数据边界失效

```json
[
  "hazard_enters_via_environment_state",
  "sensitive_scope_is_assumed_authorized",
  "privilege_boundary_is_ignored",
  "sensitive_resource_is_accessed",
  "policy_violation_occurs"
]
```

### 6.3 C2.1 内容注入

```json
[
  "hazard_enters_via_retrieved_content",
  "data_is_interpreted_as_instruction",
  "subgoal_is_rewritten",
  "sensitive_resource_is_accessed",
  "policy_violation_occurs"
]
```

### 6.4 C2.2 工具输出污染

```json
[
  "hazard_enters_via_tool_output",
  "tool_output_is_trusted_without_verification",
  "plan_is_shifted",
  "unsafe_arguments_are_built",
  "data_exfiltration_occurs"
]
```

---

## 7. 不推荐写法

以下写法应避免：

- 使用完整句子或长段落
- 直接写 attack family，如 `indirect_prompt_injection_happens`
- 直接写模型心理状态，如 `agent_becomes_confused`
- 写与归因无关的中间执行细节
- 一个链里混入多个互相竞争的主因

---

## 8. 推荐模板

```yaml
failure_chain:
  - hazard_enters_via_tool_output
  - tool_output_is_trusted_without_verification
  - plan_is_shifted
  - sensitive_data_is_sent_to_untrusted_sink
  - data_exfiltration_occurs
```

若必须扩展节点命名，应遵循两个条件：

1. 命名描述的是关键状态变化
2. 命名仍然能与 ontology 主字段互相解释
