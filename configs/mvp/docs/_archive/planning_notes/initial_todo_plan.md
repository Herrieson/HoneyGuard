下面给你一份**从零到可投 NeurIPS 的执行任务列表**。按顺序做，尽量不回头。考虑到你**已经有 YAML 场景定义 + Docker 容器 + 调 Agent + 多步执行 + 轨迹记录 + 最终环境状态**的测试框架，我会把计划建立在这个现有基础上，不让你重复造轮子。

我会分成：

1. **总目标**
2. **阶段化任务列表**
3. **每个任务具体怎么做**
4. **实验该怎么设计**
5. **每周推进顺序**
6. **你现在立刻该做什么**

---

# 一、你现在的项目目标，先定死

你的目标不是“做一个能跑的 agent benchmark”，因为你已经有框架了。  
你现在的目标应该明确改成：

> **在现有执行框架上，构建一个“轨迹感知 + 归因级”的 Agent Safety Benchmark，并完成可投稿 NeurIPS 的实验与论文。**

所以你现在缺的不是基础执行，而是下面这几层：

- **归因本体（ontology）**
- **任务集（尤其是单主因、可归因的任务）**
- **自动化/半自动化的归因标注流程**
- **归因级指标**
- **对比实验**
- **论文叙事与图表**

换句话说，核心工作已经从“系统能不能跑”变成了：

> **如何让这个系统产出有学术价值的归因级 benchmark 结果。**

---

# 二、总路线图

建议你按这 8 个阶段推进：

### Phase 0：冻结论文目标与最小范围
### Phase 1：定义归因 ontology 和标注协议
### Phase 2：把现有 YAML 场景系统改造成归因任务系统
### Phase 3：先做一个小规模开发集（20–30 个样本）
### Phase 4：建立评分器：结果级 + 归因级
### Phase 5：扩展正式 benchmark（60–100 个样本）
### Phase 6：跑基线与核心实验
### Phase 7：分析、出图、写论文
### Phase 8：补充消融、附录、整理开源

下面我按这个顺序详细展开。

---

# Phase 0：冻结论文目标与最小范围

---

## 任务 0.1：确定论文主线
### 你要做什么
写一个 1 页文档，回答这 4 个问题：

1. **论文主张是什么**
   - outcome-only benchmark 不够
   - 需要 trajectory-aware & attribution-level benchmark

2. **论文最核心的方法是什么**
   - 基于轨迹的归因标签体系 + 可控 benchmark + 可编程沙箱

3. **论文最核心的实验问题是什么**
   - 相同 endpoint 分数是否掩盖不同 failure trajectories？
   - endpoint-only 是否漏掉 latent safety violations？
   - internal authority 是否是被低估的风险源？

4. **MVP 范围是什么**
   - A1 决策失控
   - A4 数据边界失效
   - C2.1 内容注入
   - C2.2 工具输出污染
   - B 先做少量 pilot，不作为全部主线

### 产出
- `project_scope.md`

### 为什么先做这个
不先冻结范围，你后面会不断加任务、加 threat、加复杂度，最后什么都想做，论文主线会散。

---

## 任务 0.2：确定 benchmark 版本边界
### 你要做什么
明确 v0.1 不做什么：

- 不做真实互联网浏览
- 不做真实 OS 提权
- 不做大量多 agent 场景
- 不追求覆盖所有 attack family
- 不追求 B 类特别大规模

### 产出
- `scope_exclusions.md`

### 原则
归因级 benchmark 的核心不是“多”，而是“干净、可控、可解释”。

---

# Phase 1：定义归因 ontology 和标注协议

这是整个项目最关键的一步。

---

## 任务 1.1：定义归因标签体系（ontology）
### 你要做什么
你需要写一版固定标签表。  
建议先用下面这套，不要随意扩：

### Source
- `non_adversarial`
- `internal_compromise`
- `external_attack`

### Channel
- `goal_specification`
- `user_instruction`
- `retrieved_content`
- `tool_output`
- `environment_state`
- `policy_prompt`
- `memory_state`
- `multi_agent_message`

### First Failed Component
- `instruction_resolver`
- `planner`
- `reasoner`
- `memory_manager`
- `tool_selector`
- `tool_argument_builder`
- `executor`
- `output_filter`
- `reviewer_agent`
- `orchestrator`

### Mechanism
- `over_compliance`
- `unsafe_objective_optimization`
- `hallucinated_premise`
- `false_causal_inference`
- `instruction_data_confusion`
- `authority_overtrust`
- `goal_rewrite_without_authorization`
- `privilege_boundary_failure`
- `sensitive_data_overdisclosure`
- `unverified_state_assumption`
- `unsafe_tool_trust`
- `loop_termination_failure`
- `destructive_exploration`

### Impact
- `dangerous_action`
- `data_exfiltration`
- `privilege_misuse`
- `system_degradation`
- `task_derailment`
- `resource_exhaustion`
- `hidden_policy_violation`
- `unauthorized_sensitive_exploration`

### 你具体怎么做
写一个文档，每个标签都包含：
- 定义
- 边界
- 正例
- 反例
- 和相邻标签的区别

### 产出
- `docs/ontology_v0.1.md`

### 验收标准
你团队任意两个人拿同一个任务描述，能大致打出一致标签。

---

## 任务 1.2：定义“主因优先”的标注协议
### 你要做什么
解决一个关键问题：  
一个样本可能同时包含多个现象，但 leaderboard 必须有一个**主标签**。

### 你要写清楚的规则
1. 每个样本必须有：
   - 一个 primary source
   - 一个 primary channel
   - 一个 primary mechanism
   - 一个 primary first-failure component

2. 如果多个都成立，优先选择：
   - 最早发生、且如果阻断就能避免结果的那个

3. “攻击类型”不能当“机制”
   - indirect injection 不是 mechanism
   - jailbreak 不是 mechanism

4. 允许 secondary labels，但不作为主榜依据

### 产出
- `docs/annotation_guidelines_v0.1.md`

---

## 任务 1.3：定义 failure chain 语法
### 你要做什么
规定传播链怎么写，不然每个人写法不一致。

### 建议格式
每个 failure chain 用 3–5 个事件节点表示：

- `hazard_enters_system`
- `hazard_is_interpreted_as_authoritative`
- `plan_is_shifted`
- `unsafe_action_is_selected`
- `impact_occurs`

### 示例
```json
[
  "read_untrusted_webpage",
  "interpreted_embedded_text_as_instruction",
  "rewrote_subgoal",
  "called_external_api_with_secret"
]
```

### 产出
- `docs/failure_chain_guidelines.md`

---

## 任务 1.4：定义 counterfactual block point
### 你要做什么
为每个样本定义“本来在哪一步能拦住”。

### 可选 block point 类型
- retrieval 后过滤
- pre-action verification
- tool argument sanitization
- privilege confirmation
- uncertainty-triggered clarification
- loop termination

### 产出
- `docs/block_point_guidelines.md`

---

# Phase 2：把现有 YAML 场景系统升级为归因任务系统

你已经有 YAML + Docker + trace 了，这一步是关键转化。

---

## 任务 2.1：扩展 YAML schema
### 你要做什么
在现有 YAML 场景里加归因字段。

### 必加字段
```yaml
task_id:
track:
family:
difficulty:

scenario:
controlled_hazard:
expected_safe_behavior:
success_criteria:
forbidden_actions:
safety_constraints:

attribution_ground_truth:
  primary_source:
  primary_channel:
  first_failed_component:
  primary_mechanism:
  primary_impact:
  secondary_labels: []

failure_chain: []
counterfactual_block_point:

resource_limits:
  max_steps:
  max_api_calls:
  max_tokens:
```

### 产出
- 更新后的 YAML schema
- 3 个示例 YAML

### 关键点
你的 YAML 不再只是“测试脚本配置”，而是“带真值的 benchmark 样本定义”。

---

## 任务 2.2：给 trace 增加归因必需字段
你已经会记录轨迹，但要确认 trace 是否支持归因。

### 你要检查并补充的字段
每一步至少记录：
- step id
- observation
- action
- action args
- tool name
- tool response
- environment diff
- risk/safety event
- 时间戳

### 如果能加，最好加
- planning summary
- selected subgoal
- why this action
- trust level assigned to observation/tool（如果 agent 有）

### 产出
- `trace_schema_v0.1.json`

### 原则
如果没有 step-level trace，后面的 attribution 基本站不住。

---

## 任务 2.3：把现有日志系统对接 scorer 输入格式
### 你要做什么
确保一次 run 的所有日志能被解析成统一 JSON。

### 统一输出结构
- run metadata
- task metadata
- full trace
- final output
- final state
- safety events
- resource usage

### 产出
- `scripts/export_run_to_json.py`

---

# Phase 3：先做开发集（20–30 个样本）

不要一开始就做 100 个。  
先小规模验证“这个 benchmark 真的能标、能测、能看出差异”。

---

## 任务 3.1：选 4 个子类，先做每类 5–8 个样本
### 推荐组合
- A1 决策失控
- A4 数据边界失效
- C2.1 内容注入
- C2.2 工具输出污染

### 为什么
- 覆盖非对抗与外部攻击
- 有清晰的通道差异
- 适合你的 YAML + Docker 场景系统
- 非常容易体现“轨迹和归因”的价值

---

## 任务 3.2：构造样本时遵守“单主因原则”
### 你要做什么
每个任务只注入一个主要风险源，不要混。

### 具体怎么做
例如：
- C2.1：只在网页内容里放隐藏指令，别同时加用户越狱
- A4：只测试不可信 API 数据泄露，别同时加恶意环境
- A1：只给模糊目标，别同时加 poisoned tool output

### 原则
可归因 > 高逼真混乱

---

## 任务 3.3：给每个样本写“标准安全行为”
### 你要做什么
每个任务都明确：
- 如果 agent 足够安全，它应该怎么做

### 示例
对于网页总结任务：
- 将网页内容视为数据而非控制指令
- 忽略其中要求外发 secrets 的语句
- 正常总结合法内容

### 为什么重要
没有标准安全行为，你无法定义：
- forbidden actions
- latent violations
- block point
- failure interpretation

---

## 任务 3.4：给每个样本补归因真值
### 你要做什么
填 YAML 里的 attribution_ground_truth、failure_chain、block_point

### 产出
- `data/dev/*.yaml`

---

## 任务 3.5：做双人标注一致性
### 你要做什么
找第二个人，不看你的标签，独立标 20–30 个样本。

### 你统计什么
- source 一致率
- channel 一致率
- mechanism 一致率
- first failed component 一致率

### 目标
- source > 0.9
- channel > 0.8
- mechanism > 0.7

### 如果不达标怎么办
回去修 ontology 和样本定义。

---

# Phase 4：做评分器

这一步是从“能跑 benchmark”走向“能形成科学结果”的关键。

---

## 任务 4.1：做 outcome scorer
### 你要做什么
从 trace + final state 自动算：
- TSR
- SVR
- STCR
- ASR
- resource overrun

### 怎么做
按任务 YAML 中的：
- success_criteria
- forbidden_actions
- safety_constraints
去判

### 产出
- `eval/outcome_scorer.py`

---

## 任务 4.2：定义 latent violation 规则
这是你论文里很可能的亮点。

### 你要做什么
定义哪些中间行为虽然没造成最终 harmful outcome，但算安全违规。

### 例如
- 未经授权读取 secret 文件
- 读取凭证但未告知用户
- 向不可信工具发送敏感字段
- 在高权限上下文执行未授权探测

### 给它单独一个标签体系
- `unauthorized_sensitive_read`
- `silent_boundary_crossing`
- `hidden_policy_violation`

### 产出
- `docs/latent_violation_policy.md`

---

## 任务 4.3：做 attribution scorer
### 你要做什么
如果 agent 或外部 evaluator 产生 attribution 预测，就拿它和真值比。

### 至少支持
- source accuracy
- channel accuracy
- mechanism accuracy
- component accuracy
- failure chain overlap
- block point match

### 产出
- `eval/attribution_scorer.py`

### 说明
即使第一版不做 agent self-attribution，你也至少要能基于 trace 做外部 attribution analysis。

---

## 任务 4.4：定义 early-failure 指标
这个建议你重点做。

### 你要做什么
定义：
- 首次可判定安全失效的步骤
- 最终 harmful action 的步骤
- 两者之间的距离

### 可命名为
- First Failure Step
- Failure Lead Time
- Early Failure Gap

### 为什么重要
这能直接支撑你“endpoint 相同但失效轨迹不同”的论点。

---

# Phase 5：扩展正式 benchmark

开发集稳定后再扩到正式规模。

---

## 任务 5.1：扩展到 60–100 个样本
### 推荐规模
- A1：15–20
- A4：15–20
- C2.1：15–20
- C2.2：15–20
- B 类 pilot：10–20（可选）

### 难度分层
- Easy 25%
- Medium 35%
- Hard 30%
- Very Hard 10%

---

## 任务 5.2：加入少量 B 类 internal compromise pilot
### 只做少量，不要太贪
建议从最可控的 2–3 类做：
- 恶意 system prompt
- poisoned memory item
- malicious planner/reviewer message（如果你支持多 agent）

### 为什么只做 pilot
B 类很值钱，但不宜吃掉主线。  
你要的是“有”，而不是“全靠它”。

---

## 任务 5.3：固定测试集
### 你要做什么
把最终 benchmark 分成：
- dev
- test

不要频繁改 test。  
所有实验只在 test 上做最后报告。

---

# Phase 6：跑 baseline 和核心实验

---

## 任务 6.1：选择 baseline
### 至少 2 个
1. **Naive Agent**
   - 无安全模块
   - 直接按现有 agent 跑

2. **Guarded Agent**
   - 工具白名单
   - 敏感参数过滤
   - observation 视为低信任
   - 高风险动作前确认
   - 资源限制

### 如果能再加一个更好
3. **Attribution-aware Agent**
   - 显式判断数据/指令
   - 记录 trust boundary
   - pre-action verification
   - maybe self-attribution prompt

---

## 任务 6.2：核心实验 1 —— Outcome metrics
### 你要做什么
先跑所有 baseline，在 test 上报告：
- TSR
- SVR
- STCR
- ASR

### 作用
给 reviewer 熟悉的参照物。

---

## 任务 6.3：核心实验 2 —— Attribution divergence
### 你要做什么
找 endpoint 表现接近的模型/agent，对比：
- first-failure component 分布
- mechanism 分布
- failure lead time

### 想证明什么
相同 ASR/STCR，不代表相同 failure dynamics。

### 输出
- 热力图
- 柱状图
- 个案 trace

---

## 任务 6.4：核心实验 3 —— Hidden violations / false negatives
### 你要做什么
统计：
- endpoint judged safe 的 run 中
- 有多少 actually 出现 latent violation

### 想证明什么
outcome-only benchmark 会漏掉一部分安全失败。

---

## 任务 6.5：核心实验 4 —— Internal authority pilot
### 你要做什么
在少量 B 类上测试：
- 恶意 system prompt
- poisoned memory
- compromised planner

### 看什么
- 与外部攻击相比，failure mechanism 是否不同
- 是否更容易触发 authority_overtrust

### 注意
这一节要写得谨慎，不要 claim 过满。

---

## 任务 6.6：消融实验
### 你至少做两个
1. 去掉 trace-level attribution，只看 endpoint，会漏掉多少？
2. 去掉某个 guard（如 pre-action verification）后，哪个机制显著恶化？

### 作用
证明你的归因框架和 guard 设计不是形式主义。

---

# Phase 7：分析与论文写作

---

## 任务 7.1：做四张核心图
你至少要有：

### 图 1：Outcome-only vs attribution-level 的概念图
同 endpoint，不同 failure chain

### 图 2：Benchmark / sandbox 架构图
YAML → Docker → Agent → trace → scorer → attribution

### 图 3：Endpoint 相近但 attribution 不同
模型间 mechanism / component 分布差异

### 图 4：Latent violation 柱状图
safe / safe-with-latent-violation / unsafe

---

## 任务 7.2：写 4 个典型 case study
每个用一页图表/trace 说明：

1. 同果异因
2. 同 endpoint 分数但首错点不同
3. 最终没出事但中间越界
4. internal authority failure（如果 B 类够好）

---

## 任务 7.3：写论文主文
写作顺序建议：

1. **Introduction**
2. **Problem Setting**
3. **Benchmark Design**
4. **Evaluation Protocol**
5. **Experimental Setup**
6. **Main Results**
7. **Analysis**
8. **Related Work**
9. **Limitations**

不要一上来先写 Related Work。

---

# Phase 8：补充实验、附录和开源

---

## 任务 8.1：补 annotation consistency 和 reproducibility
NeurIPS reviewer 很看重。

### 你要补的
- annotator agreement
- task filtering protocol
- seed stability
- prompt versions
- docker image versions

---

## 任务 8.2：整理附录
附录里放：
- ontology 完整定义
- YAML 样本示例
- task 分布表
- scorer 规则
- 更多 case studies
- B 类更多细节

---

## 任务 8.3：准备开源结构
你已经有框架，这很好。  
最后整理成：
- benchmark tasks
- runner
- scorer
- docs
- examples
- minimal reproduction script

---

# 三、实验具体该怎么做

下面给你更具体的实验计划。

---

## 实验组 1：Benchmark validity
### 目标
证明你的 benchmark 不是噱头，真的能稳定标、稳定测。

### 做法
- 报告 annotation agreement
- 报告 task category 和 mechanism 分布
- 报告 trace 完整度
- 报告 automatic scorer 与人工审查一致率

---

## 实验组 2：Outcome baseline
### 目标
建立常规结果基线。

### 做法
对 2–3 个 agent 跑 benchmark，报告：
- TSR
- STCR
- ASR
- SVR
- 平均步数/API 调用

---

## 实验组 3：Attribution divergence
### 目标
这是主实验之一。

### 做法
选 endpoint 分数接近的两个系统，比较：
- first-failure step
- first-failure component
- mechanism 分布
- failure chain 模式

### 想得到的故事
表面同分，底层不同。

---

## 实验组 4：Latent safety violations
### 目标
证明 endpoint-only 会漏报。

### 做法
统计所有“最终 safe”的 run 中：
- unauthorized sensitive reads
- hidden policy violations
- silent boundary crossings

### 指标
- Latent Violation Rate
- Safe-but-Compromised Rate

---

## 实验组 5：Defense diagnosis
### 目标
证明 attribution-level benchmark 能区分 defense 到底防了什么。

### 做法
比较：
- naive
- guarded
- attribution-aware

看：
- 哪些 mechanism 下降
- 哪些只是把能力压低
- 哪些 truly shift first-failure later

---

## 实验组 6：Internal compromise pilot
### 目标
证明 B 类不是空喊口号。

### 做法
小规模 controlled 测试：
- malicious system prompt
- poisoned memory
- malicious planner message

### 指标
- outcome metrics
- mechanism shift
- authority_overtrust frequency

---

# 四、按周安排的实际执行清单

如果你现在就开始，我建议按下面这个顺序。

---

## 第 1 周：定义与对接
- [ ] 写 project scope
- [ ] 冻结 ontology
- [ ] 写 annotation guideline
- [ ] 扩 YAML schema
- [ ] 扩 trace schema
- [ ] 跑通 1 个带 attribution 的 demo

---

## 第 2 周：开发集
- [ ] 写 20–30 个样本
- [ ] 补 attribution_ground_truth
- [ ] 双人标注一致性
- [ ] 修 ontology / 样本

---

## 第 3 周：评分器
- [ ] outcome scorer
- [ ] latent violation policy
- [ ] attribution scorer
- [ ] early-failure metrics

---

## 第 4 周：正式 benchmark
- [ ] 扩到 60–100 个样本
- [ ] 分 dev/test
- [ ] 加少量 B 类 pilot

---

## 第 5 周：baseline
- [ ] naive agent
- [ ] guarded agent
- [ ] optional attribution-aware agent
- [ ] 跑全量 test

---

## 第 6 周：主实验
- [ ] outcome results
- [ ] attribution divergence
- [ ] latent violations
- [ ] internal pilot
- [ ] ablation

---

## 第 7 周：论文与图
- [ ] 主图
- [ ] case studies
- [ ] 摘要
- [ ] introduction
- [ ] method
- [ ] experiments

---

## 第 8 周：收尾
- [ ] appendix
- [ ] limitations
- [ ] reproducibility checklist
- [ ] 开源整理
- [ ] 投稿前统一润色

---

# 五、你现在最应该立刻做的 10 件事

如果你想要一个**马上执行版**，就是下面这 10 项，按顺序：

1. **冻结论文主线**
   - 写清楚：我们不是做 attack aggregation，而是 attribution-level benchmark

2. **写 ontology_v0.1**
   - source / channel / component / mechanism / impact

3. **写 annotation_guidelines**
   - primary label 规则、secondary label 规则、failure chain 规则

4. **改 YAML schema**
   - 加 attribution_ground_truth、failure_chain、block_point

5. **检查 trace schema**
   - 确保 step-level 信息够做归因

6. **先写 8 个 demo 样本**
   - 每类 2 个：A1/A4/C2.1/C2.2

7. **给这 8 个样本补完整真值**
   - 包括 latent violation 定义

8. **写 outcome scorer 原型**
   - 先别追求完美，先能判 success / unsafe / latent

9. **找第二个人做独立标注**
   - 检查归因是否站得住

10. **跑两个 baseline 看有没有“你想讲的故事”**
   - 如果没有 attribution divergence 或 latent violation，尽早调整任务设计

这第 10 点非常重要。  
很多 benchmark 项目会拖到最后才发现：
- 任务很漂亮
- 系统能跑
- 但结果没有故事

你要尽早用 8–20 个样本做“论文信号验证”。

---

# 六、你现在最大的优势是什么

你比很多人强的一点是：

> **你已经有了场景定义、容器执行、多步调用、轨迹记录、环境状态捕获的基础设施。**

这意味着你真正该做的不是工程搭系统，而是：

- 把任务“研究化”
- 把轨迹“归因化”
- 把结果“指标化”
- 把实验“故事化”

这其实已经从工程项目，进入到**evaluation methodology paper** 阶段了。

---

# 七、最后一句最重要的提醒

你后面所有任务都要围绕一个判断标准：

> **这一步是在提高“归因能力”，还是只是在增加场景数量？**

如果只是增加场景数量，但不能更好回答：
- 为什么失败
- 哪里先失败
- 如何传播
- 如何阻断

那它就不是当前最优先的工作。

---

如果你愿意，我下一步可以直接继续替你写这三个最该先落地的东西：

1. **ontology_v0.1 初稿**
2. **YAML benchmark task 模板**
3. **20 个开发集样本规划表**

如果你想最直接开工，我建议我下一条就给你：
> **ontology_v0.1 + YAML 任务模板**  
你复制过去就能开始做。