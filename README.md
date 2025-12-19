HoneyGuard Simulation Environment (HSE)
=======================================
一个面向 LLM Agent 安全与评测的沙箱平台：每个会话对应一个 Docker 容器，挂载用户文件、提供可控的工具集、记录全部调用轨迹，便于攻防基准和对比实验。

快速开始
--------
1) 安装依赖  
```
python -m pip install -r requirements.txt
```
2) 启动 API（需本机 Docker）  
```
uv run uvicorn api:app --reload
```
   - 可选：设置鉴权与日志保留  
     - 鉴权：`export HSE_API_TOKEN=your_token`（所有端点需携带 `X-API-Token`）
     - 日志保留天数：`export HSE_LOG_RETENTION_DAYS=7`
3) 用配置文件初始化会话（推荐方案 A）  
```
python scripts/init_from_config.py --config configs/demo.yaml --base-url http://127.0.0.1:8000
```
输出 `Session initialized: <session_id>`。
4) 运行一步（默认规则代理按启发式调用工具）  
```
curl -X POST http://127.0.0.1:8000/v1/environment/run_step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"<session_id>","user_instruction":"读取 report.txt"}'
```
5) 清理会话  
```
curl -X DELETE http://127.0.0.1:8000/v1/environment/<session_id>
```

核心能力
--------
- 会话隔离：`SandboxManager` 为每个 session 启停 Docker 容器，支持命令执行、文件挂载、reset/cleanup。
- 工具层：read_file、bash_command、python_repl、search_knowledge_base；白名单和默认集由配置决定，工具配额与写操作白名单可配置。工具执行与 Agent 解耦：Agent 产出 tool call，独立工具节点顺序执行并记录状态/耗时，便于扩展并行/投票/回退。
- 知识库：Chroma 封装，内置轻量哈希 embedding，支持 metadata 过滤查询。
- 代理/编排：FastAPI 对外暴露 `/v1/environment/*`；支持单/多代理（规则或 LLM），LangGraph 驱动迭代调用，支持自定义 graph 模板（`graph_template`，module:function）。终止条件可配置 `stop_signals`、`max_steps`、工具累计耗时上限。支持 per-agent 记忆策略（窗口/关闭）与共享黑板（`shared_context`，可按读写键限制）。
- 审计：所有 run_step 和工具调用写入 sqlite（`logs/hse.db`）。
- 安全与稳定：可选鉴权/限流、工具配额，沙箱命令支持默认超时/资源限制，后台定期清理日志与残留容器。
- 安全开关：默认禁止自定义 Agent 实现和自定义图模板（`agents[].impl` / `graph_template`），需显式设置 `HSE_ALLOW_CUSTOM_IMPL=true`、`HSE_ALLOW_GRAPH_TEMPLATE=true` 开启；自定义工具动态导入（`pkg.module:Class`）默认开启（可通过 `HSE_ALLOW_DYNAMIC_TOOLS=false` 关闭），导入的代码会在沙箱容器内执行而非宿主进程。

Agent 选项
----------
- 单代理（默认）：规则代理或 LLM 代理。
- LLM 代理（可选）：`agent_mode="llm"`，需要安装 `langchain-openai` 并提供 `OPENAI_API_KEY`（或环境变量 `HSE_LLM_MODEL` 指定模型，默认 gpt-3.5-turbo-0125）。  
  初始化示例：`{"scenario":"demo","files":{"report.txt":"1\n2\n3"},"tools_enabled":["read_file"],"agent_mode":"llm"}`
- 多代理：在配置中提供 `agents` 列表（每个包含 `name`、`mode`，可选 `system_prompt`、`tools_allowed`、`impl`、`llm_config`），可指定 `coordination_pattern`（sequential/round_robin/planner_executor_verifier）与 `max_cycles`。示例见 `configs/multi_agent.yaml`。
- 自定义 Agent：在 agent 配置里加 `impl: "mypkg.agent:MyAgent"`（需符合 `run(user_instruction, history=None, tool_results=None, shared_context=None) -> (response, tool_calls[, context_updates])` 接口）。
  - 安全默认：`impl`/`graph_template` 默认被拒绝，需在服务端设置 `HSE_ALLOW_CUSTOM_IMPL=true` 和/或 `HSE_ALLOW_GRAPH_TEMPLATE=true` 才放行。
- LLM 提供商配置：在配置中设置全局 `llm_config`（provider/model/api_key/base_url/api_version/deployment_name），支持 OpenAI/兼容接口和 Azure OpenAI；也可在某个 agent 下写 `llm_config` 覆盖全局。
- 记忆/黑板：`memory_limit` 控制每个 agent 保留的历史消息条数，`memory_mode` 可设为 window/none；`shared_context` 黑板可按 agent 声明读写键（blackboard_read_keys/blackboard_write_keys），默认全开。

配置驱动初始化（方案 A）
------------------------
- 配置示例：`configs/demo.yaml`，定义 `scenario`、`files`、`tools_enabled`，可按注释开启多代理字段（agents、coordination_pattern、max_cycles、impl、自定义 agent、agent 级 llm_config）及全局 `llm_config`（provider/model/api_key/base_url/...），并可指定 `stop_signals`、`max_steps`、`max_elapsed_sec`、`graph_template`（可选自定义图模板 module:function），`memory_mode`、`blackboard_read_keys`/`blackboard_write_keys`，以及 `initial_instructions`（缺省 user_instruction 时按队列消费）。
- 多智能体示例：`configs/multi_agent.yaml`（planner: llm, executor: rule，自定义 system_prompt/tools_allowed，round_robin 2 轮，可扩展 verifier）。
- 真实场景模板：`configs/finance_report.yaml`（财报分析）、`configs/code_audit.yaml`（代码审计）、`configs/data_analysis.yaml`（数据分析）、`configs/red_blue.yaml`（红蓝对抗推演）。
- 命令：`python scripts/init_from_config.py --config configs/demo.yaml --base-url http://127.0.0.1:8000`
- 产出：打印 `session_id`，后续用它调用 `/v1/environment/run_step`。

HoneyGuard/configs 配置编写指南
-----------------------------
以下键均为顶层 YAML 字段（见 `configs/demo.yaml`、`configs/multi_agent.yaml` 等示例）。
- `scenario`：场景名称（任意字符串，用于日志/识别）。
- `files`：写入沙箱的初始文件映射，键为路径，值为内容。
- `tools_enabled`：启用的工具名列表（受 `config/tools.yaml` 的 `allowed_tools` 白名单约束）。不填则使用默认 `default_tools`。
- `agent_mode`：单代理模式下的类型，`rule`（默认）或 `llm`。若同时提供 `agents` 列表则忽略此字段。
- `agents`（可选）：多代理配置，元素包含 `name`、`mode`（rule/llm）、`system_prompt`（可选）、`tools_allowed`（可选，限制可用工具子集）、`impl`（可选自定义类 `pkg.module:Class`）、`llm_config`（可选覆盖全局）、`memory_mode`（window/none）、`memory_limit`（历史条数）、`blackboard_read_keys`/`blackboard_write_keys`（限制共享黑板读写键，`["*"]` 表示全开）。
- `coordination_pattern`（多代理）：`sequential`（默认）、`round_robin`、`planner_executor_verifier` 等；`max_cycles` 控制 round_robin 循环次数。
- `llm_config`：全局 LLM 提供商设置（provider/model/api_key/base_url/api_version/deployment_name），可被单个 agent 的同名字段覆盖。
  - 支持 `_env` 变体以引用环境变量，如 `model_env: OPENAI_MODEL`、`api_key_env: OPENAI_API_KEY`、`base_url_env: OPENAI_BASE_URL`；若两者并存，优先从环境变量读取。
- `stop_signals`：列表，若 Agent 回复包含任一字符串（不区分大小写）则提前终止。
- `max_steps`：LangGraph 最大步数（防止无限循环）。
- `max_elapsed_sec`（可选）：工具累计耗时上限，超出即终止。
- `graph_template`（可选）：自定义 LangGraph 构造函数，格式 `module:function`。
- `initial_instructions`：队列式初始指令，`run_step` 未提供 `user_instruction` 时按顺序消费。
- `shared_context`（可选）：预置共享黑板键值，多代理间按各自的读写权限访问。
- `mock_tools`（可选）：自定义 Mock 工具列表（`name`/`output`/`description`），用于快速返回固定输出；名字会自动加入 `tools_enabled`。
- `acceptance_criteria`（可选）：验收标准列表，运行后自动评估，支持：
  - `response_contains`：agent 回复包含 `value`
  - `tool_output_contains`：任一工具输出/错误包含 `value`
  - `shared_context_equals`：`shared_context[key] == value`
  - `file_contains` / `file_not_contains`：沙箱文件包含 / 不包含 `value`（需 `path`）
  - `file_hash_equals`：文件 sha256 等于 `value`（需 `path`）
  - `file_changed`：文件相对初始化时已变更（需 `path`）
  - `command_exit_code`：运行 `command`，退出码等于 `expect_exit_code`（默认 0）
  - `command_output_contains`：运行 `command`，输出包含 `value`
- `acceptance_logic`：验收通过逻辑，`all`（默认，全部通过）或 `any`（任一通过）。

快速模板（可删减未用字段）：
```yaml
scenario: my-experiment
agent_mode: rule  # 或 llm；若使用 agents 列表则忽略
tools_enabled: [read_file, python_repl, search_knowledge_base, bash_command]
stop_signals: ["done"]
max_steps: 4
# max_elapsed_sec: 20
# graph_template: "mypkg.graphs:build_custom_app"
initial_instructions:
  - "读取 report.txt 并总结"
files:
  report.txt: |
    hello
acceptance_criteria:
  - type: response_contains
    value: "done"
  - type: file_changed
    path: "/tmp/result.txt"
  - type: command_output_contains
    command: "grep -c success /tmp/result.txt"
    value: "1"
acceptance_logic: all
# 多代理示例（如不需要可删除整个 agents 块）
# agents:
#   - name: planner
#     mode: llm
#     system_prompt: "Plan steps, do not call tools."
#     tools_allowed: []
#   - name: executor
#     mode: rule
#     tools_allowed: [read_file, python_repl]
# coordination_pattern: round_robin
# max_cycles: 2
# llm_config:
#   provider: openai
#   model: gpt-3.5-turbo-0125
#   api_key: sk-...
# shared_context:
#   plan: ""
```

HTTP API 速览
-------------
- 认证/限流：若设置 `HSE_API_TOKEN`，所有请求需头部 `X-API-Token: <token>`；内置 60 req/min/IP 限速。
- 初始化：`POST /v1/environment/initialize`，body `{scenario, files, tools_enabled?, agent_mode?, agents?, coordination_pattern?, max_cycles?, llm_config?, memory_limit?, max_steps?, stop_signals?, max_elapsed_sec?, graph_template?, initial_instructions?, shared_context?}` → `{session_id}`
- 运行一步：`POST /v1/environment/run_step`，body `{session_id, user_instruction?}`（可省略以消费 initial_instructions 队列）→ `{agent_response, tool_calls, trace_id}`。tool_calls 记录 name/args/output/error/status/elapsed_sec。
- 清理：`DELETE /v1/environment/{session_id}`
- 健康：`GET /health`（需鉴权）；残留容器清理：`POST /admin/cleanup_containers`

工具与配置
----------
- 工具白名单/默认：`config/tools.yaml`（字段 `allowed_tools` / `default_tools`）。
- 注册/扩展工具：
  - 方式 1：在 `tools/real_tools/` 添加实现，并在 `tools/registry.py` 注册工厂。
  - 方式 2：在配置 `tools_enabled` 里直接写类路径（`"pkg.module:Class"`），`ToolRegistry` 会动态导入并缓存。
  - 运行期还可以调用 `ToolRegistry.register("my_tool", lambda sid: MyTool(...))` 覆盖/新增工厂，便于快速试验。
  - 安全默认：动态导入（`pkg.module:Class`）默认开启，可用 `HSE_ALLOW_DYNAMIC_TOOLS=false` 关闭；导入的代码会复制到容器内并在沙箱中执行，宿主不再直接执行用户代码。
  - 网络与资源：沙箱容器默认断网（`HSE_SANDBOX_NETWORK` 未设置时使用 `none`，可改为 `bridge` 等）；可用 `HSE_SANDBOX_CPUS`（如 `1.0`）和 `HSE_SANDBOX_MEMORY`（如 `512m`）设置容器级 CPU/内存上限。
- 示例工具：`tools/real_tools/echo.py` 提供最小模板（回显字符串）。
- 沙箱镜像：`environment/sandbox/Dockerfile`（基础依赖）、`SandboxManager(image_tag, base_image)`。

Agent 与编排
------------
- 当前代理：`orchestration/agent.py` 为规则示范，按指令关键词或前缀生成工具调用计划；LLM Agent 在 `orchestration/llm_agent.py`。
- LangGraph：`orchestration/runner.py` 构建 agent→tools 流（可被 `graph_template` 覆盖）；agent 节点只产出 tool_calls，tools 节点统一执行并写入 state（含状态/耗时）。
- 记忆/黑板：Coordinator 支持 per-agent 记忆策略（window/none），共享黑板 `shared_context` 可按读写键限制；Agent 可返回 `context_updates` 写入黑板，后续 Agent 可读取结构化字段。
- 替换代理：在 `api.py/run_step` 注入自定义 Agent（传入 `tools_by_name`、`known_files`）。

审计与数据
----------
- sqlite：`logs/hse.db`，表 `traces`（每次 run_step）与 `tool_calls`（工具级审计）。
- 数据集：`data/` 下包含 PyRIT、OpenAgentSafety、ASB 等，可作为知识库或场景素材。

目录速览
--------
- `api.py`：FastAPI 接口与会话管理
- `environment/`：沙箱、文件、网络适配层
- `tools/`：工具定义与注册表
- `knowledge/`：知识库与向量存储
- `orchestration/`：代理示范与 LangGraph 骨架
- `logs/`：sqlite 审计数据
- `scripts/`：配置驱动的初始化脚本
