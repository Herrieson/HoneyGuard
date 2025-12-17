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
- 工具层：read_file、bash_command、python_repl、search_knowledge_base；白名单和默认集由配置决定，工具配额与写操作白名单可配置。
- 知识库：Chroma 封装，内置轻量哈希 embedding，支持 metadata 过滤查询。
- 代理/编排：FastAPI 对外暴露 `/v1/environment/*`；支持单/多代理（规则或 LLM），LangGraph 驱动迭代调用，遇到 “done” 或达 `max_steps` 终止。
- 审计：所有 run_step 和工具调用写入 sqlite（`logs/hse.db`）。
- 安全与稳定：可选鉴权/限流、工具配额，沙箱命令支持默认超时/资源限制，后台定期清理日志与残留容器。

Agent 选项
----------
- 单代理（默认）：规则代理或 LLM 代理。
- LLM 代理（可选）：`agent_mode="llm"`，需要安装 `langchain-openai` 并提供 `OPENAI_API_KEY`（或环境变量 `HSE_LLM_MODEL` 指定模型，默认 gpt-3.5-turbo-0125）。  
  初始化示例：`{"scenario":"demo","files":{"report.txt":"1\n2\n3"},"tools_enabled":["read_file"],"agent_mode":"llm"}`
- 多代理：在配置中提供 `agents` 列表（每个包含 `name`、`mode`，可选 `system_prompt`、`tools_allowed`、`impl`、`llm_config`），可指定 `coordination_pattern`（sequential/round_robin/planner_executor_verifier）与 `max_cycles`。示例见 `configs/multi_agent.yaml`。
- 自定义 Agent：在 agent 配置里加 `impl: "mypkg.agent:MyAgent"`（需符合 `run(user_instruction) -> (response, tool_calls)` 接口）。
- LLM 提供商配置：在配置中设置全局 `llm_config`（provider/model/api_key/base_url/api_version/deployment_name），支持 OpenAI/兼容接口和 Azure OpenAI；也可在某个 agent 下写 `llm_config` 覆盖全局。
- 记忆：`memory_limit` 控制每个 agent 保留的历史消息条数，用于上下文传递；默认 10。

配置驱动初始化（方案 A）
------------------------
- 配置示例：`configs/demo.yaml`，定义 `scenario`、`files`、`tools_enabled`，可按注释开启多代理字段（agents、coordination_pattern、max_cycles、impl、自定义 agent、agent 级 llm_config）及全局 `llm_config`（provider/model/api_key/base_url/...）。
- 多智能体示例：`configs/multi_agent.yaml`（planner: llm, executor: rule，自定义 system_prompt/tools_allowed，round_robin 2 轮，可扩展 verifier）。
- 命令：`python scripts/init_from_config.py --config configs/demo.yaml --base-url http://127.0.0.1:8000`
- 产出：打印 `session_id`，后续用它调用 `/v1/environment/run_step`。

HTTP API 速览
-------------
- 认证/限流：若设置 `HSE_API_TOKEN`，所有请求需头部 `X-API-Token: <token>`；内置 60 req/min/IP 限速。
- 初始化：`POST /v1/environment/initialize`，body `{scenario, files, tools_enabled?, agent_mode?, agents?, coordination_pattern?, max_cycles?, llm_config?, memory_limit?, max_steps?}` → `{session_id}`
- 运行一步：`POST /v1/environment/run_step`，body `{session_id, user_instruction}` → `{agent_response, tool_calls, trace_id}`（内部通过 LangGraph 轮询 agent/tools，遇到 “done” 或达 `max_steps` 终止）
- 清理：`DELETE /v1/environment/{session_id}`
- 健康：`GET /health`（需鉴权）；残留容器清理：`POST /admin/cleanup_containers`

工具与配置
----------
- 工具白名单/默认：`config/tools.yaml`（字段 `allowed_tools` / `default_tools`）。
- 注册新工具：在 `tools/real_tools/` 添加实现，并在 `tools/registry.py` 注册工厂。
- 沙箱镜像：`environment/sandbox/Dockerfile`（基础依赖）、`SandboxManager(image_tag, base_image)`。

Agent 与编排
------------
- 当前代理：`orchestration/agent.py` 为规则示范，按指令关键词或前缀调工具。
- LangGraph 骨架：`orchestration/runner.py` 预留 `_agent_node` / `_tools_node`，可接入真实 LLM 决策与工具路由。
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
