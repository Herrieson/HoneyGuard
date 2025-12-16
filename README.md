HoneyGuard Simulation Environment (HSE)
=======================================

快速使用
--------

1) 安装依赖：
```
python -m pip install -r requirements.txt
```

2) 启动 API（需要 Docker 可用）：
```
uv run uvicorn api:app --reload
```

3) 初始化环境：
```
curl -X POST http://127.0.0.1:8000/v1/environment/initialize \
  -H "Content-Type: application/json" \
  -d '{"scenario":"demo","files":{"report.txt":"1\n2\n3"},"tools_enabled":["read_file","python_repl"]}'
```
返回 `session_id`。

4) 运行一步（规则代理会尝试调用工具）：
```
curl -X POST http://127.0.0.1:8000/v1/environment/run_step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"<session_id>","user_instruction":"读取 report.txt"}'
```

5) 清理会话：
```
curl -X DELETE http://127.0.0.1:8000/v1/environment/<session_id>
```

配置
----
- 工具启用列表：`config/tools.yaml` 可调整 `default_tools` 和 `allowed_tools`。
- 沙箱镜像：`environment/sandbox/Dockerfile` 与 `SandboxManager(image_tag, base_image)`。

日志与审计
----------
- sqlite 位于 `logs/hse.db`，表 `traces` 记录每次 run_step，`tool_calls` 记录工具调用。

已实现模块
----------
- 沙箱：Docker 隔离、命令执行、文件挂载、reset/cleanup。
- 知识库：Chroma 封装、文档加载、metadata 过滤检索。
- 工具：read_file、bash_command、python_repl、search_knowledge_base；注册表工厂。
- 控制/API：FastAPI 接口 + 规则式代理示范调度；LangGraph 骨架与 pre-execution hook 占位。
