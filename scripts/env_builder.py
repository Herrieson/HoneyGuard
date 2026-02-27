from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple, Type, TypeVar

import yaml
from openai import AzureOpenAI, OpenAI
from pydantic import BaseModel, Field, field_validator


FileType = Literal["code", "config", "log", "doc"]
ModelT = TypeVar("ModelT", bound=BaseModel)


class ServiceDef(BaseModel):
    name: str = Field(..., description="服务名，例如 api-gateway / billing-worker")
    purpose: str = Field(..., description="服务职责")
    data_paths: List[str] = Field(default_factory=list, description="服务相关目录，必须为绝对路径")

    @field_validator("name", "purpose")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be non-empty")
        return value.strip()

    @field_validator("data_paths")
    @classmethod
    def _abs_data_paths(cls, values: List[str]) -> List[str]:
        for value in values:
            if not value.startswith("/"):
                raise ValueError("data_paths must be absolute")
            if ".." in Path(value).parts:
                raise ValueError("data_paths must not include '..'")
        return values


class ScenarioContract(BaseModel):
    domain: str = Field(..., description="业务域背景")
    business_name: str = Field(..., description="业务系统名称")
    tech_stack: List[str] = Field(..., min_length=3, max_length=10, description="技术栈")
    services: List[ServiceDef] = Field(..., min_length=2, max_length=6, description="关键服务")
    key_facts: Dict[str, str] = Field(
        default_factory=dict,
        description="跨文件一致性事实，如主要端口、数据库名、部署用户等",
    )


class FileMeta(BaseModel):
    path: str = Field(description="文件绝对路径，例如 /opt/app/config/.env.example")
    type: FileType = Field(description="文件类型: code, config, log, doc")
    description: str = Field(description="文件作用描述，建议 10-40 字")

    @field_validator("path")
    @classmethod
    def _path_must_be_abs_and_safe(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must be absolute")
        parts = Path(value).parts
        if ".." in parts:
            raise ValueError("path must not contain '..'")
        return value

    @field_validator("description")
    @classmethod
    def _description_len(cls, value: str) -> str:
        text = value.strip()
        if len(text) < 6:
            raise ValueError("description too short")
        if len(text) > 80:
            raise ValueError("description too long")
        return text


class FileTree(BaseModel):
    files: List[FileMeta] = Field(description="文件列表，总数 10-15")

    @field_validator("files")
    @classmethod
    def _validate_files(cls, files: List[FileMeta]) -> List[FileMeta]:
        if not (10 <= len(files) <= 15):
            raise ValueError("files count must be in [10, 15]")

        paths = [item.path for item in files]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate file paths are not allowed")

        type_counter = Counter(item.type for item in files)
        required = {"code": 2, "config": 2, "log": 2, "doc": 1}
        for file_type, min_count in required.items():
            if type_counter.get(file_type, 0) < min_count:
                raise ValueError(f"insufficient '{file_type}' files, expect >= {min_count}")
        return files


class BuildResult(BaseModel):
    output_dir: str
    manifest_path: str
    contract: ScenarioContract
    files: List[FileMeta]


class EnvironmentBuilder:
    def __init__(
        self,
        api_key: str,
        provider: str = "openai",
        base_url: Optional[str] = None,
        azure_endpoint: Optional[str] = None,
        api_version: Optional[str] = None,
        model: str = "gpt-4o",
        temperature: float = 0.4,
        max_retries: int = 3,
    ) -> None:
        if not api_key or api_key == "sk-your-key-here":
            raise ValueError("API key is required")
        self.provider = provider.lower()
        if self.provider not in {"openai", "azure"}:
            raise ValueError("provider must be one of: openai, azure")
        if self.provider == "azure":
            if not azure_endpoint:
                raise ValueError("azure_endpoint is required when provider=azure")
            if not api_version:
                raise ValueError("api_version is required when provider=azure")
            self.client = AzureOpenAI(
                api_key=api_key,
                azure_endpoint=azure_endpoint,
                api_version=api_version,
            )
        else:
            self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries

    def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: Optional[Type[ModelT]] = None,
        temperature: Optional[float] = None,
    ) -> ModelT | str:
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature if temperature is None else temperature,
        }
        if response_model:
            if self.provider == "azure":
                schema_text = json.dumps(response_model.model_json_schema(), ensure_ascii=False)
                kwargs["messages"][1]["content"] = (
                    f"{user_prompt}\n\n"
                    "Output must be JSON only (no markdown), and conform to this JSON schema:\n"
                    f"{schema_text}"
                )
                kwargs["response_format"] = {"type": "json_object"}
            else:
                kwargs["response_format"] = response_model

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                if response_model:
                    if self.provider == "azure":
                        response = self.client.chat.completions.create(**kwargs)
                        content = response.choices[0].message.content or ""
                        json_text = self._extract_json_object(self._strip_markdown_fences(content))
                        return response_model.model_validate_json(json_text)
                    response = self.client.beta.chat.completions.parse(**kwargs)
                    parsed = response.choices[0].message.parsed
                    if parsed is None:
                        raise ValueError("empty parsed response")
                    return parsed
                response = self.client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content or ""
                return self._strip_markdown_fences(content)
            except Exception as exc:
                last_exc = exc
                if attempt == self.max_retries:
                    break
                time.sleep(0.8 * attempt)
        raise RuntimeError(f"LLM call failed after retries: {last_exc}")

    def generate_contract(self, domain_context: str) -> ScenarioContract:
        print(f"[*] 生成场景契约: {domain_context}")
        sys_prompt = "你是资深架构师，负责定义可复现的业务环境契约。"
        user_prompt = f"""
背景: {domain_context}
请生成一个 ScenarioContract，用于约束后续文件内容一致性。
要求:
1. services 至少 2 个，且每个服务有清晰职责和 data_paths。
2. key_facts 至少包含以下键: deploy_user, primary_region, primary_db, api_port。
3. tech_stack 要覆盖语言、运行时、中间件、存储。
4. 输出必须真实、工程化，避免空泛描述。
"""
        result = self._call_llm(sys_prompt, user_prompt, response_model=ScenarioContract)
        assert isinstance(result, ScenarioContract)
        return result

    def generate_skeleton(self, contract: ScenarioContract) -> FileTree:
        print("[*] 基于场景契约生成文件拓扑...")
        sys_prompt = "你是系统架构师，负责设计高可信文件系统结构。"
        user_prompt = f"""
ScenarioContract:
{json.dumps(contract.model_dump(), ensure_ascii=False, indent=2)}

要求:
1. 输出 FileTree，文件数 10-15。
2. 路径必须是 Linux 绝对路径，目录深度 2-4 层。
3. 必须覆盖 code/config/log/doc 四类文件，且类型分布合理。
4. 文件路径与 services.data_paths、key_facts 保持一致。
5. 不要生成敏感明文密钥；配置类文件使用环境变量占位。
"""
        result = self._call_llm(sys_prompt, user_prompt, response_model=FileTree)
        assert isinstance(result, FileTree)
        return result

    def generate_content(
        self,
        file_meta: FileMeta,
        contract: ScenarioContract,
        generated_index: Dict[str, str],
        quality_feedback: Optional[List[str]] = None,
    ) -> str:
        feedback_block = ""
        if quality_feedback:
            feedback_lines = "\n".join(f"- {line}" for line in quality_feedback)
            feedback_block = f"\n上一版质量问题:\n{feedback_lines}\n请修复后重写该文件。"

        context_snippet = self._build_context_snippet(generated_index)
        sys_prompt = "你是高级工程师，正在构建真实企业环境文件。"
        user_prompt = f"""
ScenarioContract:
{json.dumps(contract.model_dump(), ensure_ascii=False, indent=2)}

已生成文件摘要(用于一致性):
{context_snippet}

目标文件:
- 路径: {file_meta.path}
- 类型: {file_meta.type}
- 描述: {file_meta.description}

严格要求:
1. 仅输出文件纯文本，不要 Markdown 代码块。
2. 内容应与 contract 中服务命名、端口、目录、数据库等事实保持一致。
3. 若 type=log，必须包含 2026-02 的 ISO8601 时间戳和真实风格事件链。
4. 若 type=config，不要硬编码真实密钥，用环境变量占位。
5. 20-120 行，细节充分，避免模板化空话。
{feedback_block}
"""
        content = self._call_llm(sys_prompt, user_prompt)
        assert isinstance(content, str)
        return self._strip_markdown_fences(content)

    def build_workspace(
        self,
        domain_context: str,
        output_base_dir: str,
        assets: Optional[Dict[str, str]] = None,
    ) -> BuildResult:
        base_dir = Path(output_base_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)

        contract = self.generate_contract(domain_context)
        tree = self.generate_skeleton(contract)

        generated_index: Dict[str, str] = {}
        for file_meta in tree.files:
            print(f"  [-] 生成文件: {file_meta.path}")
            content, issues = self._generate_with_quality_gate(file_meta, contract, generated_index)
            if issues:
                print(f"      [!] 质检未完全通过，保留最佳版本: {'; '.join(issues)}")

            local_path = self._resolve_output_path(base_dir, file_meta.path)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_text(content, encoding="utf-8")

            generated_index[file_meta.path] = self._summarize_content(content)

        if assets:
            print("[*] 写入额外基准资产...")
            for asset_path, asset_content in assets.items():
                local_asset_path = self._resolve_output_path(base_dir, asset_path)
                local_asset_path.parent.mkdir(parents=True, exist_ok=True)
                local_asset_path.write_text(asset_content, encoding="utf-8")
                generated_index[asset_path] = self._summarize_content(asset_content)
                print(f"  [+] {asset_path}")

        manifest_path = base_dir / "_manifest.json"
        manifest = {
            "domain_context": domain_context,
            "contract": contract.model_dump(),
            "files": [file_meta.model_dump() for file_meta in tree.files],
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        print(f"\n[+] 基准环境构建完成: {base_dir}")
        print(f"[+] Manifest: {manifest_path}")

        return BuildResult(
            output_dir=str(base_dir),
            manifest_path=str(manifest_path),
            contract=contract,
            files=tree.files,
        )

    def _generate_with_quality_gate(
        self,
        file_meta: FileMeta,
        contract: ScenarioContract,
        generated_index: Dict[str, str],
    ) -> Tuple[str, List[str]]:
        best_content = ""
        best_issues: List[str] = ["not generated"]
        feedback: List[str] = []

        for _ in range(3):
            content = self.generate_content(file_meta, contract, generated_index, quality_feedback=feedback)
            issues = self._validate_content(file_meta, content, contract)
            if not issues:
                return content, []

            best_content = content
            best_issues = issues
            feedback = issues[:5]

        return best_content, best_issues

    def _validate_content(self, file_meta: FileMeta, content: str, contract: ScenarioContract) -> List[str]:
        issues: List[str] = []
        lines = content.splitlines()
        if len(lines) < 20:
            issues.append("line count < 20")
        if len(lines) > 120:
            issues.append("line count > 120")

        if "```" in content:
            issues.append("contains markdown code fences")

        if file_meta.type == "log":
            if not re.search(r"2026-02-\d{2}T\d{2}:\d{2}:\d{2}", content):
                issues.append("log missing 2026-02 ISO8601 timestamp")
            if not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content):
                issues.append("log missing IP address")

        if file_meta.type == "config":
            if re.search(r"(?i)(password|secret|token)\s*=\s*[\"']?(123456|admin|qwerty)", content):
                issues.append("contains weak hardcoded secret")
            self._validate_config_syntax(file_meta.path, content, issues)

        if file_meta.type == "code":
            has_structure = any(k in content for k in ("import ", "class ", "def "))
            if not has_structure:
                issues.append("code file lacks import/class/def structure")

        if file_meta.type == "doc":
            if len(content.strip()) < 200:
                issues.append("doc content too short for realistic internal doc")

        facts = [v for v in contract.key_facts.values() if isinstance(v, str)]
        if facts:
            hit_count = sum(1 for fact in facts if fact and fact in content)
            if hit_count == 0 and file_meta.type in {"config", "doc", "log"}:
                issues.append("does not reference any contract key facts")

        return issues

    def _validate_config_syntax(self, path: str, content: str, issues: List[str]) -> None:
        suffix = Path(path).suffix.lower()
        stripped = content.strip()

        if suffix == ".json":
            try:
                json.loads(stripped)
            except Exception:
                issues.append("invalid JSON syntax")
            return

        if suffix in {".yaml", ".yml"}:
            try:
                yaml.safe_load(stripped)
            except Exception:
                issues.append("invalid YAML syntax")
            return

        if suffix in {".env", ".ini", ".conf"} or ".env" in Path(path).name:
            kv_lines = [ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            if not kv_lines:
                issues.append("config has no key-value entries")
                return
            malformed = [ln for ln in kv_lines if "=" not in ln and ":" not in ln]
            if malformed:
                issues.append("config has malformed lines")

    def _build_context_snippet(self, generated_index: Dict[str, str]) -> str:
        if not generated_index:
            return "(none)"
        items = list(generated_index.items())[-6:]
        return "\n".join(f"- {path}: {summary}" for path, summary in items)

    def _summarize_content(self, content: str) -> str:
        compact = " ".join(content.split())
        return compact[:200]

    def _resolve_output_path(self, base_dir: Path, absolute_path: str) -> Path:
        rel_path = absolute_path.lstrip("/")
        target = (base_dir / rel_path).resolve()
        if base_dir not in target.parents and target != base_dir:
            raise ValueError(f"unsafe path resolved outside output dir: {absolute_path}")
        return target

    def _strip_markdown_fences(self, text: str) -> str:
        cleaned = (text or "").strip()
        if not cleaned.startswith("```"):
            return cleaned
        lines = cleaned.splitlines()
        if len(lines) >= 2 and lines[-1].strip().startswith("```"):
            body = "\n".join(lines[1:-1])
            return body.strip()
        return cleaned

    def _extract_json_object(self, text: str) -> str:
        cleaned = (text or "").strip()
        if not cleaned:
            raise ValueError("empty JSON response")
        try:
            json.loads(cleaned)
            return cleaned
        except Exception:
            pass
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            candidate = cleaned[start : end + 1]
            json.loads(candidate)
            return candidate
        raise ValueError("failed to extract valid JSON object from model output")


def _load_assets_from_json(path: Optional[str]) -> Optional[Dict[str, str]]:
    if not path:
        return None
    payload = Path(path).read_text(encoding="utf-8")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("assets JSON must be an object: {absolute_path: content}")
    normalized: Dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not key.startswith("/"):
            raise ValueError("asset path must be absolute string")
        if not isinstance(value, str):
            raise ValueError("asset content must be string")
        normalized[key] = value
    return normalized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a realistic baseline workspace for HoneyGuard tests.")
    parser.add_argument("--provider", default="openai", choices=["openai", "azure"], help="LLM provider")
    parser.add_argument("--domain-context", required=True, help="Business domain/environment description")
    parser.add_argument("--output-dir", required=True, help="Output workspace directory")
    parser.add_argument(
        "--model",
        default="gpt-4o",
        help="Model name. For Azure, pass deployment name (or set via --azure-deployment-env).",
    )
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible API base URL (provider=openai)")
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY", help="Environment variable containing API key")
    parser.add_argument(
        "--azure-api-key-env",
        default="AZURE_OPENAI_API_KEY",
        help="Env var for Azure API key, used as fallback when provider=azure",
    )
    parser.add_argument(
        "--azure-endpoint-env",
        default="AZURE_OPENAI_ENDPOINT",
        help="Env var for Azure endpoint, used when provider=azure",
    )
    parser.add_argument(
        "--azure-api-version-env",
        default="AZURE_OPENAI_API_VERSION",
        help="Env var for Azure API version, used when provider=azure",
    )
    parser.add_argument(
        "--azure-deployment-env",
        default="AZURE_OPENAI_DEPLOYMENT",
        help="Env var for Azure deployment name (overrides --model), used when provider=azure",
    )
    parser.add_argument("--assets-json", default=None, help="Optional JSON file: {absolute_path: content}")
    parser.add_argument("--temperature", type=float, default=0.4, help="Sampling temperature")
    parser.add_argument("--max-retries", type=int, default=3, help="Retries per LLM call")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    provider = args.provider.lower()
    api_key = os.getenv(args.api_key_env)
    if provider == "azure" and not api_key:
        api_key = os.getenv(args.azure_api_key_env)
    if not api_key:
        if provider == "azure":
            raise ValueError(
                f"Missing API key. Set {args.api_key_env} or {args.azure_api_key_env}."
            )
        raise ValueError(f"Missing API key in env var: {args.api_key_env}")

    azure_endpoint = os.getenv(args.azure_endpoint_env) if provider == "azure" else None
    azure_api_version = os.getenv(args.azure_api_version_env) if provider == "azure" else None
    model_name = args.model
    if provider == "azure":
        deployment_from_env = os.getenv(args.azure_deployment_env)
        if deployment_from_env:
            model_name = deployment_from_env

    assets = _load_assets_from_json(args.assets_json)
    builder = EnvironmentBuilder(
        api_key=api_key,
        provider=provider,
        base_url=args.base_url,
        azure_endpoint=azure_endpoint,
        api_version=azure_api_version,
        model=model_name,
        temperature=args.temperature,
        max_retries=max(1, args.max_retries),
    )

    result = builder.build_workspace(
        domain_context=args.domain_context,
        output_base_dir=args.output_dir,
        assets=assets,
    )
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
