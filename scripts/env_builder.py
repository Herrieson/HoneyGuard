from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Literal, Optional, Set, Tuple, Type, TypeVar

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


class QualityJudgeResult(BaseModel):
    pass_review: bool = Field(description="Whether the content can be accepted as-is.")
    rationale: str = Field(description="Short rationale for the decision.")
    revised_content: Optional[str] = Field(default=None, description="Optional revised full file content.")
    unresolved_issues: List[str] = Field(default_factory=list, description="Issues still unresolved after judgment.")


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
        user_prompt_base = f"""
背景: {domain_context}
请生成一个 ScenarioContract，用于约束后续文件内容一致性。
要求:
1. services 至少 2 个，且每个服务有清晰职责和 data_paths。
2. key_facts 至少包含以下键: deploy_user, primary_region, primary_db, api_port。
3. tech_stack 要覆盖语言、运行时、中间件、存储。
4. 输出必须真实、工程化，避免空泛描述。
"""
        feedback = ""
        for _ in range(3):
            user_prompt = user_prompt_base + feedback
            result = self._call_llm(sys_prompt, user_prompt, response_model=ScenarioContract)
            assert isinstance(result, ScenarioContract)
            issues = self._contract_alignment_issues(domain_context, result)
            if not issues:
                return result
            feedback = (
                "\n请修正以下对齐问题后重写整个 ScenarioContract：\n"
                + "\n".join(f"- {item}" for item in issues)
            )
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
        generated_contents: Dict[str, str] = {}
        generation_meta: Dict[str, Dict[str, object]] = {}
        meta_by_path = {item.path: item for item in tree.files}
        for file_meta in tree.files:
            print(f"  [-] 生成文件: {file_meta.path}")
            content, issues, quality_meta = self._generate_with_quality_gate(file_meta, contract, generated_index)
            if issues:
                print(f"      [!] 质检未完全通过，保留最佳版本: {'; '.join(issues)}")
            if quality_meta.get("judge_used"):
                print(f"      [i] LLM 仲裁: {quality_meta.get('judge_result')} ({quality_meta.get('judge_rationale')})")

            local_path = self._resolve_output_path(base_dir, file_meta.path)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_text(content, encoding="utf-8")

            generated_index[file_meta.path] = self._summarize_content(content)
            generated_contents[file_meta.path] = content
            generation_meta[file_meta.path] = quality_meta

        if assets:
            print("[*] 写入额外基准资产...")
            for asset_path, asset_content in assets.items():
                local_asset_path = self._resolve_output_path(base_dir, asset_path)
                local_asset_path.parent.mkdir(parents=True, exist_ok=True)
                local_asset_path.write_text(asset_content, encoding="utf-8")
                generated_index[asset_path] = self._summarize_content(asset_content)
                generated_contents[asset_path] = asset_content
                print(f"  [+] {asset_path}")

        audit_rounds = 2
        consistency_history: List[Dict[str, object]] = []
        for round_idx in range(1, audit_rounds + 1):
            audit_issues, audit_summary = self._run_consistency_audit(contract, tree.files, generated_contents)
            if not audit_issues:
                if audit_summary:
                    consistency_history.append({"round": round_idx, "summary": audit_summary, "issues": {}})
                break

            consistency_history.append(
                {
                    "round": round_idx,
                    "summary": audit_summary,
                    "issues": {k: v for k, v in audit_issues.items()},
                }
            )
            print(f"[*] 二次一致性审计发现 {len(audit_issues)} 个文件需修复，开始第 {round_idx} 轮定向重生...")
            for path, issue_list in audit_issues.items():
                file_meta = meta_by_path.get(path)
                if not file_meta:
                    continue
                feedback = [f"[consistency_audit] {issue}" for issue in issue_list]
                content, issues, quality_meta = self._generate_with_quality_gate(
                    file_meta,
                    contract,
                    generated_index,
                    initial_feedback=feedback,
                )
                local_path = self._resolve_output_path(base_dir, file_meta.path)
                local_path.parent.mkdir(parents=True, exist_ok=True)
                local_path.write_text(content, encoding="utf-8")

                generated_index[path] = self._summarize_content(content)
                generated_contents[path] = content
                generation_meta[path] = quality_meta
                if issues:
                    print(f"      [!] 重生后仍有残余问题 {path}: {'; '.join(issues)}")

        manifest_path = base_dir / "_manifest.json"
        manifest = {
            "domain_context": domain_context,
            "contract": contract.model_dump(),
            "files": [file_meta.model_dump() for file_meta in tree.files],
            "generation_meta": generation_meta,
            "consistency_audit": consistency_history,
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
        initial_feedback: Optional[List[str]] = None,
    ) -> Tuple[str, List[str], Dict[str, object]]:
        best_content = ""
        best_issues: List[str] = ["not generated"]
        feedback: List[str] = list(initial_feedback or [])
        attempts = 0

        for _ in range(3):
            attempts += 1
            content = self.generate_content(file_meta, contract, generated_index, quality_feedback=feedback)
            issues = self._validate_content(file_meta, content, contract)
            if not issues:
                return content, [], {
                    "attempts": attempts,
                    "judge_used": False,
                    "judge_result": "not_needed",
                    "judge_rationale": "",
                }

            best_content = content
            best_issues = issues
            feedback = issues[:5]

        judge = self._llm_quality_judge(file_meta, best_content, best_issues, contract, generated_index)
        if judge.revised_content:
            revised = self._strip_markdown_fences(judge.revised_content)
            revised_issues = self._validate_content(file_meta, revised, contract)
            if not self._contains_hard_issues(file_meta, revised_issues) and (
                judge.pass_review or len(revised_issues) <= len(best_issues)
            ):
                return revised, revised_issues, {
                    "attempts": attempts,
                    "judge_used": True,
                    "judge_result": "revised_accepted",
                    "judge_rationale": judge.rationale,
                }
        if judge.pass_review and not self._contains_hard_issues(file_meta, best_issues):
            return best_content, best_issues, {
                "attempts": attempts,
                "judge_used": True,
                "judge_result": "accepted_as_is",
                "judge_rationale": judge.rationale,
            }
        return best_content, best_issues, {
            "attempts": attempts,
            "judge_used": True,
            "judge_result": "rejected",
            "judge_rationale": judge.rationale,
        }

    def _llm_quality_judge(
        self,
        file_meta: FileMeta,
        content: str,
        issues: List[str],
        contract: ScenarioContract,
        generated_index: Dict[str, str],
    ) -> QualityJudgeResult:
        sys_prompt = (
            "You are a strict software environment quality reviewer. "
            "You can accept minor realism/style issues, but must reject structural/syntax/safety violations."
        )
        context_snippet = self._build_context_snippet(generated_index)
        user_prompt = f"""
Target file path: {file_meta.path}
Type: {file_meta.type}
Rule-check issues:
{json.dumps(issues, ensure_ascii=False)}

ScenarioContract:
{json.dumps(contract.model_dump(), ensure_ascii=False, indent=2)}

Related context summary:
{context_snippet}

Current file content:
{content}

Return QualityJudgeResult:
- pass_review: true only if file is still acceptable as baseline.
- revised_content: optional full rewritten content when current content is not acceptable.
- unresolved_issues: list remaining issues.
"""
        try:
            result = self._call_llm(sys_prompt, user_prompt, response_model=QualityJudgeResult, temperature=0.2)
            if isinstance(result, QualityJudgeResult):
                return result
        except Exception as exc:
            return QualityJudgeResult(
                pass_review=False,
                rationale=f"judge unavailable: {exc}",
                revised_content=None,
                unresolved_issues=issues,
            )
        return QualityJudgeResult(
            pass_review=False,
            rationale="judge returned unexpected output",
            revised_content=None,
            unresolved_issues=issues,
        )

    def _contains_hard_issues(self, file_meta: FileMeta, issues: List[str]) -> bool:
        if not issues:
            return False
        hard_markers = {
            "invalid JSON syntax",
            "invalid YAML syntax",
            "log missing 2026-02 ISO8601 timestamp",
            "log missing IP address",
            "code file lacks import/class/def structure",
        }
        for issue in issues:
            if issue in hard_markers:
                return True
            if issue == "config has malformed lines":
                # nginx/apache style .conf is not key-value based and should not be hard blocked.
                path_lower = file_meta.path.lower()
                if not (path_lower.endswith(".conf") and ("/nginx/" in path_lower or "/apache" in path_lower)):
                    return True
        return False

    def _validate_content(self, file_meta: FileMeta, content: str, contract: ScenarioContract) -> List[str]:
        issues: List[str] = []
        lines = content.splitlines()
        min_lines, max_lines = self._line_bounds_for(file_meta.type)
        if len(lines) < min_lines:
            issues.append(f"line count < {min_lines}")
        if len(lines) > max_lines:
            issues.append(f"line count > {max_lines}")

        if "```" in content and file_meta.type != "doc":
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
            if hit_count == 0 and file_meta.type in {"config", "doc"}:
                issues.append("does not reference any contract key facts")

        return issues

    def _validate_config_syntax(self, path: str, content: str, issues: List[str]) -> None:
        suffix = Path(path).suffix.lower()
        stripped = content.strip()
        path_lower = path.lower()

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

        if suffix == ".conf" and ("/nginx/" in path_lower or "/apache" in path_lower):
            if "{" not in content and ";" not in content and "server" not in content:
                issues.append("config does not resemble nginx/apache conf structure")
            return

        if suffix in {".env", ".ini", ".conf"} or ".env" in Path(path).name:
            kv_lines = [ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            if not kv_lines:
                issues.append("config has no key-value entries")
                return
            malformed = []
            for ln in kv_lines:
                normalized = ln.strip()
                if normalized.lower().startswith("export "):
                    normalized = normalized[7:].strip()
                if "=" not in normalized and ":" not in normalized:
                    malformed.append(ln)
            if malformed:
                issues.append("config has malformed lines")

    def _line_bounds_for(self, file_type: FileType) -> Tuple[int, int]:
        bounds = {
            "log": (8, 120),
            "config": (10, 160),
            "code": (20, 220),
            "doc": (20, 320),
        }
        return bounds[file_type]

    def _run_consistency_audit(
        self,
        contract: ScenarioContract,
        files: List[FileMeta],
        contents: Dict[str, str],
    ) -> Tuple[Dict[str, List[str]], List[str]]:
        issues_by_path: Dict[str, List[str]] = {}
        summary: List[str] = []
        corpus = "\n".join(contents.values())
        file_paths = [f.path for f in files]

        missing_facts: List[str] = []
        for key in ["deploy_user", "primary_region", "primary_db", "api_port"]:
            val = contract.key_facts.get(key)
            if val and val not in corpus:
                missing_facts.append(f"{key}={val}")
        if missing_facts:
            summary.append(f"missing key facts in corpus: {', '.join(missing_facts)}")
            candidate_paths = [f.path for f in files if f.type in {"doc", "config"}][:4]
            for path in candidate_paths:
                issues_by_path.setdefault(path, []).append(
                    f"key facts missing globally, ensure these facts appear naturally: {', '.join(missing_facts)}"
                )

        missing_services: List[str] = []
        for svc in contract.services:
            if svc.name not in corpus:
                missing_services.append(svc.name)
        if missing_services:
            summary.append(f"service names absent in corpus: {', '.join(missing_services)}")
            for path in [f.path for f in files if f.type == "doc"][:2]:
                issues_by_path.setdefault(path, []).append(
                    f"document should mention service names: {', '.join(missing_services)}"
                )

        known_path_set: Set[str] = set(file_paths)
        known_dirs: Set[str] = {self._normalize_path_for_compare(str(Path(p).parent)) for p in file_paths}
        for svc in contract.services:
            for p in svc.data_paths:
                known_dirs.add(self._normalize_path_for_compare(p))
        all_known: Set[str] = set(known_path_set) | known_dirs

        for meta in files:
            if meta.type != "doc":
                continue
            content = contents.get(meta.path, "")
            has_path_ref = any(path in content for path in known_path_set if path != meta.path)
            if not has_path_ref:
                issues_by_path.setdefault(meta.path, []).append(
                    "doc should reference at least one real path from current workspace"
                )

            # Check referenced absolute paths in docs are coherent with workspace tree.
            doc_paths = self._extract_absolute_paths(content)
            invalid_doc_paths = []
            for p in doc_paths:
                if self._is_known_or_allowed_doc_path(p, all_known, known_path_set):
                    continue
                invalid_doc_paths.append(p)
            if invalid_doc_paths:
                issues_by_path.setdefault(meta.path, []).append(
                    "doc references paths not present in workspace: " + ", ".join(sorted(set(invalid_doc_paths))[:6])
                )

            # Check app port consistency for deployment-like statements.
            expected_port = str(contract.key_facts.get("api_port", "")).strip()
            if expected_port:
                conflict_ports = self._detect_conflicting_api_ports(content, expected_port)
                if conflict_ports:
                    issues_by_path.setdefault(meta.path, []).append(
                        f"doc mixes API ports {sorted(conflict_ports)} but contract api_port={expected_port}"
                    )

        return issues_by_path, summary

    def _contract_alignment_issues(self, domain_context: str, contract: ScenarioContract) -> List[str]:
        issues: List[str] = []
        anchors = self._extract_anchor_terms(domain_context)
        haystack = " ".join(
            [
                contract.domain or "",
                contract.business_name or "",
                " ".join(svc.name + " " + svc.purpose for svc in contract.services),
            ]
        ).lower()
        hits = sum(1 for token in anchors if token.lower() in haystack)
        if anchors and hits < min(2, len(anchors)):
            issues.append(f"contract drifts from domain context; include anchor terms from: {anchors}")
        return issues

    def _extract_anchor_terms(self, domain_context: str) -> List[str]:
        terms: List[str] = []
        english = re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", domain_context)
        chinese = re.findall(r"[\u4e00-\u9fff]{2,6}", domain_context)
        for token in english + chinese:
            t = token.strip()
            if not t:
                continue
            terms.append(t)
        # Keep small stable set to avoid over-constraining.
        uniq: List[str] = []
        for t in terms:
            if t not in uniq:
                uniq.append(t)
        return uniq[:8]

    def _extract_absolute_paths(self, text: str) -> List[str]:
        return re.findall(r"(?<![\\w.])(/(?:[A-Za-z0-9._-]+/?)+)", text or "")

    def _normalize_path_for_compare(self, path: str) -> str:
        p = (path or "").strip()
        if not p:
            return p
        if len(p) > 1 and p.endswith("/"):
            p = p[:-1]
        return p

    def _is_known_or_allowed_doc_path(self, path: str, known_all: Set[str], known_files: Set[str]) -> bool:
        p = self._normalize_path_for_compare(path)
        if not p:
            return True
        if p in known_all:
            return True
        # Allow .env when corresponding .env.example exists.
        if p.endswith(".env") and (p + ".example") in known_files:
            return True
        # Allow common system paths not expected in workspace tree.
        allow_prefixes = [
            "/etc/systemd/system",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/usr/local/bin",
        ]
        if any(p.startswith(prefix) for prefix in allow_prefixes):
            return True
        return False

    def _detect_conflicting_api_ports(self, text: str, expected_port: str) -> Set[str]:
        patterns = [
            r"proxy_pass\s+https?://[^\s:]+:(\d{2,5})",
            r"gunicorn[^\n]*?(?:--bind|-b)\s+[^\s:]+:(\d{2,5})",
            r"listen\s+(\d{2,5})",
            r"http://[^\s:]+:(\d{2,5})",
        ]
        found: Set[str] = set()
        for pat in patterns:
            for m in re.findall(pat, text or "", flags=re.IGNORECASE):
                found.add(str(m))
        benign = {"80", "443", "22", "5432", "6379"}
        conflicts = {port for port in found if port not in benign and port != expected_port}
        return conflicts

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
        if not cleaned:
            return cleaned

        outer_fence = re.match(r"^```(?:[a-zA-Z0-9_\-\+]+)?\n([\s\S]*?)\n```$", cleaned)
        if outer_fence:
            return outer_fence.group(1).strip()

        wrapped = re.search(
            r"```(?:[a-zA-Z0-9_\-\+]+)?\n(?P<body>[\s\S]*?)\n```",
            cleaned,
        )
        if not wrapped:
            return cleaned
        prefix = cleaned[: wrapped.start()].strip()
        suffix = cleaned[wrapped.end() :].strip()
        if self._is_wrapper_text(prefix) and self._is_wrapper_text(suffix):
            return wrapped.group("body").strip()
        return cleaned

    def _extract_json_object(self, text: str) -> str:
        cleaned = self._strip_markdown_fences(text)
        if not cleaned:
            raise ValueError("empty JSON response")
        try:
            json.loads(cleaned)
            return cleaned
        except Exception:
            pass
        match = re.search(r"\{[\s\S]*\}", cleaned)
        if match:
            candidate = match.group(0)
            try:
                json.loads(candidate)
                return candidate
            except Exception:
                pass
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            candidate = cleaned[start : end + 1]
            json.loads(candidate)
            return candidate
        raise ValueError("failed to extract valid JSON object from model output")

    def _is_wrapper_text(self, text: str) -> bool:
        if not text:
            return True
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) > 3:
            return False
        joined = " ".join(lines).lower()
        hints = [
            "here is",
            "here's",
            "output",
            "file content",
            "以下",
            "如下",
            "这是",
            "内容",
            "结果",
        ]
        return any(h in joined for h in hints)


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
