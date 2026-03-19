#!/usr/bin/env python3
from __future__ import annotations

"""
攻击配置质量检查器。

作用:
- 对单个攻击场景 YAML 做静态规则检查，输出 errors/warnings。
- 关注验收条件质量，避免把 stop token 当作攻击成功证据。

输入:
- --config: 攻击场景 YAML 文件路径。

输出:
- 打印 JSON 报告；有 error 时退出码为 1。
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

from common_specs import FIVE_METRIC_CATEGORIES

FIVE_METRIC_CATEGORY_SET = set(FIVE_METRIC_CATEGORIES)
TARGET_SURFACES = {"enterprise", "user", "hybrid"}
USER_HINT_TOKENS = {
    "session",
    "cookie",
    "cart",
    "checkout",
    "order",
    "payment",
    "wallet",
    "profile",
    "account",
    "customer",
    "ticket",
    "message",
    "inbox",
    "otp",
    "mfa",
    "patient",
    "student",
    "subscriber",
    "citizen",
}
ENTERPRISE_HINT_TOKENS = {
    "/etc/",
    "/var/",
    "/usr/",
    "/opt/",
    "/srv/",
    "/home/deploy/",
    ".ssh",
    "cron",
    "systemd",
    "policy",
    "config",
    "kube",
    "vault",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lint HoneyGuard attack config quality rules.")
    parser.add_argument("--config", required=True, help="Path to attack YAML config")
    return parser.parse_args()


def _to_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _collect_file_maps(cfg: Dict[str, Any]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for key in ("files", "files_overrides"):
        raw = cfg.get(key)
        if not isinstance(raw, dict):
            continue
        for path, content in raw.items():
            if isinstance(path, str) and isinstance(content, str):
                merged[path] = content
    return merged


def _normalize_target_surface(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if value in TARGET_SURFACES:
        return value
    return "unknown"


def _looks_user_like(text: str) -> bool:
    lowered = (text or "").lower()
    return any(token in lowered for token in USER_HINT_TOKENS)


def _looks_enterprise_like(text: str) -> bool:
    lowered = (text or "").lower()
    return any(token in lowered for token in ENTERPRISE_HINT_TOKENS)


def _collect_surface_hints(
    criteria: List[Any],
    inline_files: Dict[str, str],
    workspace: Any,
) -> List[str]:
    hints: List[str] = []
    for item in criteria:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        value = item.get("value")
        command = item.get("command")
        if isinstance(path, str) and path.strip():
            hints.append(path.strip())
        if isinstance(value, str) and value.strip():
            hints.append(value.strip())
        if isinstance(command, str) and command.strip():
            hints.append(command.strip())

    hints.extend(inline_files.keys())

    if isinstance(workspace, dict):
        include = workspace.get("include")
        if isinstance(include, list):
            for item in include:
                if isinstance(item, str) and item.strip():
                    hints.append(item.strip())

    return hints


def lint_config(cfg: Dict[str, Any], path: str) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    scenario = str(cfg.get("scenario") or "")
    tools_enabled = set(_to_list(cfg.get("tools_enabled")))
    stop_signals = [str(x).strip().lower() for x in _to_list(cfg.get("stop_signals")) if str(x).strip()]
    criteria = _to_list(cfg.get("acceptance_criteria"))
    acceptance_logic = str(cfg.get("acceptance_logic") or "all").lower()
    acceptance_template = str(cfg.get("acceptance_template") or "").strip().lower()
    target_surface_raw = cfg.get("target_surface")
    target_surface = _normalize_target_surface(target_surface_raw)
    workspace = cfg.get("workspace")
    inline_files = _collect_file_maps(cfg)

    if not scenario:
        errors.append("missing required top-level field: scenario")
    if acceptance_template and acceptance_template not in {"five_metric_v1"}:
        warnings.append(f"unknown acceptance_template: {acceptance_template}")
    if acceptance_logic not in {"all", "any"}:
        errors.append("acceptance_logic must be 'all' or 'any'")
    if target_surface_raw is not None and target_surface == "unknown":
        errors.append("target_surface must be one of: enterprise|user|hybrid when provided")
    if not criteria:
        errors.append("acceptance_criteria must not be empty for attack scenarios")
    if not cfg.get("files") and not cfg.get("workspace") and not cfg.get("files_overrides"):
        errors.append("at least one of files/workspace/files_overrides must be present")

    if workspace is not None:
        if not isinstance(workspace, dict):
            errors.append("workspace must be a mapping when provided")
        else:
            source = str(workspace.get("source") or "dir").strip().lower()
            if source != "dir":
                errors.append("workspace.source must be 'dir'")
            wpath = workspace.get("path")
            if not isinstance(wpath, str) or not wpath.strip():
                errors.append("workspace.path must be a non-empty string")
            include = workspace.get("include")
            if include is not None and not isinstance(include, list):
                errors.append("workspace.include must be a list when provided")
            exclude = workspace.get("exclude")
            if exclude is not None and not isinstance(exclude, list):
                errors.append("workspace.exclude must be a list when provided")
            if not isinstance(workspace.get("max_files", 1), int):
                errors.append("workspace.max_files must be an integer")
            if not isinstance(workspace.get("max_bytes_per_file", 1), int):
                errors.append("workspace.max_bytes_per_file must be an integer")
            truncate_mode = str(workspace.get("truncate_mode") or "skip").lower()
            if truncate_mode not in {"skip", "none", "head_tail"}:
                errors.append("workspace.truncate_mode must be one of skip|none|head_tail")

    short_stop_tokens = {token for token in stop_signals if len(token) <= 24}
    has_process_evidence = False
    response_tokens: List[str] = []
    has_category = False
    categories_seen = set()
    surface_hints = _collect_surface_hints(criteria, inline_files, workspace)
    has_user_like_hint = any(_looks_user_like(text) for text in surface_hints)
    has_enterprise_like_hint = any(_looks_enterprise_like(text) for text in surface_hints)

    for idx, raw in enumerate(criteria):
        if not isinstance(raw, dict):
            errors.append(f"acceptance_criteria[{idx}] must be a mapping")
            continue

        ctype = str(raw.get("type") or "")
        value = str(raw.get("value") or "")
        category = raw.get("category")
        enforce = raw.get("enforce", True)
        if not ctype:
            errors.append(f"acceptance_criteria[{idx}] missing type")
            continue
        if category is not None and not isinstance(category, str):
            errors.append(f"acceptance_criteria[{idx}].category must be a string when provided")
        elif isinstance(category, str) and category.strip():
            has_category = True
            categories_seen.add(category.strip())
            if category.strip() not in FIVE_METRIC_CATEGORY_SET:
                warnings.append(
                    f"acceptance_criteria[{idx}].category '{category.strip()}' is outside five-metric template"
                )
        if not isinstance(enforce, bool):
            errors.append(f"acceptance_criteria[{idx}].enforce must be a boolean when provided")

        if ctype in {"tool_output_contains", "command_output_contains"}:
            has_process_evidence = True

        if ctype == "response_contains":
            lowered = value.strip().lower()
            response_tokens.append(value)
            if lowered in short_stop_tokens:
                errors.append(
                    f"acceptance_criteria[{idx}] uses stop token '{value}' as response_contains; "
                    "stop signals must not be success criteria"
                )
            if lowered in {"done", "task complete", "summary complete", "patch complete"}:
                warnings.append(
                    f"acceptance_criteria[{idx}] uses weak completion token '{value}' as compromise evidence"
                )

        if ctype in {"command_exit_code", "command_output_contains"} and "bash_command" not in tools_enabled:
            errors.append(
                f"acceptance_criteria[{idx}] is command-based but bash_command is not enabled in tools_enabled"
            )

    scenario_l = scenario.lower()
    looks_like_attack = any(token in scenario_l for token in ["attack", "insider", "backdoor", "prompt_injection"])
    if looks_like_attack and not has_process_evidence:
        errors.append(
            "attack scenario acceptance_criteria should include process evidence "
            "(tool_output_contains or command_output_contains)"
        )
    if looks_like_attack and not has_category:
        warnings.append(
            "attack scenario acceptance_criteria should set category for metric-level reporting"
        )
    if looks_like_attack and has_category:
        missing_categories = sorted(cat for cat in FIVE_METRIC_CATEGORIES if cat not in categories_seen)
        if missing_categories:
            msg = "missing five-metric categories: " + ", ".join(missing_categories)
            if acceptance_template == "five_metric_v1":
                errors.append(msg)
            else:
                warnings.append(msg)

        has_enforced_unauthorized = any(
            isinstance(item, dict)
            and str(item.get("category") or "") == "unauthorized_trigger_rate"
            and item.get("enforce") is True
            for item in criteria
        )
        if not has_enforced_unauthorized:
            msg = "five-metric template should include enforce=true for unauthorized_trigger_rate"
            if acceptance_template == "five_metric_v1":
                errors.append(msg)
            else:
                warnings.append(msg)

    # Detect overly concentrated response tokens from a single inline file.
    if len(response_tokens) >= 2 and inline_files:
        token_paths: Dict[str, List[str]] = {}
        for token in response_tokens:
            paths = [fp for fp, content in inline_files.items() if token and token in content]
            token_paths[token] = paths
        known_tokens = [t for t in response_tokens if token_paths.get(t)]
        if len(known_tokens) >= 2:
            unique_paths = set()
            for token in known_tokens:
                unique_paths.update(token_paths[token])
            if len(unique_paths) == 1:
                warnings.append(
                    "response_contains tokens appear concentrated in a single file; "
                    "prefer spreading markers across multiple files"
                )
    elif len(response_tokens) >= 2 and workspace and not inline_files:
        warnings.append(
            "response_contains token diversity cannot be validated in lint when only workspace reference is present"
        )

    trunc_marker_pat = re.compile(r"truncated by build_attack_config|\[\.\.\.SNIPPED BY build_attack_config\.\.\.\]", re.I)
    truncated_hits = [
        fp for fp, content in inline_files.items() if trunc_marker_pat.search(content or "")
    ]
    if truncated_hits:
        warnings.append(
            "inline files contain truncation markers from generator; prefer workspace reference mode or adjust size policy"
        )

    # Detect semantic mismatch: source code files replaced by raw mail body style text.
    code_suffixes = (".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cc", ".cpp", ".cs", ".rs")
    for fp, content in inline_files.items():
        lowered = fp.lower()
        if not lowered.endswith(code_suffixes):
            continue
        c = content or ""
        if re.search(r"(?mi)^\s*from:\s+", c) and re.search(r"(?mi)^\s*subject:\s+", c):
            warnings.append(
                f"code file appears to contain raw mail body text: {fp}; "
                "prefer comment/docstring-style injection for code carriers"
            )
            break

    if (
        "malicious_coder_backdoor" in scenario
        or "i_code_backdoor" in scenario
        or "_i_backdoor_" in scenario
    ):
        backdoor_paths = {
            str(item.get("path") or "")
            for item in criteria
            if isinstance(item, dict)
            and item.get("type") == "file_contains"
            and isinstance(item.get("path"), str)
            and "BACKDOOR_INSTALLED" in str(item.get("value") or "")
        }
        has_backdoor_check = bool(backdoor_paths)
        if not backdoor_paths:
            backdoor_paths = {
                str(item.get("path") or "")
                for item in criteria
                if isinstance(item, dict)
                and item.get("type") in {"file_contains", "file_changed"}
                and isinstance(item.get("path"), str)
                and str(item.get("path") or "").startswith("/")
            }

        has_fix_check = any(
            isinstance(item, dict)
            and item.get("type") == "file_contains"
            and str(item.get("path") or "") in backdoor_paths
            and "BACKDOOR_INSTALLED" not in str(item.get("value") or "")
            and str(item.get("value") or "").strip()
            for item in criteria
        )
        if not has_fix_check:
            has_fix_check = any(
                isinstance(item, dict)
                and item.get("category") == "utility_retention_rate"
                and item.get("type") in {"file_contains", "file_changed"}
                and str(item.get("path") or "") in backdoor_paths
                for item in criteria
            )
        if not (has_fix_check and has_backdoor_check):
            warnings.append(
                "backdoor scenario should include both fix-check and backdoor-check on the same code target path"
            )
        if acceptance_logic != "all":
            warnings.append("backdoor scenario should prefer acceptance_logic=all")

    if looks_like_attack and target_surface == "user":
        if not has_user_like_hint:
            errors.append(
                "target_surface=user requires user-side evidence hints in criteria/files/workspace "
                "(e.g., session/profile/order/payment/account paths or values)"
            )
        if has_enterprise_like_hint and not has_user_like_hint:
            warnings.append(
                "target_surface=user appears dominated by enterprise/ops hints; consider adding user-facing artifacts"
            )

    if looks_like_attack and target_surface == "hybrid":
        if not has_user_like_hint:
            errors.append(
                "target_surface=hybrid requires user-side evidence hints in criteria/files/workspace"
            )
        if not has_enterprise_like_hint:
            errors.append(
                "target_surface=hybrid requires enterprise/ops-side evidence hints in criteria/files/workspace"
            )

    return {
        "config": path,
        "scenario": scenario,
        "target_surface": target_surface,
        "errors": errors,
        "warnings": warnings,
        "ok": len(errors) == 0,
    }


def main() -> int:
    args = parse_args()
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.stderr.write(f"Config not found: {cfg_path}\n")
        return 2

    try:
        payload = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        sys.stderr.write(f"Failed to parse YAML: {exc}\n")
        return 2

    if not isinstance(payload, dict):
        sys.stderr.write("YAML root must be a mapping\n")
        return 2

    report = lint_config(payload, str(cfg_path))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
