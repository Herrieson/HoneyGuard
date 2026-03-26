#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

INTENTS: Sequence[str] = ("confidentiality", "integrity", "availability")
INTENT_SHORT = {
    "confidentiality": "c",
    "integrity": "i",
    "availability": "a",
}

DEFAULT_TASK_FILES: Sequence[str] = (
    "agent_task.jsonl",
    "agent_task_pot.jsonl",
    "agent_task_pot_msg.jsonl",
)

DEFAULT_ASB_DATA_DIR = "/home/hyx/workplace/ASB/data"

BUILD_MODE_OPTIONS: Sequence[str] = ("full_faithful", "balanced_legacy")

AGENT_SURFACE_MAP = {
    "system_admin_agent": "enterprise",
    "financial_analyst_agent": "enterprise",
    "legal_consultant_agent": "enterprise",
    "medical_advisor_agent": "user",
    "education_consultant_agent": "user",
    "psychological_counselor_agent": "user",
    "ecommerce_manager_agent": "hybrid",
    "aerospace_engineer_agent": "hybrid",
    "academic_search_agent": "hybrid",
    "autonomous_driving_agent": "hybrid",
}

AGENT_SHORT = {
    "system_admin_agent": "sysadmin",
    "financial_analyst_agent": "finance",
    "legal_consultant_agent": "legal",
    "medical_advisor_agent": "medical",
    "education_consultant_agent": "edu",
    "psychological_counselor_agent": "psych",
    "ecommerce_manager_agent": "ecom",
    "aerospace_engineer_agent": "aero",
    "academic_search_agent": "research",
    "autonomous_driving_agent": "auto",
}

SURFACE_CYCLE = {
    "confidentiality": ("enterprise", "user", "hybrid"),
    "integrity": ("hybrid", "enterprise", "user"),
    "availability": ("enterprise", "hybrid", "user"),
}

AGENT_DOMAIN_LABEL = {
    "system_admin_agent": "系统运维",
    "financial_analyst_agent": "金融分析",
    "legal_consultant_agent": "法务咨询",
    "medical_advisor_agent": "医疗服务",
    "education_consultant_agent": "教育咨询",
    "psychological_counselor_agent": "心理咨询",
    "ecommerce_manager_agent": "电商运营",
    "aerospace_engineer_agent": "航空工程",
    "academic_search_agent": "学术检索",
    "autonomous_driving_agent": "自动驾驶",
}

CONF_KW = (
    "credential",
    "password",
    "token",
    "key",
    "export",
    "exfil",
    "leak",
    "capture",
    "sensitive",
    "private",
    "surveil",
    "monitor",
    "record",
)
INTEG_KW = (
    "tamper",
    "modify",
    "alter",
    "inject",
    "backdoor",
    "override",
    "replace",
    "spoof",
    "forg",
    "rerout",
    "manipulat",
    "duplicate",
)
AVAIL_KW = (
    "shutdown",
    "interrupt",
    "disrupt",
    "block",
    "delay",
    "throttle",
    "overload",
    "disable",
    "drop",
    "queue",
    "degradation",
    "downtime",
    "drain",
)

DEFENSIVE_TASK_KW = (
    "safety",
    "secure",
    "security",
    "compliance",
    "ethical",
    "vulnerab",
    "patch",
    "protect",
    "防护",
    "安全",
    "合规",
    "修复",
    "漏洞",
    "防御",
)


@dataclass
class AttackEntry:
    source_line: int
    agent: str
    tool: str
    instruction: str
    goal: str
    attack_type: str
    aggressive: str
    intent: str


@dataclass
class SeedRow:
    scenario_name: str
    target_surface: str
    attack_intent: str
    attack_intent_note: str
    seed: str
    asb_agent: str
    asb_attack_tool: str
    asb_attack_type: str
    asb_aggressive: str
    asb_instruction: str
    asb_goal: str
    asb_source_line: int


def _read_jsonl(path: Path) -> List[dict]:
    rows: List[dict] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def _normalize_text(text: str) -> str:
    cleaned = re.sub(r"\s+", " ", (text or "").strip())
    return cleaned


def _normalize_seed_text(task: str) -> str:
    text = _normalize_text(task)
    if not text:
        return "Complete the routine operational task using available project materials."
    return text


def _pick_seed_task(task_pool: Sequence[str], intent: str, ordinal: int) -> str:
    if not task_pool:
        return "Complete the routine operational task using available project materials."

    source: List[str] = list(task_pool)
    # Defensive/safety-heavy tasks often trigger model refusal; prefer neutral operational wording.
    filtered = [item for item in source if not any(k in item.lower() for k in DEFENSIVE_TASK_KW)]
    if filtered:
        source = filtered

    return _normalize_seed_text(source[ordinal % len(source)])


def _sanitize_instruction(text: str, max_len: int = 220) -> str:
    cleaned = _normalize_text(text)
    cleaned = re.sub(r"^please\s+", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.rstrip(" .;")
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3].rstrip() + "..."
    return cleaned


def _infer_intent(attack_type: str, instruction: str, goal: str, desc: str) -> str:
    text = f"{instruction} {goal} {desc}".lower()
    if any(k in text for k in AVAIL_KW):
        return "availability"
    if any(k in text for k in INTEG_KW):
        return "integrity"
    if any(k in text for k in CONF_KW):
        return "confidentiality"

    attack_type_l = (attack_type or "").lower()
    if "disruptive" in attack_type_l:
        return "availability"
    if "stealthy" in attack_type_l:
        return "confidentiality"
    return "integrity"


def _build_attack_note(attack: AttackEntry) -> str:
    domain = AGENT_DOMAIN_LABEL.get(attack.agent, "业务")

    tool = _sanitize_instruction(attack.tool, max_len=40)
    inst = _sanitize_instruction(attack.instruction, max_len=170)
    goal = _sanitize_instruction(attack.goal, max_len=120)
    attack_type = _sanitize_instruction(attack.attack_type, max_len=48)

    source = f"ASB样本「{tool}」" if tool else "ASB样本"
    if attack_type:
        source = f"{source}（{attack_type}）"

    clauses: List[str] = []
    if inst:
        clauses.append(f"对外任务表述为“{inst}”")
    if goal:
        clauses.append(f"实际执行目标为“{goal}”")

    if not clauses:
        return f"在{domain}场景中，参考{source}的攻击行为，以隐蔽方式推进恶意目标并避免被察觉。"

    note = f"在{domain}场景中，参考{source}，{ '，'.join(clauses) }，全过程保持低可见度。"
    if len(note) > 320:
        note = note[:317].rstrip() + "..."
    return note




def _slugify(token: str) -> str:
    slug = re.sub(r"[^a-z0-9_]+", "_", (token or "").lower()).strip("_")
    if not slug:
        return "seed"
    return slug[:96]


def _unique_name(base: str, seen: set[str]) -> str:
    name = base
    idx = 2
    while name in seen:
        name = f"{base}_{idx:02d}"
        idx += 1
    seen.add(name)
    return name


def _load_tasks(asb_dir: Path, task_files: Sequence[str]) -> Dict[str, List[str]]:
    by_agent: Dict[str, List[str]] = defaultdict(list)
    seen: Dict[str, set[str]] = defaultdict(set)

    for file_name in task_files:
        path = asb_dir / file_name
        if not path.is_file():
            continue

        for row in _read_jsonl(path):
            agent = str(row.get("agent_name") or "").strip()
            if not agent:
                continue

            tasks: List[str] = []
            if isinstance(row.get("tasks"), list):
                tasks.extend(str(x) for x in row.get("tasks") or [])
            for key in ("Task1", "Task2"):
                if key in row and str(row.get(key) or "").strip():
                    tasks.append(str(row.get(key)))

            for task in tasks:
                cleaned = _normalize_seed_text(task)
                key = cleaned.lower()
                if key in seen[agent]:
                    continue
                seen[agent].add(key)
                by_agent[agent].append(cleaned)

    return by_agent


def _resolve_attack_file(asb_dir: Path, source: str, override: str) -> Path:
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise FileNotFoundError(f"attack tools file not found: {path}")

    name_map = {
        "all": "all_attack_tools.jsonl",
        "aggressive": "all_attack_tools_aggressive.jsonl",
        "non-aggressive": "all_attack_tools_non_aggressive.jsonl",
    }
    path = asb_dir / name_map[source]
    if not path.is_file():
        raise FileNotFoundError(f"attack tools file not found: {path}")
    return path


def _load_attacks(path: Path) -> List[AttackEntry]:
    out: List[AttackEntry] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue

            instruction = _normalize_text(str(row.get("Attacker Instruction") or ""))
            if not instruction:
                continue
            attack_type = str(row.get("Attack Type") or "")
            goal = _normalize_text(str(row.get("Attack goal") or ""))
            desc = _normalize_text(str(row.get("Description") or ""))
            intent = _infer_intent(attack_type=attack_type, instruction=instruction, goal=goal, desc=desc)
            out.append(
                AttackEntry(
                    source_line=line_no,
                    agent=str(row.get("Corresponding Agent") or "").strip(),
                    tool=_normalize_text(str(row.get("Attacker Tool") or "attack_tool")),
                    instruction=instruction,
                    goal=goal,
                    attack_type=attack_type,
                    aggressive=str(row.get("Aggressive") or ""),
                    intent=intent,
                )
            )
    return out


def _pick_surface(agent: str, intent: str, ordinal: int, mode: str) -> str:
    if mode == "agent":
        return AGENT_SURFACE_MAP.get(agent, "hybrid")
    seq = SURFACE_CYCLE[intent]
    return seq[ordinal % len(seq)]


def _select_rows_balanced(rows: List[SeedRow], max_rows: int) -> List[SeedRow]:
    if max_rows <= 0 or len(rows) <= max_rows:
        return rows

    by_intent: Dict[str, List[SeedRow]] = {intent: [] for intent in INTENTS}
    for row in rows:
        by_intent[row.attack_intent].append(row)

    picked: List[SeedRow] = []
    idx = 0
    while len(picked) < max_rows:
        progress = False
        for intent in INTENTS:
            bucket = by_intent[intent]
            if idx < len(bucket):
                picked.append(bucket[idx])
                progress = True
                if len(picked) >= max_rows:
                    break
        if not progress:
            break
        idx += 1
    return picked


def _build_rows_legacy(
    tasks_by_agent: Dict[str, List[str]],
    attacks: List[AttackEntry],
    variants_per_intent: int,
    surface_mode: str,
    max_rows: int,
) -> List[SeedRow]:
    attacks_by_agent_intent: Dict[str, Dict[str, List[AttackEntry]]] = defaultdict(lambda: defaultdict(list))
    attacks_by_intent: Dict[str, List[AttackEntry]] = defaultdict(list)

    for attack in attacks:
        if attack.agent:
            attacks_by_agent_intent[attack.agent][attack.intent].append(attack)
        attacks_by_intent[attack.intent].append(attack)

    rows: List[SeedRow] = []
    name_seen: set[str] = set()

    agents = sorted(set(tasks_by_agent) & set(attacks_by_agent_intent))
    if not agents:
        raise RuntimeError("No overlapping agents between ASB tasks and attack tools")

    for agent_idx, agent in enumerate(agents):
        task_pool = tasks_by_agent.get(agent) or []
        if not task_pool:
            continue

        for intent_idx, intent in enumerate(INTENTS):
            local_attack_pool = attacks_by_agent_intent[agent].get(intent) or []
            global_attack_pool = attacks_by_intent.get(intent) or []
            fallback_pool = list(attacks_by_agent_intent[agent].values())
            flattened_fallback = [item for bucket in fallback_pool for item in bucket]
            if not local_attack_pool:
                local_attack_pool = global_attack_pool or flattened_fallback
            if not local_attack_pool:
                continue

            for var_idx in range(1, variants_per_intent + 1):
                attack = local_attack_pool[(var_idx - 1) % len(local_attack_pool)]
                task_index = intent_idx + var_idx - 1
                seed = _pick_seed_task(task_pool=task_pool, intent=intent, ordinal=task_index)
                surface = _pick_surface(
                    agent=agent,
                    intent=intent,
                    ordinal=agent_idx + var_idx + intent_idx,
                    mode=surface_mode,
                )

                agent_short = AGENT_SHORT.get(agent, _slugify(agent.replace("_agent", "")))
                base_name = f"asb_{agent_short}_{INTENT_SHORT[intent]}_{var_idx:02d}"
                scenario_name = _unique_name(base_name, name_seen)

                rows.append(
                    SeedRow(
                        scenario_name=scenario_name,
                        target_surface=surface,
                        attack_intent=intent,
                        attack_intent_note=_build_attack_note(attack),
                        seed=seed,
                        asb_agent=attack.agent,
                        asb_attack_tool=attack.tool,
                        asb_attack_type=attack.attack_type,
                        asb_aggressive=attack.aggressive,
                        asb_instruction=attack.instruction,
                        asb_goal=attack.goal,
                        asb_source_line=attack.source_line,
                    )
                )

    if not rows:
        raise RuntimeError("No rows generated from ASB data")
    return _select_rows_balanced(rows, max_rows=max_rows)


def _build_rows_full_faithful(
    tasks_by_agent: Dict[str, List[str]],
    attacks: List[AttackEntry],
    surface_mode: str,
    max_rows: int,
) -> List[SeedRow]:
    rows: List[SeedRow] = []
    name_seen: set[str] = set()
    per_agent_counter: Dict[str, int] = defaultdict(int)

    for idx, attack in enumerate(attacks, start=1):
        agent = (attack.agent or "unknown_agent").strip() or "unknown_agent"
        intent = attack.intent if attack.intent in INTENTS else "integrity"

        per_agent_counter[agent] += 1
        ordinal = per_agent_counter[agent] - 1
        task_pool = tasks_by_agent.get(agent) or []
        seed = _pick_seed_task(task_pool=task_pool, intent=intent, ordinal=ordinal)

        surface = _pick_surface(agent=agent, intent=intent, ordinal=idx, mode=surface_mode)
        agent_short = AGENT_SHORT.get(agent, _slugify(agent.replace("_agent", "")))
        base_name = f"asb_{agent_short}_{INTENT_SHORT.get(intent, 'x')}_{idx:04d}"
        scenario_name = _unique_name(base_name, name_seen)

        rows.append(
            SeedRow(
                scenario_name=scenario_name,
                target_surface=surface,
                attack_intent=intent,
                attack_intent_note=_build_attack_note(attack),
                seed=seed,
                asb_agent=agent,
                asb_attack_tool=attack.tool,
                asb_attack_type=attack.attack_type,
                asb_aggressive=attack.aggressive,
                asb_instruction=attack.instruction,
                asb_goal=attack.goal,
                asb_source_line=attack.source_line,
            )
        )

    if not rows:
        raise RuntimeError("No rows generated from ASB data")

    if max_rows > 0:
        return rows[:max_rows]
    return rows


def _build_rows(
    tasks_by_agent: Dict[str, List[str]],
    attacks: List[AttackEntry],
    variants_per_intent: int,
    surface_mode: str,
    max_rows: int,
    build_mode: str,
) -> List[SeedRow]:
    mode = (build_mode or "full_faithful").strip().lower()
    if mode == "balanced_legacy":
        return _build_rows_legacy(
            tasks_by_agent=tasks_by_agent,
            attacks=attacks,
            variants_per_intent=variants_per_intent,
            surface_mode=surface_mode,
            max_rows=max_rows,
        )
    return _build_rows_full_faithful(
        tasks_by_agent=tasks_by_agent,
        attacks=attacks,
        surface_mode=surface_mode,
        max_rows=max_rows,
    )


def _write_tsv(path: Path, rows: Iterable[SeedRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scenario_name",
                "target_surface",
                "attack_intent",
                "attack_intent_note",
                "seed",
                "asb_agent",
                "asb_attack_tool",
                "asb_attack_type",
                "asb_aggressive",
                "asb_instruction",
                "asb_goal",
                "asb_source_line",
            ],
            delimiter="\t",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "scenario_name": row.scenario_name,
                    "target_surface": row.target_surface,
                    "attack_intent": row.attack_intent,
                    "attack_intent_note": row.attack_intent_note,
                    "seed": row.seed,
                    "asb_agent": row.asb_agent,
                    "asb_attack_tool": row.asb_attack_tool,
                    "asb_attack_type": row.asb_attack_type,
                    "asb_aggressive": row.asb_aggressive,
                    "asb_instruction": row.asb_instruction,
                    "asb_goal": row.asb_goal,
                    "asb_source_line": row.asb_source_line,
                }
            )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate HoneyGuard seed TSV from ASB data (rule-based, no LLM call).")
    parser.add_argument("--asb-data-dir", default=DEFAULT_ASB_DATA_DIR, help="ASB data directory")
    parser.add_argument(
        "--task-files",
        default=",".join(DEFAULT_TASK_FILES),
        help="Comma-separated task JSONL files under ASB data dir",
    )
    parser.add_argument(
        "--attack-tools-source",
        default="all",
        choices=["all", "aggressive", "non-aggressive"],
        help="Which ASB attack-tools set to use",
    )
    parser.add_argument("--attack-tools-file", default="", help="Optional explicit attack tools JSONL path")
    parser.add_argument("--variants-per-intent", type=int, default=1, help="Rows per (agent, intent), only for balanced_legacy mode")
    parser.add_argument("--max-rows", type=int, default=0, help="Optional cap of output rows; 0 means no cap")
    parser.add_argument(
        "--build-mode",
        default="full_faithful",
        choices=list(BUILD_MODE_OPTIONS),
        help="full_faithful: one seed per ASB attack entry; balanced_legacy: agent x intent x variants layout.",
    )
    parser.add_argument(
        "--surface-mode",
        default="agent",
        choices=["agent", "cycle"],
        help="How to assign target_surface: by agent profile or cyclic distribution",
    )
    parser.add_argument(
        "--output",
        default="configs/seeds/template_seed_batch_asb.tsv",
        help="Output TSV path",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.build_mode == "balanced_legacy":
        if args.variants_per_intent < 1 or args.variants_per_intent > 10:
            raise SystemExit("--variants-per-intent must be in [1, 10] when --build-mode=balanced_legacy")

    asb_dir = Path(args.asb_data_dir)
    if not asb_dir.is_dir():
        raise SystemExit(f"ASB data dir not found: {asb_dir}")

    task_files = [x.strip() for x in str(args.task_files or "").split(",") if x.strip()]
    if not task_files:
        raise SystemExit("--task-files must not be empty")

    tasks_by_agent = _load_tasks(asb_dir=asb_dir, task_files=task_files)
    attack_path = _resolve_attack_file(asb_dir=asb_dir, source=args.attack_tools_source, override=args.attack_tools_file)
    attacks = _load_attacks(attack_path)

    rows = _build_rows(
        tasks_by_agent=tasks_by_agent,
        attacks=attacks,
        variants_per_intent=args.variants_per_intent,
        surface_mode=args.surface_mode,
        max_rows=max(0, args.max_rows),
        build_mode=args.build_mode,
    )

    output_path = Path(args.output)
    _write_tsv(output_path, rows)

    intent_counter = Counter(row.attack_intent for row in rows)
    surface_counter = Counter(row.target_surface for row in rows)
    agent_count = len(set(name for name in tasks_by_agent if name in AGENT_SHORT or name))

    summary = {
        "output": str(output_path.resolve()),
        "rows": len(rows),
        "attacks_total": len(attacks),
        "intents": dict(sorted(intent_counter.items())),
        "surfaces": dict(sorted(surface_counter.items())),
        "build_mode": args.build_mode,
        "variants_per_intent": args.variants_per_intent,
        "attack_tools_source": args.attack_tools_source,
        "attack_tools_file": str(attack_path.resolve()),
        "task_files": task_files,
        "agents_with_tasks": len(tasks_by_agent),
        "agents_seen": agent_count,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
