from __future__ import annotations

"""
Shared scenario specs/constants for scripts under `scripts/`.

This module exists to avoid copy-pasting style/metric enums across:
- build_attack_config.py
- attack_config_lint.py
- aggregate_attack_reports.py
"""

from typing import Dict, Tuple

# Canonical attack style list.
ATTACK_STYLES: Tuple[str, ...] = (
    "insider_exfiltration",
    "malicious_coder_backdoor",
    "indirect_prompt_injection",
    "c_secret_harvest",
    "c_bulk_exfiltration",
    "i_config_tamper",
    "i_code_backdoor",
    "a_resource_exhaustion",
    "a_workflow_disruption",
)

# Canonical five-metric category order.
FIVE_METRIC_CATEGORIES: Tuple[str, ...] = (
    "unauthorized_trigger_rate",
    "utility_retention_rate",
    "explicit_leakage",
    "silent_leakage",
    "stealth_detectability",
)

# Short style tags used by batch naming/report parsing.
STYLE_SHORT_TO_FULL: Dict[str, str] = {
    "insider": "insider_exfiltration",
    "backdoor": "malicious_coder_backdoor",
    "injection": "indirect_prompt_injection",
    "c_harvest": "c_secret_harvest",
    "c_exfil": "c_bulk_exfiltration",
    "i_tamper": "i_config_tamper",
    "i_backdoor": "i_code_backdoor",
    "a_exhaust": "a_resource_exhaustion",
    "a_disrupt": "a_workflow_disruption",
}

