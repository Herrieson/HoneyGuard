# Style Templateization Audit & Fix Plan

## Context
Recent generated scenarios show that some attack styles still rely on hardcoded/template signals
(fixed marker paths/tokens and generic utility words), which reduces scenario realism and domain fit.

Scope:
- `scripts/build_attack_config.py` generation logic
- All 9 attack styles

## Problem Summary
- Reused fixed acceptance signals across unrelated domains (for example, global `/tmp` marker flags).
- `utility_retention_rate` tokens for several styles are too generic and weakly tied to scenario context.
- Some generated override files include visibly synthetic marker comments (for example `SECRET_MARKER`), reducing realism.

## Style-by-Style Audit
- `insider_exfiltration`: medium templateization
  - Reuses generic utility/stealth wording in acceptance metrics.
- `malicious_coder_backdoor`: high templateization
  - Strong hardcoded target path (`/app/app.py`) and fixed marker.
- `indirect_prompt_injection`: high templateization
  - Fixed payload path and marker semantics.
- `c_secret_harvest`: medium templateization
  - Asset-driven markers are better, but utility token remains generic.
- `c_bulk_exfiltration`: medium templateization
  - Similar to `c_secret_harvest`, partial dynamic behavior only.
- `i_config_tamper`: low templateization (already improved)
  - Dynamic target path, dynamic key extraction, dynamic response tokens.
- `i_code_backdoor`: high templateization
  - Shares hardcoded checks with code-backdoor legacy path.
- `a_resource_exhaustion`: high templateization
  - Hardcoded `/tmp/availability_attack.flag` and static wording.
- `a_workflow_disruption`: high templateization
  - Hardcoded `/tmp/availability_attack.flag` and static wording.

## Fix Plan (Incremental)
- [x] Phase 0: baseline docs and issue tracking
  - This document created.
- [x] Phase 1: availability styles (`a_resource_exhaustion`, `a_workflow_disruption`)
  - Replace fixed `/tmp` marker criteria with scenario-native operational target checks.
  - Derive utility/explicit/stealth tokens from target path/content/context.
- [x] Phase 2: code-backdoor styles (`malicious_coder_backdoor`, `i_code_backdoor`)
  - Move away from fixed `/app/app.py` assumptions when scenario path differs.
- [x] Phase 3: confidentiality styles (`insider_exfiltration`, `c_secret_harvest`, `c_bulk_exfiltration`)
  - Improve utility/stealth token contextualization and marker diversity.
- [x] Phase 4: prompt-injection style (`indirect_prompt_injection`)
  - Make injected artifact path/content domain-adaptive.
  - Replace fixed `/tmp/pwned.txt` and `SYSTEM_COMPROMISED` acceptance signals with dynamic scenario-native target path and marker.
- [x] Phase 5 (part 1): output realism cleanup (cross-style)
  - Strip synthetic inline marker comments from file overrides while preserving measurable signals.

## Acceptance Criteria For Refactor
- No regression in generator executability and lint pass rates.
- No forced fallback increase due to stricter hardcoded gates.
- Better scenario-specific signals in generated YAML:
  - target paths aligned with manifest/domain files
  - fewer fixed global markers
  - utility tokens tied to domain/task language
