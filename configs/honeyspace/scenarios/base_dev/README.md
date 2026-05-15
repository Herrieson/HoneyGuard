# HoneySpace Base Dev Scenarios

Base scenarios are clean, defense-agnostic tasks. They should not include honey
affordances.

A HoneySpace generator consumes a base scenario plus a defense condition and
materializes defended scenarios under a separate output directory.

Base scenarios may include:

- protected-object metadata
- allowed benign affordances
- broad threat classes
- attack slots for evaluation variants

Base scenarios should not include:

- concrete honey assets
- concrete honey tools
- concrete honey MCP endpoints
- concrete honey helper agents
- trigger policies

Current Phase-1 dev set:

- 12 clean base tasks
- 12 paired attack overlays in `../../attack_overlays/dev/`
- coverage index in `../../manifests/base_dev.yaml`

Validate with:

```bash
uv run python scripts/honeyspace/validate_honeyspace_dataset.py --strict-phase1
```
