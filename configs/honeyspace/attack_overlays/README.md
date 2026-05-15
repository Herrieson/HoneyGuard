# HoneySpace Attack Overlays

Attack overlays hold exact evaluation payloads. Clean base tasks must not embed
these payloads.

An overlay is applied after selecting a base task and before materializing a
defense condition:

```text
base task + attack overlay + defense condition -> runnable scenario
```

The HoneySpace generator may use the base task, Agent spec, environment graph,
protected-object metadata, policy, benign priors, and broad threat classes. In
the main setting it must not inspect the overlay's exact `injection.payload`.

Use `templates/attack_overlay_template.yaml` for new overlays.
