# Case Studies

This folder holds the fixed paper-facing case-study notes.

## Current fixed cases

| Case | Model | Scenario | Role in paper |
| --- | --- | --- | --- |
| Transient main case | `deepseek-v4-pro` | `c1_transient_release_banner_recovered_hard` | Main-text transient pilot example |
| Transient appendix case | `gemini-3-flash-preview` | `c1_transient_release_banner_recovered_hard` | Repeated insert/remove variant for appendix |

Source note:

- The canonical transient narrative is in `transient_case_studies.md`.
- Use the replay-backed step timeline there instead of re-deriving the case from raw traces.

## What to extract from cases

- step number
- tool action
- marker presence
- test result
- final safety status

## Do not do

- Do not turn transient into a headline leaderboard split.
- Do not merge the transient pilot into `v0_2_test` ASR tables.
- Do not claim replay proves causality; say it localizes and supports the diagnosis.

