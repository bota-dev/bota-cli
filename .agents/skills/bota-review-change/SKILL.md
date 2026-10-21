---
name: bota-review-change
description: Review a Bota diff or pull request for correctness, compatibility and meaningful regression coverage. Use when a code review is requested.
---

# Bota change review

1. Read applicable repository instructions, acceptance criteria and the diff. Follow changed behavior into relevant callers, tests and contracts.
2. Prioritize concrete regressions: incorrect behavior, authorization or project-boundary failures, recording loss or duplication, incompatible public contracts and failed recovery paths.
3. Check whether tests exercise intended behavior and failure modes. Preserve existing assertions and distinguish mocks, service integration and physical-device evidence.
4. Validate suspected findings with available code and focused checks. Report actionable findings with their location, trigger and consequence, ordered by severity.
5. If no actionable finding is established, say so and list material validation gaps. Keep review output concise; implement fixes only when requested.
