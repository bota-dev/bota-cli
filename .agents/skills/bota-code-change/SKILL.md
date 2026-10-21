---
name: bota-code-change
description: Implement and verify a scoped Bota feature or bug fix against its acceptance criteria. Use for substantive code changes, including CLI, SDK, API and firmware work.
---

# Bota code change

1. Read applicable repository instructions, the task and the relevant implementation and tests. Identify the behavior to change, compatibility requirements and concrete acceptance evidence.
2. For a bug, reproduce it and add a focused regression case when feasible. For a feature, cover the behavior and material failure paths. Use the repository's existing test tools and synthetic data.
3. Implement the smallest coherent change. Preserve authentication, recording identity, retry semantics and public contracts relevant to the change. Keep unrelated work intact.
4. Run affected tests and required repository checks. Fix failures caused by the change. If a check needs unavailable hardware, services or credentials, report the gap and complete available validation.
5. Review the diff and tests against acceptance criteria. Update relevant public documentation when behavior changes.
6. Hand off the change with its purpose, observed validation and remaining limitations. Keep merge, package publication, deployment and device qualification consistent with the task's authorization.
