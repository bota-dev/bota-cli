## Shared working rules

- Read the instructions and code relevant to the task. Keep changes within the requested outcome and preserve unrelated work.
- Treat acceptance criteria as the completion contract. Resolve ambiguous behavior that changes the outcome with the owner; continue independent work where possible.
- Use `$bota-code-change` for substantive implementation and bug fixes. Use `$bota-review-change` when asked to review a change. Keep small documentation and formatting edits lightweight.
- Run checks appropriate to the change using this repository's commands. Preserve regression assertions; explain changed acceptance criteria. Record what ran and what remains unverified.
- Use synthetic recordings, transcripts and credentials for routine tests. Keep customer content and secrets out of committed fixtures, logs and review artifacts. Preserve authorization and project boundaries.
- Complete safe local implementation and validation within the task's authorization. Use a branch and a reviewable PR for shared changes. Follow the repository's existing release and deployment requirements.
- Distinguish source completion, passing tests, published packages, deployed services and physical device acceptance. Report evidence at the level actually verified.
- Edit shared rules and skills in `bota-dev/bota-skills/engineering/bundle/`. Edit repository instructions in `.bota-harness/repo.md`, then run `python3 scripts/bota-harness.py render`. Keep repository-specific skills under distinct names.
