---
name: compound-engineering
description: Apply Plan → Work → Review → Compound. Use when starting non-trivial work or reviewing an implementation before claiming completion, especially to compare results with the authoritative design and record evidence, deviations, and verification gaps.
---

# Compound Engineering

Source: [every.to/guides/compound-engineering](https://every.to/guides/compound-engineering)

Each unit of engineering work should make subsequent units easier — not harder. The "compound" step is what separates this from standard development.

## The Loop

**Plan → Work → Review → Compound → Repeat**

### Plan (80% of the value)
- State assumptions explicitly before writing any code
- If multiple interpretations exist, surface them — don't pick silently
- Define success criteria up front: "add validation" → "write tests for invalid inputs, then make them pass"
- Identify the current authoritative design/spec sections and acceptance criteria for the requested scope; distinguish target requirements from historical plans and shipped-state notes.
- For multi-step tasks, write a brief plan with verify steps before starting

### Work (20% of the effort)
- Execute against the plan
- Use available skills (see `/bota-skills:superpowers`) before starting work in a new area
- Parallelise independent tasks — the bottleneck is compute, not human attention

### Review
- Verify against the success criteria defined in Plan
- Run tests, build, exercise the changed flow manually
- Check for regressions in adjacent areas

#### Post-Implementation Design Review

- Before claiming completion, re-read the authoritative design and compare the actual changed behavior with each relevant requirement, including cross-component contracts and failure/recovery paths where affected.
- Record requirement/section → implementation evidence → verification result → status. Use `matched`, `intentionally diverged`, `partial`, `not implemented`, or `unverified`; cite the approved decision for intentional divergence. Keep this in the existing review, PR, or conformance tracker; a short final-response checklist is enough for a small change.
- Use appropriate tests, runtime observations, or hardware evidence where feasible. Passing unit tests or finding code does not establish end-to-end, deployed, or hardware conformance. State exactly what each check proves.
- Fix discrepancies within the authorized scope and recheck affected requirements. Report scope-expanding discrepancies with the needed follow-up; do not silently rewrite the design to make the implementation appear compliant.
- When verification needs unavailable hardware, credentials, environments, or authority, mark the requirement `unverified`, explain the limit, and identify the remaining check. Do not claim full conformance.
- If no applicable design exists, compare against the user's requirements and acceptance criteria and state that basis; do not invent a design or require a new spec solely to complete this review.

### Compound
- Update the owning design, runbook or guide only when its durable contract, decision, pitfall or convention changes. Revise the existing statement in place and follow repository-specific ownership and placement rules.
- Keep `AGENTS.md` / `CLAUDE.md` limited to durable instructions and `ARCHITECTURE.md` to stable responsibilities, interfaces, trust boundaries and data flows. Do not append task checkpoints, CI/test receipts, run IDs or session memory, or create a repository log merely to satisfy Compound.
- Keep reviewed conformance and necessary evidence in the existing owning review or tracker; a concise final-response review is sufficient for a small change. Mark only verified requirements complete; preserve partial, deferred, and unverified items, and keep target design separate from implementation status.
- If no durable statement or conformance result changes, no documentation edit is required.

## Beliefs to Unlearn

- Code must be manually typed line by line
- Every line requires human review
- First attempts should be perfect
- Writing code is the core job — it isn't; direction-setting and taste-encoding are

## When to Apply

Apply this loop explicitly for:
- Any task touching more than one file
- Any task that modifies a protocol, API shape, or cross-system contract
- Any refactor or architectural change
- Any task where "I'm not sure what's expected" — stop and plan first
