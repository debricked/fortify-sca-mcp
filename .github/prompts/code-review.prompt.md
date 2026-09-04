---
name: code-review
description: "Review a Fortify SCA MCP change for Python correctness, MCP boundary security, Debricked policy behavior, dependency risk, and verification gaps."
argument-hint: "Files, diff, branch, or change description to review"
agent: fortify
tools: [read, search, execute]
---

Review the supplied change as a security- and correctness-focused code review for this FastMCP service.

Read the repository guidance and the changed source first. Report findings before any summary, ordered by severity, and include file paths. Focus on:

- validation and normalization of MCP inputs before external calls;
- exposure of secrets, internal details, raw exceptions, and unsafe logging;
- `httpx` timeout and TLS behavior, plus handling of remote API failures;
- changes that bypass Debricked dependency policy, Fortify SAST expectations, or ITLS license review;
- dependency additions, support status, locked versions, provenance, and license risk;
- missing focused tests and whether `uv run python -m compileall src` was run.

Do not assert scanner results that are not available. Identify unavailable Fortify, Debricked, ITLS, or CI evidence as a review gap. If no defects are found, say so clearly and name residual test or scan gaps.

For source-level Python implementation analysis, use the `python-backend` agent's repository knowledge; retain the final security, dependency, license, and CI assessment in this `fortify` review.