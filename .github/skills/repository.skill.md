---
name: repository
description: "Use when setting up, changing, validating, or reviewing the Fortify SCA MCP Python service, including Debricked dependency-policy checks, uv dependencies, GitLab compliance, and secure MCP development."
argument-hint: "Describe the repository task or verification needed."
---

# Fortify SCA MCP Repository Workflow

## Procedure

1. Read `.github/copilot-policy.md`, `.github/CONSTITUTION.md`, `.github/copilot-instructions.md`, `pyproject.toml`, `.gitlab-ci.yml`, and the task-owning `src/` module.
2. Route Python implementation, debugging, testing, and source-level review to `python-backend`; route governance, security, dependency, license, and CI decisions to `fortify`.
3. Make the smallest change consistent with the existing split between tool behavior, validation, and configuration.
4. For dependency work, inspect `uv.lock`, check the exact versioned purl with the MCP policy tool, and require Debricked, Fortify SAST, and ITLS evidence before merge.
5. Run `uv run python -m compileall src` for Python changes. Add focused tests for behavioral changes when test infrastructure is present or introduced.
6. Report validation that ran, unavailable CI/scanner evidence, and residual risk. Do not treat an unavailable policy check as approval.

## Secure Development Checks

- Validate and normalize input before outbound requests; keep explicit timeouts and TLS verification.
- Keep `DEBRICKED_API_TOKEN` in the environment and out of responses, logs, commits, and prompts.
- Prefer supported dependencies with accepted licenses. Escalate restricted, unknown, no-license, or unsupported components under ITLS; final disposition follows ITLS policy and SOP-00502.
- The GitLab pipeline imports centralized compliance controls. Do not claim DAST, Black Duck, Sonar, or container scans are configured unless a repository change provides evidence.

## Governance Boundaries

Never edit `.github/copilot-policy.md` or `.github/CONSTITUTION.md`. Use `reset fortify policy` only to refresh the repository-specific artifacts listed in `.github/AGENTS.md`.