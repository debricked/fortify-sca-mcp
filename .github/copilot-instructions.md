# Fortify SCA MCP Instructions

## Governance

- Treat `.github/copilot-policy.md` and `.github/CONSTITUTION.md` as read-only, centrally controlled inputs. Do not modify them.
- Keep changes limited to the active task and state which validation actually ran. Human review is mandatory; route security-sensitive changes to AppSec.
- Do not request, print, commit, or return secrets. `DEBRICKED_API_TOKEN` must remain an environment variable.
- Do not stage, commit, push, merge, rebase, or run destructive Git operations without explicit user approval in the current conversation.

## Working Style

- Lead with the result and concise rationale. Prefer small, reviewable diffs and only essential clarifying questions.
- Stay in the current workspace and task context. Read only the files needed to verify behavior; do not present assumptions, guessed APIs, or inferred framework behavior as facts.
- For non-trivial security changes, identify relevant trust boundaries and abuse cases, then state residual risk after validation.

## Repository Map

- `src/server.py` owns the FastMCP tool and Debricked HTTP request.
- `src/validators.py` owns package URL, repository URL, and repository name validation.
- `src/config.py` loads and validates environment configuration.
- `src/client.py` is a local MCP client example.
- `pyproject.toml` and `uv.lock` own Python dependencies. `.gitlab-ci.yml` imports the centrally managed compliance pipeline.

## Agent Routing

- Use `python-backend` for Python implementation, debugging, testing, and review in `src/`.
- Use `fortify` for governance, security, dependency, license, and GitLab compliance decisions.
- Consult `.github/AGENTS.md` for the complete routing table and managed-artifact inventory.

## Implementation Rules

- Preserve validation and normalization at the MCP boundary before any outbound request.
- Use explicit `httpx` timeouts; never disable TLS certificate verification.
- Return minimal, user-safe failures. Never expose tokens, stack traces, internal paths, or raw confidential response data.
- Treat remote API payloads as untrusted data. Do not execute, deserialize unsafely, or interpolate them into commands.
- Keep tool, configuration, and validation responsibilities separated as they are today.
- Add dependencies only when necessary, explain their purpose, keep `uv.lock` synchronized, and prefer maintained, supportable packages.
- Verify a dependency's exact name, namespace, registry, version, support status, and license to reduce typosquatting and dependency-confusion risk. Do not use mutable version ranges.
- Use secure standard libraries and well-supported dependencies. When cryptography or authentication is introduced, require an explicit security review; use modern approved primitives and never disable certificate-chain validation.
- Sanitize data used in logs or headers to prevent CRLF injection. Never use Python native deserialization such as `pickle` for untrusted data.

## Security And Quality Workflow

- Before any dependency change, call `check_dependency_policy_compliance` with the exact versioned purl and complete Debricked, Fortify SAST, and ITLS review in CI.
- License triage: usually acceptable with normal validation: `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `EPL-2.0`. Review required: GPL, LGPL, CC-BY, OFL, CPL, BUSL, and `OLDAP-Unknown`. Escalate AGPL, CC-BY-NC, unknown/no-license, unsupported, or otherwise restricted components. Final disposition follows ITLS policy, SOP-00502, and OSS Governance.
- Resolve scan findings and ITLS data-quality exceptions before release. Do not suppress findings without a documented, approved exception with owner, rationale, compensating controls, and expiry.
- This repository has no evidenced container build, deployed DAST target, Black Duck integration, or Sonar configuration. Do not claim those checks ran; note them as not applicable or unavailable if relevant to a change.
- Update `README.md` when changes affect setup, tool behavior, configuration, or operations.

## Validation

- For Python-only changes, run `uv run python -m compileall src`.
- Add focused `pytest` coverage for behavior changes when a test suite is introduced or available.
- Run the relevant GitLab CI compliance checks before merge and report results or blockers explicitly.
- Use commit messages in the form `type(scope): short summary`; prefer `security(scope): ...` for security work.