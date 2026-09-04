# Agent Inventory

This repository uses the centrally controlled `.github/copilot-policy.md` and `.github/CONSTITUTION.md` as immutable governance inputs. Repository-specific operational artifacts are listed below.

| Artifact | Purpose | Use when |
| --- | --- | --- |
| `.github/agents/fortify.agent.md` | Default repository agent | Implementing, debugging, reviewing, or documenting this MCP service |
| `.github/agents/python-backend.agent.md` | Python backend specialist | Changing, debugging, testing, or reviewing FastMCP, validation, configuration, or Debricked HTTP code |
| `.github/prompts/code-review.prompt.md` | Security-focused code review prompt | Reviewing a change before merge |
| `.github/skills/repository.skill.md` | Repository workflow skill | Performing setup, dependency, or verification work |
| `.github/copilot-instructions.md` | Always-on repository instructions | Any task in this repository |

## Routing

| Task or context | Agent | Prompt | Skill |
| --- | --- | --- | --- |
| Python MCP tool, validation, configuration, HTTP behavior, or tests | `python-backend` | None | `repository` |
| Security, dependency, or license review | `fortify` | `code-review` | `repository` |
| Setup, local verification, or CI compliance investigation | `fortify` | None | `repository` |
| No specialized agent matches | `fortify` | As applicable | `repository` |

The `fortify` agent is the default handler for repository governance and routes Python backend implementation to `python-backend`. Keep this inventory current when managed agents, prompts, or skills change.