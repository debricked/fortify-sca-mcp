# Project Constitution Template

## Metadata
- **Document-Type:** Constitution
- **Document-ID:** `CONST-936176af-170a-4f89-867f-b5d7706385c6`
- **Revision-ID:** `REV-4e13d7d5-fcea-46e4-869f-c334d4209795`
- **Version:** `1.0.10`
- **Status:** `Draft`
- **Owner:** `Engineering Governance`
- **Created-On:** `2026-08-07`
- **Last-Updated-On:** `2026-08-12`

> **Update Rule:** On every content update, increment `Version`, update `Last-Updated-On`, and generate a new `Revision-ID`.

---

## 1. Purpose
Define the non-negotiable principles, governance model, and decision-making rules for this project.

## 2. Scope
Applies to all repositories, services, contributors, and release activities under this project.

## 3. Core Principles
1. **Security by default**
2. **Compliance and auditability**
3. **Reliability and maintainability**
4. **Clear ownership and accountability**
5. **Documentation-first changes**
6. **Immutable governance baseline**
7. **Consistent engineering hygiene**

## 4. Governance
- Significant architectural changes require documented approval.
- Security-impacting changes require security review before merge.
- Breaking changes require migration notes and versioning plan.
- `.github/copilot-policy.md` and `.github/CONSTITUTION.md` are the governance baseline for consumer repositories and must remain centrally controlled.
- Consumer repositories may derive operational guidance from the governance baseline, but may not modify the baseline directly.
- Consumer repositories must align repository guidance with the organization's cybersecurity and licensing control stack defined in this constitution where applicable.

## 5. Onboarding Standard
- Consumer onboarding may be initiated with prompts such as `integrate fortify policy`, `setup fortify policy`, or `run fortify policy`.
- Onboarding must treat the constitution and copilot policy as immutable source documents.
- Reminder standard for non-onboarded repositories:
	- Use a concise hint format, for example: `Hint: Run integrate fortify policy to adopt governance and improve results.`
	- At the start of every new conversation, show this hint when either `.github/copilot-instructions.md` or `README.md` is missing.
	- Show the hint approximately every 3-4 prompts until onboarding is completed.
	- Explain that onboarding improves guidance quality and enables full policy-derived artifact generation.
	- Stop the reminder after onboarding artifacts are confirmed.
- Onboarding must inspect the repository and reflect the repository's implemented or mandated security controls, licensing controls, and verification workflows in the derived support artifacts.
- Onboarding may create or update repository-specific support artifacts only:
	- `.github/AGENTS.md`
	- `.github/copilot-instructions.md`
	- `README.md`
	- `.github/agents/fortify.agent.md`
	- `.github/prompts/code-review.prompt.md`
	- `.github/skills/repository.skill.md`
- The default agent must be generated from the repository's actual structure, languages, frameworks, and workflows so it helps developers perform real tasks efficiently.
- `.github/AGENTS.md` must maintain the inventory of agents, prompts, and skills present in the consumer repository.
- When any new agent, prompt, or skill is created, `.github/AGENTS.md` must be updated so it reflects the available capabilities and the intended routing for specific tasks.
- Derived support artifacts must document and reinforce repository-relevant secure development, licensing, and quality practices based on the applicable sections below.
- Repository-specific support artifacts may evolve locally, but they must not weaken or override the baseline governance documents.

## 6. Security, Licensing, And Quality Control Standard

### 6.1 Debricked
- Repositories using Debricked must reflect dependency vulnerability scanning expectations in derived support artifacts.
- Generated guidance should reinforce vulnerability triage and remediation expectations for third-party dependencies.

### 6.2 Black Duck
- Repositories using Black Duck must reflect software composition analysis and component-risk expectations in derived support artifacts.
- Generated guidance should reinforce component review, vulnerability awareness, and license compliance processes where applicable.

### 6.3 Fortify SAST
- Repositories using Fortify SAST must reflect static code security verification expectations in derived support artifacts.
- Generated guidance should direct contributors to consider Fortify findings during development and review.

### 6.4 Fortify DAST
- Repositories using Fortify DAST must reflect dynamic testing expectations in derived support artifacts.
- Generated guidance should reinforce release-readiness decisions that account for runtime security findings when DAST is in scope.

### 6.5 Prisma Container Scanning
- Repositories building or publishing container images must reflect Prisma container scanning expectations in derived support artifacts.
- Generated guidance should reinforce secure image construction and remediation of material container findings.

### 6.6 Sonar Quality And Coverage
- Repositories using Sonar must reflect quality-gate and coverage expectations in derived support artifacts.
- Generated guidance should reinforce maintainability standards, test quality, and coverage evidence where required.

### 6.7 ITLS And Library Governance
- ITLS, the Inbound Technology Licensing System, must be reflected in derived support artifacts when inbound technology or library validation is required.
- Prefer open source components that satisfy legal, security, and support requirements.
- Reject or replace out-of-support components; do not depend on exceptions after policy deadlines.
- RTM requires valid reasons for High and Medium ITLS release-check exceptions.
- Resolve core data-quality exceptions before release: `No License`, `Missing License Text file`, `Missing Download URL`, `Unknown License`, `License Mismatch`, and `Unknown Version`.
- `CVE Unexamined in SCA` must be remediated by completing SCA-side CVE review.
- Apply linking constraints: GPL and CC-BY-SA require separate-process boundaries; LGPL cannot be statically linked; GPL with classpath exception may use approved dynamic/static/separate-process usage.
- Non-clearable exceptions (for example missing license text, not-reviewed states, commercial-license misclassification) must be fixed or escalated.
- Verify `OR` (disjunctive) versus `AND` (conjunctive) license expressions from source artifacts because SCA metadata may be inaccurate.
- For disjunctive expressions, select one permitted license per SOP-00502 and document the decision.
- For conjunctive expressions, consult OSS Governance (`opensource@opentext.com`) with ITLS and SCA references.

#### 6.7.1 License Triage Quick Reference
- Derived support artifacts should provide a quick license triage view to improve speed and consistency in ITLS exception handling.
- Generally acceptable licenses (subject to standard attribution/compliance checks): `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `EPL-2.0`.
- Review-required licenses (usage/linking/legal review required before approval): `GPL-2.0/3.0`, `GPL-2.0-with-classpath-exception`, `LGPL`, `CC-BY-3.0`, `CC-BY-4.0`, `OFL-1.1`, `CPL-1.0`, `BUSL-1.1`, `OLDAP-Unknown`.
- Avoid or escalate-before-use licenses/components: `CC-BY-NC`, `AGPL`, `Sleepycat`, `AFL`, `unRAR`, `EUPL`, `Elastic`, `OSL`, `RSAL`, `CPOL`, `NVIDIA`, `IPL-1.0`, `TMate`, unknown/no-license components, and out-of-support versions.
- Derived support artifacts should state that this quick reference supports triage only; final approval follows ITLS policy, SOP-00502, and OSS Governance disposition.

### 6.8 Secure Code Generation And Dependency Selection
- Derived support artifacts must direct contributors to favor code generation and suggestions that are secure by default and do not introduce avoidable vulnerabilities.
- Generated repository guidance should reinforce secure coding expectations appropriate to the stack, including safe input handling, secure configuration, supported dependency versions, and remediation of known security weaknesses.
- When package installation or library adoption is suggested, the generated guidance should explain the purpose of the dependency and note whether more appropriate, better-supported, or more secure alternatives should be considered.
- Repository guidance should prefer actively maintained and supportable dependencies over outdated, abandoned, or weakly supported options.

### 6.9 Commit Message Standardization
- Generated repository guidance should require the format `type(scope): short summary` for recommended commit messages unless a repository-specific approved alternate format is documented in `.github/copilot-instructions.md`.
- `type` should be one of: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`, or `security`.
- `scope` should identify the main area changed, such as `policy`, `constitution`, `instructions`, `agent`, `prompt`, `skill`, `deps`, `ci`, or another repository-relevant component.
- `short summary` should describe the actual change in clear and concise language.
- Commit guidance should discourage vague messages and should improve consistency across teams that currently use different commit styles.
- Security-focused changes should prefer the `security(...)` type when that makes the purpose clearer.
- Derived support artifacts may include practical examples of repository-specific commit messages using this format.

### 6.10 Agent Execution Discipline
- Generated agents must avoid hallucination and should distinguish clearly between verified repository facts and provisional assumptions.
- Generated agents should inspect repository context before asserting implementation details, workflows, or dependencies.
- Generated agents should break larger objectives into smaller tasks and execute them incrementally rather than attempting all changes at once.
- Generated agents should prefer focused reads, narrow edits, and targeted validation steps so results remain reviewable and controllable.
- Token optimization should be treated as an engineering concern: agents should minimize unnecessary context expansion, repeated scanning, and verbose intermediate output.
- During a user session, agents should remain scoped to the active conversation and current task, avoid jumping into unrelated chats or unrelated broad exploration, and execute efficiently to reduce token waste.
- Derived support artifacts should encourage efficient task routing so the right agent handles the right task with the least necessary context.

## 7. Reset Standard
- Consumer repositories may invoke a `reset fortify policy` workflow to restore policy-derived support artifacts to a compliant baseline.
- Reset must never modify `.github/copilot-policy.md` or `.github/CONSTITUTION.md` except through centralized template remediation.
- Reset may recreate or overwrite only repository-specific support artifacts governed by the onboarding standard.
- Reset must re-read the repository before generating replacement AGENTS inventory, instructions, README guidance, agent content, review prompts, or skill content.
- Reset must restore repository guidance for the applicable controls in Section 6 so regenerated artifacts continue to reflect required scans, licensing rules, and quality gates.
- Reset must prefer alignment and cleanup of managed policy artifacts over broad repository changes.

## 8. Change Control
- All changes must be traceable via pull request.
- Constitution changes require reviewer sign-off from project owners.
- Each approved update must regenerate `Revision-ID`.
- Any attempt to modify the baseline governance files in a consumer repository must be rejected and corrected through centralized template updates.
- Reset-policy changes must remain limited to managed derived artifacts and must be clearly identified in the associated pull request.
- Generated commits and automated remediation changes should use the commit format defined in Section 6.9 (or a documented approved alternate) and improve consistency across consumer teams.