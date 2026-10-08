# Fortify SCA MCP

MCP server for Fortify SCA dependency policy compliance checks.

This project is implemented in Go using the official MCP Go SDK:

- `github.com/modelcontextprotocol/go-sdk`

## Transport

This build is `stdio` only.

- `MCP_TRANSPORT` must be `stdio` when set.
- The server runs over stdin/stdout using MCP newline-delimited JSON messages.

## Authentication

`FORTIFY_SCA_ACCESS_TOKEN` is the long-lived token. The server never sends it to the API endpoint
directly. Instead it posts the token to `POST {FORTIFY_SCA_BASE_URL}/api/login_refresh` to obtain a
short-lived bearer token, which is cached in memory and sent as `Authorization: Bearer <token>`.

The cached bearer is refreshed:

- proactively, 60 seconds before the `exp` claim in the returned JWT (or after 50 minutes if the
  token is opaque), and
- reactively, once, when the API responds `401`.

## Configuration

Required:

- `FORTIFY_SCA_ACCESS_TOKEN`

Optional:

- `FORTIFY_SCA_BASE_URL` (default: `https://debricked.com`)
- `FORTIFY_SCA_API_VERSION` (default: `1.0`)
- `MCP_TRANSPORT` (default: `stdio`)

## Build

```bash
go build -o fortify-sca-mcp .
```

## Use From Another Go Module

The public integration package is `github.com/debricked/fortify-sca-mcp/v26/pkg/server`.
Packages under `internal/` are implementation details and cannot be imported by a different
module. The `pkg` directory is a public-package convention; exported identifiers such as
`server.Serve` are the actual integration API.

For a host application such as the future Debricked CLI, run the MCP server with host-supplied
configuration and streams:

```go
import (
	"context"
	"io"

	"github.com/debricked/fortify-sca-mcp/v26/pkg/server"
)

func runFortifySCAMCP(ctx context.Context, accessToken string, input io.Reader, output io.Writer) error {
	return server.Serve(ctx, server.Options{
		AccessToken: accessToken,
		BaseURL:     "https://debricked.com",
		APIVersion:  "1.0",
	}, input, output)
}
```

The host owns authentication, context cancellation, and stream lifecycle. The CLI does not need
to import or use the MCP SDK directly. The package does not read the host's environment or
process stdio.

The standalone executable loads `FORTIFY_SCA_ACCESS_TOKEN`, `FORTIFY_SCA_BASE_URL`, and
`FORTIFY_SCA_API_VERSION` in `main.go`, handles process signals there, and calls the same
`server.Serve` function over stdin/stdout.

## Run

```bash
./fortify-sca-mcp
```

## Test

```bash
go test ./...
```

## Release

Releases are source-only Go module releases. Push a semantic-version tag such as `v26.4.0` to
run the release workflow. It runs the test and build checks, then creates a GitHub Release with
automatically generated notes. GitHub provides the tagged source as `.tar.gz` and `.zip` archives.

The module path declares major version 26 (`.../v26`), so tags must be `v26.x.y` per Go's semantic
import versioning rules.

The module version comes from the Git tag:

```bash
go get github.com/debricked/fortify-sca-mcp/v26@v26.4.0
```

This project does not upload binary or checksum assets for the module release. The MCP metadata
version and Fortify SCA API version are independent of the Go module tag.

## Tool Contract

Tool name:

- `check_dependency_policy_compliance`

Required tool inputs:

- `purls`: array of 1–5 distinct package URLs including versions; use a one-item array for one package
- `repo_url`: git remote URL (SSH or HTTPS)
- `repo_name`: repository slug with owner/org (for example, `my-org/my-repo`)

Example payload:

```json
{
	"purls": ["pkg:npm/react@19.1.8"],
	"repo_url": "https://github.com/my-org/my-repo",
	"repo_name": "my-org/my-repo"
}
```

Failure mode:

- returns recommendation `POLICY_CHECK_UNAVAILABLE` with an actionable `reason`
  when input validation fails, Fortify SCA API auth/plan checks fail, network
  timeout occurs, or other API/runtime errors occur.

The tool passes the purls array to the API and returns its envelope with one result per PURL and
shared `blockingRules`. Resolve each
result's `blockingRuleIds` to the matching rule and use that rule's `matches` entry for the
package-specific evidence. Never attribute one package's evidence to another. The `summary` field
is optional; individual results are authoritative.

When started by the CLI with cached OAuth authentication, the optional `authenticate` tool reuses
the `debricked auth login` browser flow. After `AUTHENTICATION_REQUIRED`, ask the user for permission
and call it with `{"confirmed": true}`. It waits up to five minutes, stores credentials through the
CLI, and clears the MCP bearer cache. Retry the original policy check once after login succeeds;
login itself does not establish API access or policy compliance. The tool is not exposed in
PAT-only mode, and the MCP host may require its own tool approval.

## Automatic Invocation

The server ships MCP `instructions` (sent on `initialize`) and a trigger-rich tool description so
agents call `check_dependency_policy_compliance` on their own whenever a dependency is added,
installed, upgraded, imported, or recommended — without the user naming the tool.

Some hosts ignore or down-weight server instructions. To make invocation reliable in a consuming
repository, also add a repo-level instruction file. For GitHub Copilot, create
`.github/copilot-instructions.md`:

```markdown
## Dependency policy

Before adding, installing, upgrading, importing, or recommending a dependency, call
`check_dependency_policy_compliance` with 1–5 distinct, versioned PURLs (`purls`); use one for a
single package.

- **Compliant:** Report the checked package/version as approved by Fortify SCA (Debricked).
- **Blocked:** Do not add it. Report every rule's condition, package-specific trigger evidence, and
  configuration URL when present. Disclose truncated results; never infer which OR branch matched.
- **Unavailable:** Report the reason; do not claim approval.
- **Alternatives:** For a blocked package, inspect its use and compatibility, then present up to
  five exact, versioned PURLs as unchecked candidates. Ask approval for that exact list. After
  approval, check all approved candidates in one call. Recommend only candidates that pass; report
  each result and say if none pass. Approval permits checking only, not adding or installing.
  Get fresh approval before checking a different candidate list.
```

Equivalent files for other agents: `AGENTS.md`, `CLAUDE.md`, or `.cursor/rules/`.
