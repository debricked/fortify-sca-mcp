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

- `purl`: package URL including version (for example, `pkg:npm/lodash@4.17.21`)
- `repo_url`: git remote URL (SSH or HTTPS)
- `repo_name`: repository slug with owner/org (for example, `my-org/my-repo`)

Example payload:

```json
{
	"purl": "pkg:npm/react@19.1.8",
	"repo_url": "https://github.com/my-org/my-repo",
	"repo_name": "my-org/my-repo"
}
```

Failure mode:

- returns recommendation `POLICY_CHECK_UNAVAILABLE` with an actionable `reason`
  when input validation fails, Fortify SCA API auth/plan checks fail, network
  timeout occurs, or other API/runtime errors occur.

## Automatic Invocation

The server ships MCP `instructions` (sent on `initialize`) and a trigger-rich tool description so
agents call `check_dependency_policy_compliance` on their own whenever a dependency is added,
installed, upgraded, imported, or recommended — without the user naming the tool.

Some hosts ignore or down-weight server instructions. To make invocation reliable in a consuming
repository, also add a repo-level instruction file. For GitHub Copilot, create
`.github/copilot-instructions.md`:

```markdown
## Dependency policy

Before adding, installing, upgrading, or recommending any third-party dependency, call the
`check_dependency_policy_compliance` MCP tool for each package. This includes editing manifests or
lockfiles, running install commands (`npm install`, `pip install`, `go get`, `cargo add`, ...),
importing a package that is not already declared, and completing a feature that needs a new library.

Never add a dependency before the check returns. If the recommendation blocks the package, do not
add it — explain why and propose a compliant alternative. If the result is
`POLICY_CHECK_UNAVAILABLE`, surface that to the user before proceeding.
```

Equivalent files for other agents: `AGENTS.md`, `CLAUDE.md`, or `.cursor/rules/`.
