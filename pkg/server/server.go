package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/debricked/fortify-sca-mcp/v26/internal/client"
	"github.com/debricked/fortify-sca-mcp/v26/internal/policy"
	"github.com/debricked/fortify-sca-mcp/v26/internal/validators"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const unavailableRecommendation = "POLICY_CHECK_UNAVAILABLE"

const (
	defaultBaseURL    = "https://debricked.com"
	defaultAPIVersion = "1.0"
)

// serverInstructions is sent during initialize and is treated by most MCP hosts
// as always-on guidance, so it is the main lever for making the policy check
// happen automatically instead of only when the user names the tool.
const serverInstructions = `This server enforces Fortify SCA (Debricked) open source policies for this repository.

MANDATORY: call "check_dependency_policy_compliance" BEFORE adding, installing, upgrading, or
suggesting any third-party dependency. Do this on your own initiative. Never wait for the user to
ask for a policy check, and never assume a package is allowed.

Always call it when you are about to:
- add or edit an entry in a manifest or lockfile (package.json, requirements.txt, pyproject.toml,
  go.mod, pom.xml, build.gradle, Gemfile, Cargo.toml, composer.json, *.csproj, etc.)
- run an install command (npm/yarn/pnpm install|add, pip install, go get, mvn/gradle dependency
  changes, bundle add, cargo add, composer require, dotnet add package, apt/brew for app deps)
- write an import/require for a package that is not already a declared dependency
- complete a feature, fix, or refactor that needs a new library
- answer "can we use X", "is X allowed/compliant", "which library should we use", or review a
  dependency change in a diff or pull request
- review or audit existing dependencies for policy compliance

Check each package separately, including transitive packages you explicitly pin. If several
packages are involved, call the tool once per package.

If the result recommendation is to block the dependency, do not add it: tell the user why and
propose a compliant alternative. If the result is POLICY_CHECK_UNAVAILABLE, say so explicitly and
let the user decide before proceeding.`

const checkDependencyPolicyDescription = `Check whether a third-party dependency is allowed by this repository's Fortify SCA (Debricked) policies.

Call this proactively and automatically BEFORE any dependency is added, installed, upgraded, or
recommended. Do not wait to be asked to run a policy or compliance check.

Use it when you are about to:
- add/upgrade a package in package.json, requirements.txt, pyproject.toml, go.mod, pom.xml,
  build.gradle, Gemfile, Cargo.toml, composer.json, *.csproj, or any lockfile
- run npm install, yarn add, pnpm add, pip install, go get, cargo add, composer require,
  bundle add, dotnet add package, or an equivalent install command
- import or require a package that is not already a declared dependency
- implement a feature or fix that needs a new library
- answer whether a package is allowed, compliant, safe, or approved
- review a dependency change in a diff or pull request

Call once per package. Returns a recommendation plus the reason. Treat a blocking recommendation as
a hard stop and propose a compliant alternative instead. POLICY_CHECK_UNAVAILABLE means the policy
could not be evaluated and must be surfaced to the user.`

// Options configures a Fortify SCA MCP server.
type Options struct {
	AccessToken string
	BaseURL     string
	APIVersion  string
}

type CheckDependencyPolicyInput struct {
	PURL     string `json:"purl" jsonschema:"Package URL of the dependency to check, including the version being added (e.g. pkg:npm/lodash@4.17.21, pkg:pypi/requests@2.32.3, pkg:golang/github.com/gin-gonic/gin@v1.10.0)"`
	RepoURL  string `json:"repo_url" jsonschema:"Full git remote URL for the repository (SSH or HTTPS), as reported by 'git remote get-url origin'"`
	RepoName string `json:"repo_name" jsonschema:"Repository slug with owner/org prefix (e.g. my-org/my-repo), derived from the git remote URL"`
}

// Serve creates and runs a Fortify SCA MCP server over the supplied streams.
// The caller owns configuration, context cancellation, and stream lifecycle.
func Serve(ctx context.Context, options Options, input io.Reader, output io.Writer) error {
	if input == nil {
		return errors.New("input stream is required")
	}
	if output == nil {
		return errors.New("output stream is required")
	}

	server, err := newServer(options)
	if err != nil {
		return err
	}

	return server.Run(ctx, &mcp.IOTransport{
		Reader: io.NopCloser(input),
		Writer: noOpWriteCloser{Writer: output},
	})
}

func newServer(options Options) (*mcp.Server, error) {
	options.AccessToken = strings.TrimSpace(options.AccessToken)
	options.BaseURL = strings.TrimRight(strings.TrimSpace(options.BaseURL), "/")
	options.APIVersion = strings.TrimSpace(options.APIVersion)

	if options.AccessToken == "" {
		return nil, errors.New("access token is required")
	}
	if options.BaseURL == "" {
		options.BaseURL = defaultBaseURL
	}
	if options.APIVersion == "" {
		options.APIVersion = defaultAPIVersion
	}

	checker := client.New(options.BaseURL, options.APIVersion, options.AccessToken)
	server := mcp.NewServer(&mcp.Implementation{Name: "Fortify SCA MCP", Version: "1.0.0"}, &mcp.ServerOptions{
		Instructions: serverInstructions,
	})
	registerTools(server, checker)
	return server, nil
}

func registerTools(server *mcp.Server, checker policy.Checker) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_dependency_policy_compliance",
		Title:       "Check dependency policy compliance",
		Description: checkDependencyPolicyDescription,
		Annotations: &mcp.ToolAnnotations{
			Title:           "Check dependency policy compliance",
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  true,
			OpenWorldHint:   boolPtr(true),
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input CheckDependencyPolicyInput) (*mcp.CallToolResult, map[string]any, error) {
		return nil, handleCheckDependencyPolicyCompliance(ctx, checker, input.PURL, input.RepoURL, input.RepoName), nil
	})
}

func boolPtr(v bool) *bool { return &v }

func handleCheckDependencyPolicyCompliance(
	ctx context.Context,
	checker policy.Checker,
	purl string,
	repoURL string,
	repoName string,
) map[string]any {
	ok, errMsg := validators.ValidateInputs(purl, repoURL, repoName)
	if !ok {
		slog.Warn("input validation failed", "reason", errMsg, "repo_name", repoName)
		return unavailable(fmt.Sprintf("Invalid input: %s", errMsg))
	}

	data, err := checker.CheckDependencyPolicy(ctx, purl, repoURL, repoName)
	if err == nil {
		return data
	}

	switch {
	case errors.Is(err, client.ErrUnauthorized):
		slog.Error("fortify sca auth rejected", "error", err, "repo_name", repoName)
		return unavailable("Unauthorized. Please check your FORTIFY_SCA_ACCESS_TOKEN.")
	case errors.Is(err, client.ErrAuth):
		slog.Error("fortify sca authentication failed", "error", err, "repo_name", repoName)
		return unavailable("Unable to authenticate with the Fortify SCA API.")
	case errors.Is(err, client.ErrEnterprise):
		slog.Warn("fortify sca plan does not support policy checks", "repo_name", repoName)
		return unavailable("Policy checks require a Fortify SCA Enterprise plan.")
	case errors.Is(err, client.ErrTimeout):
		slog.Error("fortify sca request timed out", "error", err, "repo_name", repoName)
		return unavailable("Request to Fortify SCA API timed out.")
	case errors.Is(err, client.ErrAPIStatus):
		slog.Error("fortify sca api returned an error status", "error", err, "repo_name", repoName)
		return unavailable(fmt.Sprintf("API error: %s", err.Error()))
	default:
		slog.Error("unexpected error checking dependency policy", "error", err, "repo_name", repoName)
		return unavailable(fmt.Sprintf("Unexpected error: %s", err.Error()))
	}
}

func unavailable(reason string) map[string]any {
	return map[string]any{
		"recommendation": unavailableRecommendation,
		"reason":         reason,
	}
}
