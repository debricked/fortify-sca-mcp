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

// Options configures a Fortify SCA MCP server.
type Options struct {
	AccessToken string
	BaseURL     string
	APIVersion  string
}

type CheckDependencyPolicyInput struct {
	PURL     string `json:"purl" jsonschema:"Package URL of the dependency (e.g. pkg:npm/lodash@4.17.21)"`
	RepoURL  string `json:"repo_url" jsonschema:"Full git remote URL for the repository (SSH or HTTPS)"`
	RepoName string `json:"repo_name" jsonschema:"Repository slug with owner/org prefix (e.g. my-org/my-repo)"`
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
	server := mcp.NewServer(&mcp.Implementation{Name: "Fortify SCA MCP", Version: "1.0.0"}, nil)
	registerTools(server, checker)
	return server, nil
}

func registerTools(server *mcp.Server, checker policy.Checker) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_dependency_policy_compliance",
		Description: "Check whether a dependency is allowed by Fortify SCA policies before installation.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input CheckDependencyPolicyInput) (*mcp.CallToolResult, map[string]any, error) {
		return nil, handleCheckDependencyPolicyCompliance(ctx, checker, input.PURL, input.RepoURL, input.RepoName), nil
	})
}

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
