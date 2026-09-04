package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"fortify-sca-mcp/internal/auth"
	"fortify-sca-mcp/internal/config"
	"fortify-sca-mcp/internal/fortifysca"
	"fortify-sca-mcp/internal/validators"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const unavailableRecommendation = "POLICY_CHECK_UNAVAILABLE"

type CheckDependencyPolicyInput struct {
	PURL     string `json:"purl" jsonschema:"Package URL of the dependency (e.g. pkg:npm/lodash@4.17.21)"`
	RepoURL  string `json:"repo_url" jsonschema:"Full git remote URL for the repository (SSH or HTTPS)"`
	RepoName string `json:"repo_name" jsonschema:"Repository slug with owner/org prefix (e.g. my-org/my-repo)"`
}

type PolicyChecker interface {
	CheckDependencyPolicy(ctx context.Context, purl, repoURL, repoName string) (map[string]any, error)
}

func Run() error {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration load failed", "error", err)
		return err
	}

	if cfg.Transport != "stdio" {
		err := fmt.Errorf("unsupported transport: %s", cfg.Transport)
		slog.Error("startup failed", "error", err)
		return err
	}

	slog.Info("starting fortify sca mcp server",
		"transport", cfg.Transport,
		"fortify_sca_base_url", cfg.FortifyBaseURL,
		"fortify_sca_api_version", cfg.FortifyVersion,
	)

	provider := auth.NewRefreshTokenProvider(cfg.FortifyBaseURL, cfg.FortifyAccessToken)
	checker := fortifysca.NewClient(cfg.FortifyBaseURL, cfg.FortifyVersion, provider)
	server := mcp.NewServer(&mcp.Implementation{Name: "Fortify SCA MCP", Version: "1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_dependency_policy_compliance",
		Description: "Check whether a dependency is allowed by Fortify SCA policies before installation.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input CheckDependencyPolicyInput) (*mcp.CallToolResult, map[string]any, error) {
		return nil, HandleCheckDependencyPolicyCompliance(ctx, checker, input.PURL, input.RepoURL, input.RepoName), nil
	})

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("server ready, listening on stdio transport")
	err = server.Run(runCtx, &mcp.StdioTransport{})
	if err != nil {
		if errors.Is(err, context.Canceled) || runCtx.Err() == context.Canceled {
			slog.Info("shutdown signal received, stopping server")
			return nil
		}
		return err
	}

	return nil
}

func HandleCheckDependencyPolicyCompliance(
	ctx context.Context,
	checker PolicyChecker,
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
	case errors.Is(err, fortifysca.ErrUnauthorized):
		slog.Error("fortify sca auth rejected", "error", err, "repo_name", repoName)
		return unavailable("Unauthorized. Please check your FORTIFY_SCA_ACCESS_TOKEN.")
	case errors.Is(err, fortifysca.ErrAuth):
		slog.Error("fortify sca authentication failed", "error", err, "repo_name", repoName)
		return unavailable("Unable to authenticate with the Fortify SCA API.")
	case errors.Is(err, fortifysca.ErrEnterprise):
		slog.Warn("fortify sca plan does not support policy checks", "repo_name", repoName)
		return unavailable("Policy checks require a Fortify SCA Enterprise plan.")
	case errors.Is(err, fortifysca.ErrTimeout):
		slog.Error("fortify sca request timed out", "error", err, "repo_name", repoName)
		return unavailable("Request to Fortify SCA API timed out.")
	case errors.Is(err, fortifysca.ErrAPIStatus):
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
