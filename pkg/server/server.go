package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

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

Before adding, installing, upgrading, importing, or recommending dependencies, proactively call
check_dependency_policy_compliance with 1-5 distinct, versioned purls, including explicitly pinned
transitives. This covers manifest/lockfile edits, feature work, and dependency reviews or audits.

- Approve only checked results with recommendation=allowed and isPolicyCompliant=true. Never add
	or claim approval if isPolicyCompliant is false. Briefly name approved packages/versions and
	attribute the check to Fortify SCA (Debricked) in your final answer.
- If blocked, do not add it. Report every returned rule's configuredCondition, package-specific
	triggeredBy evidence, and configurationUrl when available. Resolve blockingRuleIds against
	shared blockingRules and use matches for that purl. Never invent details or infer OR branches.
	If blockingRulesTruncated, disclose the incomplete list and blockingRuleCount.
- Alternatives are unchecked candidates: get user approval for the exact versioned list before
	checking it, and fresh approval for each further list. Consent never overrides a policy block.
- For POLICY_CHECK_UNAVAILABLE or item errors, explain the failure; never claim approval and ask
	before proceeding. For AUTHENTICATION_REQUIRED, if authenticate is available, obtain consent,
	call it with confirmed=true, and retry the original check once after success. Never loop logins.`

const checkDependencyPolicyDescription = `Check 1-5 distinct, versioned purls against Fortify SCA (Debricked) policy before dependency changes, installs, new imports, recommendations, or reviews.

Returns per-purl results and shared blockingRules. Resolve blockingRuleIds by ruleId; use matches
for each package's triggeredBy evidence. If blocked, do not add it; report every configuredCondition
and available configurationUrl. Disclose blockingRulesTruncated and blockingRuleCount; never invent
details or infer OR branches. Only report checked, allowed, compliant packages as passing Fortify
SCA (Debricked) policy; never add or claim approval if isPolicyCompliant is false.

Get approval for each exact alternative list before checking; consent cannot override a block.
POLICY_CHECK_UNAVAILABLE or item errors are not approvals: report the reason or message and ask
before proceeding. Follow server guidance for consented authentication recovery.`

// Options configures a Fortify SCA MCP server.
type Options struct {
	AccessToken string
	// TokenFetcher, if set, is called on demand for a currently-valid bearer token,
	// taking precedence over AccessToken. Use this when the caller already owns
	// token refresh (e.g. an existing OAuth session) instead of a long-lived
	// credential this server would otherwise exchange itself via /api/login_refresh.
	TokenFetcher func(ctx context.Context) (string, error)
	// Authenticate completes caller-owned browser login without writing to MCP stdout.
	Authenticate func(ctx context.Context) error
	BaseURL      string
	APIVersion   string
}

type CheckDependencyPolicyInput struct {
	PURLs    []string `json:"purls" jsonschema:"One to five distinct, versioned package URLs to check"`
	RepoURL  string   `json:"repo_url" jsonschema:"Full git remote URL for the repository (SSH or HTTPS), as reported by 'git remote get-url origin'"`
	RepoName string   `json:"repo_name" jsonschema:"Repository slug with owner/org prefix (e.g. my-org/my-repo), derived from the git remote URL"`
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

	if options.AccessToken == "" && options.TokenFetcher == nil {
		return nil, errors.New("access token is required")
	}
	if options.BaseURL == "" {
		options.BaseURL = defaultBaseURL
	}
	if options.APIVersion == "" {
		options.APIVersion = defaultAPIVersion
	}

	var checker *client.PolicyChecker
	if options.TokenFetcher != nil {
		checker = client.NewWithTokenFetcher(options.BaseURL, options.APIVersion, options.TokenFetcher)
	} else {
		checker = client.New(options.BaseURL, options.APIVersion, options.AccessToken)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "Fortify SCA MCP", Version: "1.0.0"}, &mcp.ServerOptions{
		Instructions: serverInstructions,
	})
	registerTools(server, checker)
	if options.Authenticate != nil && options.TokenFetcher != nil {
		var loginMu sync.Mutex
		mcp.AddTool(server, &mcp.Tool{
			Name:        "authenticate",
			Description: "Open Debricked browser login and wait for completion. Ask the user for permission first; pass confirmed=true only after approval. Success loads credentials, not policy approval. Retry the original policy check once afterward.",
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: false, DestructiveHint: boolPtr(false), IdempotentHint: false, OpenWorldHint: boolPtr(true),
			},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input AuthenticateInput) (*mcp.CallToolResult, map[string]any, error) {
			if !input.Confirmed {
				return nil, map[string]any{"status": "confirmation_required", "message": "Ask the user for permission before opening browser login."}, nil
			}
			if !loginMu.TryLock() {
				return nil, map[string]any{"status": "login_in_progress", "message": "A browser login is already in progress."}, nil
			}
			defer loginMu.Unlock()
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			if err := options.Authenticate(ctx); err != nil {
				slog.Warn("browser authentication did not complete")
				return nil, map[string]any{"status": "authentication_failed", "message": "Browser login did not complete. Check the browser, cancellation, or login timeout."}, nil
			}
			checker.InvalidateCredentials()
			return nil, map[string]any{"status": "credentials_loaded", "nextAction": "retry_policy_check", "message": "Login completed. Retry the policy check; credentials do not imply policy approval."}, nil
		})
	}
	return server, nil
}

type AuthenticateInput struct {
	Confirmed bool `json:"confirmed" jsonschema:"True only after the user approves opening browser login"`
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
		return nil, handleCheckDependencyPolicyRequest(ctx, checker, input), nil
	})
}

func boolPtr(v bool) *bool { return &v }

func handleCheckDependencyPolicyRequest(
	ctx context.Context,
	checker policy.Checker,
	input CheckDependencyPolicyInput,
) map[string]any {
	purls := input.PURLs
	if ok, errMsg := validators.ValidateBatchInputs(purls, input.RepoURL, input.RepoName); !ok {
		slog.Warn("policy input validation failed", "reason", errMsg, "repo_name", input.RepoName)
		return unavailable(fmt.Sprintf("Invalid input: %s", errMsg))
	}

	data, err := checker.CheckDependencyPolicy(ctx, purls, input.RepoURL, input.RepoName)
	if err != nil {
		return unavailableForError(err, input.RepoName)
	}
	return data
}

func unavailableForError(err error, repoName string) map[string]any {
	switch {
	case errors.Is(err, client.ErrUnauthorized):
		slog.Error("fortify sca auth rejected", "error", err, "repo_name", repoName)
		return authenticationRequired("The API rejected the credentials. Sign in again and verify the configured API host.")
	case errors.Is(err, client.ErrAuth):
		slog.Error("fortify sca authentication failed", "error", err, "repo_name", repoName)
		return authenticationRequired("Unable to obtain credentials. Sign in again using the configured credential source.")
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

func authenticationRequired(reason string) map[string]any {
	out := unavailable(reason)
	out["errorCode"] = "AUTHENTICATION_REQUIRED"
	return out
}
