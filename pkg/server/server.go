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

Check each package, including transitive packages you explicitly pin. Supply one package as a
one-item purls array. For one user-approved set of alternative candidates, supply all candidates in
one purls array so they are checked in one API request.

For alternatives after a block, propose at most five specific versioned package URLs and ask the
user to approve that exact list before calling "check_dependency_policy_compliance" with purls.
Approval authorizes checking only, not using blocked packages. If no candidate passes, ask for fresh
approval before checking another list.

Make the Fortify SCA (Debricked) policy check visible in your final answer. For an approved
dependency, briefly name the checked package and version and say it passed the Fortify SCA
(Debricked) policy check. Only report approval for packages actually checked; never claim
approval or add the package when isPolicyCompliant is false, even if the result is not labeled
blocked.

If blocked, do not add the dependency. State that Fortify SCA (Debricked) policy blocked it,
identify the checked package and version, and report every returned blockingRules entry's
configuredCondition, triggeredBy evidence, and configurationUrl when present. Do not invent
missing rule details or infer which branch of an OR condition matched. If blockingRulesTruncated
is true, say the list is incomplete and give blockingRuleCount. Propose potential alternatives
only as unchecked candidates, not as compliant replacements. Ask the user to select a candidate
before checking it; do not automatically check a succession of alternatives. Check the selected
package before recommending or adding it, and only call it compliant after an approved result.

If the result is POLICY_CHECK_UNAVAILABLE, explain the reason and do not claim approval or
compliance; let the user decide before proceeding. If errorCode is AUTHENTICATION_REQUIRED and
the authenticate tool is available, ask permission to open browser login, call authenticate with
confirmed=true only after approval, then retry the original policy check once. Do not repeat
login if that retry is still unauthorized; report the API host or access issue instead.`

const checkDependencyPolicyDescription = `Check one dependency or a user-approved set of 1 to 5 distinct, versioned dependencies against this repository's Fortify SCA (Debricked) policies.

Provide purls containing one to five distinct, versioned package URLs. The server passes this array
to the policy API. For alternatives after a block, show the exact list and get the user's
approval before calling. Approval authorizes checking, not using blocked packages. Get fresh
approval before checking another list.

The API result contains per-package results and shared blockingRules. Join each result's
blockingRuleIds to the shared rules by ruleId and use each rule's matches entry for that package's
triggeredBy evidence. Do not apply one package's evidence to another. Report item errors as
POLICY_CHECK_UNAVAILABLE and never treat them as approvals.

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

Pass one to five package URLs in purls. A successful check returns the API's policy decision, including
blockingRules with configuredCondition, triggeredBy, and configurationUrl when available.
In your final answer, briefly name approved packages and versions that passed the Fortify SCA
(Debricked) policy check. Never claim approval or add a package if isPolicyCompliant is false.
If blocked, explain every returned rule, link to its configuration when available, and disclose
when blockingRulesTruncated is true. Do not claim unchecked alternatives
are compliant or automatically check multiple alternatives; ask the user to choose a candidate
before checking it. POLICY_CHECK_UNAVAILABLE means the policy could not be evaluated: report its
reason and do not treat it as approval.`

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
