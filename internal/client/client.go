package client

import (
	"context"

	"github.com/debricked/fortify-sca-mcp/v26/internal/auth"
	"github.com/debricked/fortify-sca-mcp/v26/internal/fortifysca"
)

// PolicyChecker is the client capability required by the policy domain.
type PolicyChecker = fortifysca.Client

var (
	ErrUnauthorized = fortifysca.ErrUnauthorized
	ErrEnterprise   = fortifysca.ErrEnterprise
	ErrTimeout      = fortifysca.ErrTimeout
	ErrAPIStatus    = fortifysca.ErrAPIStatus
	ErrAuth         = fortifysca.ErrAuth
)

// New builds a client that exchanges a long-lived access token for short-lived
// bearer tokens via /api/login_refresh.
func New(baseURL, apiVersion, accessToken string) *PolicyChecker {
	provider := auth.NewRefreshTokenProvider(baseURL, accessToken)
	return fortifysca.NewClient(baseURL, apiVersion, provider)
}

// NewWithTokenFetcher builds a client that calls fetch on demand for a currently-valid
// bearer token, instead of exchanging a stored credential itself. Useful when the
// caller already owns token refresh/rotation (e.g. an existing OAuth session).
func NewWithTokenFetcher(baseURL, apiVersion string, fetch func(ctx context.Context) (string, error)) *PolicyChecker {
	provider := auth.NewCallbackTokenProvider(fetch)
	return fortifysca.NewClient(baseURL, apiVersion, provider)
}
