package client

import (
	"github.com/debricked/Fortify-SCA-MCP/internal/auth"
	"github.com/debricked/Fortify-SCA-MCP/internal/fortifysca"
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

func New(baseURL, apiVersion, accessToken string) *PolicyChecker {
	provider := auth.NewRefreshTokenProvider(baseURL, accessToken)
	return fortifysca.NewClient(baseURL, apiVersion, provider)
}
