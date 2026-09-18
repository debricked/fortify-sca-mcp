package server

import (
	"context"
	"errors"
	"strings"

	"github.com/debricked/fortify-sca-mcp/v26/internal/auth"
)

// Re-exported so callers (e.g. the Debricked CLI) can distinguish failure
// reasons from VerifyAccessToken without importing this module's internal packages.
var (
	ErrUnauthorized  = auth.ErrLoginUnauthorized
	ErrLoginTimeout  = auth.ErrLoginTimeout
	ErrLoginStatus   = auth.ErrLoginStatus
	ErrLoginResponse = auth.ErrLoginResponse
)

// VerifyAccessToken checks that options.AccessToken can be exchanged for a
// short-lived bearer token, without registering or running any MCP tools.
// It lets a caller fail fast on bad credentials before starting the stdio
// server, rather than only discovering the problem on the first tool call.
func VerifyAccessToken(ctx context.Context, options Options) error {
	options.AccessToken = strings.TrimSpace(options.AccessToken)
	options.BaseURL = strings.TrimRight(strings.TrimSpace(options.BaseURL), "/")

	if options.AccessToken == "" {
		return errors.New("access token is required")
	}
	if options.BaseURL == "" {
		options.BaseURL = defaultBaseURL
	}

	provider := auth.NewRefreshTokenProvider(options.BaseURL, options.AccessToken)
	_, err := provider.Token(ctx)

	return err
}
