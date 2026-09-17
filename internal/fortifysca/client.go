package fortifysca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/debricked/fortify-sca-mcp/v26/internal/auth"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrEnterprise   = errors.New("enterprise-required")
	ErrTimeout      = errors.New("request-timeout")
	ErrAPIStatus    = errors.New("api-status-error")
	ErrAuth         = errors.New("auth-error")
)

const (
	defaultTimeout      = 30 * time.Second
	maxIdleConnsPerHost = 20
)

type Client struct {
	httpClient *http.Client
	endpoint   string
	tokens     auth.TokenProvider
	timeout    time.Duration
}

type checkPolicyRequest struct {
	PURL           string `json:"purl"`
	RemoteURL      string `json:"remoteUrl"`
	RepositoryName string `json:"repositoryName"`
}

func NewClient(baseURL, apiVersion string, tokens auth.TokenProvider) *Client {
	endpoint := fmt.Sprintf(
		"%s/api/%s/open/repository/check-dependency-policy",
		strings.TrimRight(baseURL, "/"),
		strings.TrimSpace(apiVersion),
	)

	return &Client{
		httpClient: newHTTPClient(),
		endpoint:   endpoint,
		tokens:     tokens,
		timeout:    defaultTimeout,
	}
}

func newHTTPClient() *http.Client {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return &http.Client{Transport: baseTransport}
}

func (c *Client) CheckDependencyPolicy(
	ctx context.Context,
	purl string,
	repoURL string,
	repoName string,
) (map[string]any, error) {
	payload, err := json.Marshal(checkPolicyRequest{
		PURL:           strings.TrimSpace(purl),
		RemoteURL:      strings.TrimSpace(repoURL),
		RepositoryName: strings.Trim(strings.TrimSpace(repoName), "/"),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	status, body, err := c.do(ctx, payload)
	if err != nil {
		return nil, err
	}

	// A cached bearer may have been revoked server-side; refresh once and retry.
	if status == http.StatusUnauthorized {
		slog.Warn("fortify sca api returned 401, refreshing token and retrying once")
		c.tokens.Invalidate()
		status, body, err = c.do(ctx, payload)
		if err != nil {
			return nil, err
		}
	}

	if status == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if status == http.StatusPaymentRequired {
		return nil, ErrEnterprise
	}

	if status < 200 || status >= 300 {
		slog.Error("fortify sca api returned an error status", "status", status)
		return nil, fmt.Errorf("%w (%d): %s", ErrAPIStatus, status, string(body))
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response JSON: %w", err)
	}

	return out, nil
}

func (c *Client) do(ctx context.Context, payload []byte) (int, []byte, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		slog.Error("failed to obtain fortify sca bearer token", "error", err)
		return 0, nil, mapAuthError(err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	slog.Debug("calling fortify sca api", "endpoint", c.endpoint)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			slog.Error("fortify sca api request timed out", "endpoint", c.endpoint)
			return 0, nil, fmt.Errorf("%w: %v", ErrTimeout, err)
		}
		slog.Error("fortify sca api request failed", "endpoint", c.endpoint, "error", err)
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read response body: %w", err)
	}

	return resp.StatusCode, body, nil
}

func mapAuthError(err error) error {
	switch {
	case errors.Is(err, auth.ErrLoginUnauthorized):
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	case errors.Is(err, auth.ErrLoginTimeout):
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	default:
		return fmt.Errorf("%w: %v", ErrAuth, err)
	}
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
