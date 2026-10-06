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
	PURLs          []string `json:"purls"`
	RemoteURL      string   `json:"remoteUrl"`
	RepositoryName string   `json:"repositoryName"`
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

func (c *Client) InvalidateCredentials() {
	c.tokens.Invalidate()
}

func (c *Client) CheckDependencyPolicy(
	ctx context.Context,
	purls []string,
	repoURL string,
	repoName string,
) (map[string]any, error) {
	normalizedPURLs := make([]string, len(purls))
	for i, purl := range purls {
		normalizedPURLs[i] = strings.TrimSpace(purl)
	}

	payload, err := json.Marshal(checkPolicyRequest{
		PURLs:          normalizedPURLs,
		RemoteURL:      strings.TrimSpace(repoURL),
		RepositoryName: strings.Trim(strings.TrimSpace(repoName), "/"),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	_, body, err := c.postPolicy(ctx, payload)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response JSON: %w", err)
	}
	if err := validateBatchResponse(out, normalizedPURLs); err != nil {
		return nil, fmt.Errorf("invalid batch policy response: %w", err)
	}
	return out, nil
}

func (c *Client) postPolicy(ctx context.Context, payload []byte) (int, []byte, error) {
	status, body, err := c.do(ctx, payload)
	if err != nil {
		return 0, nil, err
	}

	// A cached bearer may have been revoked server-side; refresh once and retry.
	if status == http.StatusUnauthorized {
		slog.Warn("fortify sca api returned 401, refreshing token and retrying once")
		c.tokens.Invalidate()
		status, body, err = c.do(ctx, payload)
		if err != nil {
			return 0, nil, err
		}
	}

	if status == http.StatusUnauthorized {
		return status, nil, ErrUnauthorized
	}
	if status == http.StatusPaymentRequired {
		return status, nil, ErrEnterprise
	}

	if status < 200 || status >= 300 {
		slog.Error("fortify sca api returned an error status", "status", status)
		return status, nil, fmt.Errorf("%w (%d): %s", ErrAPIStatus, status, string(body))
	}

	return status, body, nil
}

func validateBatchResponse(envelope map[string]any, requested []string) error {
	if envelope["status"] != "policy_checked" {
		return errors.New("status must be policy_checked")
	}
	results, ok := envelope["results"].([]any)
	if !ok {
		return errors.New("results must be an array")
	}
	if len(results) != len(requested) {
		return fmt.Errorf("got %d results for %d requested packages", len(results), len(requested))
	}

	want := make(map[string]struct{}, len(requested))
	for _, purl := range requested {
		if _, duplicate := want[purl]; duplicate {
			return fmt.Errorf("duplicate requested package %q", purl)
		}
		want[purl] = struct{}{}
	}

	seen := make(map[string]struct{}, len(results))
	for _, rawResult := range results {
		result, ok := rawResult.(map[string]any)
		if !ok {
			return errors.New("each result must be an object")
		}
		purl, ok := result["purl"].(string)
		if !ok || purl == "" {
			return errors.New("each result must identify its purl")
		}
		if _, requested := want[purl]; !requested {
			return fmt.Errorf("response contains unrequested package %q", purl)
		}
		if _, duplicate := seen[purl]; duplicate {
			return fmt.Errorf("response contains duplicate result for %q", purl)
		}
		seen[purl] = struct{}{}
		switch result["status"] {
		case "policy_checked":
			if _, ok := result["isPolicyCompliant"].(bool); !ok {
				return fmt.Errorf("result for %q has no compliance decision", purl)
			}
			if _, ok := result["recommendation"].(string); !ok {
				return fmt.Errorf("result for %q has no recommendation", purl)
			}
			ids, ok := result["blockingRuleIds"].([]any)
			if !ok {
				return fmt.Errorf("result for %q has no blockingRuleIds array", purl)
			}
			count, ok := result["blockingRuleCount"].(float64)
			if !ok || count < float64(len(ids)) {
				return fmt.Errorf("result for %q has an invalid blockingRuleCount", purl)
			}
			truncated, ok := result["blockingRulesTruncated"].(bool)
			if !ok || (!truncated && count != float64(len(ids))) {
				return fmt.Errorf("result for %q has inconsistent blocking rule truncation metadata", purl)
			}
		case "error":
			if _, ok := result["errorCode"].(string); !ok {
				return fmt.Errorf("error result for %q has no errorCode", purl)
			}
			if _, ok := result["message"].(string); !ok {
				return fmt.Errorf("error result for %q has no message", purl)
			}
			if _, ok := result["retryable"].(bool); !ok {
				return fmt.Errorf("error result for %q has no retryable flag", purl)
			}
		default:
			return fmt.Errorf("result for %q has unexpected status", purl)
		}
	}
	for purl := range want {
		if _, found := seen[purl]; !found {
			return fmt.Errorf("response is missing result for %q", purl)
		}
	}

	ruleByID := make(map[string]map[string]any)
	if rawRules, exists := envelope["blockingRules"]; exists {
		rules, ok := rawRules.([]any)
		if !ok {
			return errors.New("blockingRules must be an array")
		}
		for _, rawRule := range rules {
			rule, ok := rawRule.(map[string]any)
			if !ok {
				return errors.New("each blocking rule must be an object")
			}
			id, exists := rule["ruleId"]
			if !exists {
				return errors.New("each blocking rule must have a ruleId")
			}
			key := fmt.Sprint(id)
			if _, duplicate := ruleByID[key]; duplicate {
				return fmt.Errorf("duplicate blocking rule %s", key)
			}
			matches, ok := rule["matches"].([]any)
			if !ok {
				return fmt.Errorf("blocking rule %s has no matches array", key)
			}
			for _, rawMatch := range matches {
				match, ok := rawMatch.(map[string]any)
				if !ok {
					return fmt.Errorf("blocking rule %s contains an invalid match", key)
				}
				purl, ok := match["purl"].(string)
				if !ok {
					return fmt.Errorf("blocking rule %s match has no purl", key)
				}
				if _, requested := want[purl]; !requested {
					return fmt.Errorf("blocking rule %s contains a match for unrequested package %q", key, purl)
				}
			}
			ruleByID[key] = rule
		}
	}
	for _, rawResult := range results {
		result := rawResult.(map[string]any)
		if result["status"] != "policy_checked" {
			continue
		}
		ids := result["blockingRuleIds"].([]any)
		truncated, _ := result["blockingRulesTruncated"].(bool)
		purl := result["purl"].(string)
		for _, id := range ids {
			rule, exists := ruleByID[fmt.Sprint(id)]
			if !exists {
				if truncated {
					continue
				}
				return fmt.Errorf("response omitted blocking rule %v for %q", id, purl)
			}
			matches, ok := rule["matches"].([]any)
			if !ok {
				return fmt.Errorf("blocking rule %v has no matches array", id)
			}
			matched := false
			for _, rawMatch := range matches {
				match, ok := rawMatch.(map[string]any)
				if ok && match["purl"] == purl {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("blocking rule %v has no match for %q", id, purl)
			}
		}
	}
	return nil
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
