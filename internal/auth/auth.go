package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrLoginUnauthorized = errors.New("login-unauthorized")
	ErrLoginTimeout      = errors.New("login-timeout")
	ErrLoginStatus       = errors.New("login-status-error")
	ErrLoginResponse     = errors.New("login-response-invalid")
)

const (
	defaultTimeout      = 30 * time.Second
	defaultSkew         = 60 * time.Second
	defaultFallbackTTL  = 50 * time.Minute
	maxIdleConnsPerHost = 10
)

type TokenProvider interface {
	Token(ctx context.Context) (string, error)
	Invalidate()
}

// RefreshTokenProvider exchanges a long-lived Fortify SCA access token for short-lived bearer tokens.
type RefreshTokenProvider struct {
	httpClient  *http.Client
	loginURL    string
	accessToken string
	timeout     time.Duration
	skew        time.Duration
	fallbackTTL time.Duration
	now         func() time.Time

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func NewRefreshTokenProvider(baseURL, accessToken string) *RefreshTokenProvider {
	return &RefreshTokenProvider{
		httpClient:  newHTTPClient(),
		loginURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/api/login_refresh",
		accessToken: strings.TrimSpace(accessToken),
		timeout:     defaultTimeout,
		skew:        defaultSkew,
		fallbackTTL: defaultFallbackTTL,
		now:         time.Now,
	}
}

func newHTTPClient() *http.Client {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return &http.Client{Transport: baseTransport}
}

func (p *RefreshTokenProvider) Token(ctx context.Context) (string, error) {
	// Held across refresh so concurrent callers share a single login request.
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cached != "" && p.now().Before(p.expiresAt) {
		return p.cached, nil
	}

	return p.refresh(ctx)
}

func (p *RefreshTokenProvider) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cached = ""
	p.expiresAt = time.Time{}
}

func (p *RefreshTokenProvider) refresh(ctx context.Context) (string, error) {
	slog.Debug("refreshing fortify sca bearer token", "login_url", p.loginURL)

	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	form := url.Values{"refresh_token": {p.accessToken}}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, p.loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			slog.Error("fortify sca login request timed out")
			return "", fmt.Errorf("%w: %v", ErrLoginTimeout, err)
		}
		slog.Error("fortify sca login request failed", "error", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		slog.Error("fortify sca login rejected", "status", resp.StatusCode)
		return "", ErrLoginUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Error("fortify sca login returned unexpected status", "status", resp.StatusCode)
		// Body is intentionally omitted; it may echo credential material.
		return "", fmt.Errorf("%w (%d)", ErrLoginStatus, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read login response body: %w", err)
	}

	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		slog.Error("fortify sca login response was malformed")
		return "", fmt.Errorf("%w: malformed login response", ErrLoginResponse)
	}

	token := strings.TrimSpace(payload.Token)
	if token == "" {
		slog.Error("fortify sca login response contained no token")
		return "", fmt.Errorf("%w: login response contained no token", ErrLoginResponse)
	}

	if exp, ok := expiryFromJWT(token); ok {
		p.expiresAt = exp.Add(-p.skew)
	} else {
		p.expiresAt = p.now().Add(p.fallbackTTL)
	}
	p.cached = token

	slog.Debug("fortify sca bearer token refreshed", "expires_at", p.expiresAt)
	return token, nil
}

func expiryFromJWT(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}

	return time.Unix(claims.Exp, 0), true
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
