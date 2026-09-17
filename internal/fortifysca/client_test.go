package fortifysca

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/debricked/fortify-sca-mcp/v26/internal/auth"
)

type stubProvider struct {
	token       string
	err         error
	tokenCalls  int
	invalidated int
}

func (s *stubProvider) Token(context.Context) (string, error) {
	s.tokenCalls++
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}

func (s *stubProvider) Invalidate() { s.invalidated++ }

func newTestClient(baseURL string) *Client {
	return NewClient(baseURL, "1.0", &stubProvider{token: "token"})
}

func TestCheckDependencyPolicy_StatusMappings(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    error
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized, body: "unauthorized", wantErr: ErrUnauthorized},
		{name: "enterprise", statusCode: http.StatusPaymentRequired, body: "payment", wantErr: ErrEnterprise},
		{name: "status error", statusCode: http.StatusBadRequest, body: "bad request", wantErr: ErrAPIStatus},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			client := newTestClient(srv.URL)
			_, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestCheckDependencyPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"recommendation":"ALLOWED"}`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	out, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["recommendation"] != "ALLOWED" {
		t.Fatalf("unexpected response: %#v", out)
	}
}

func TestCheckDependencyPolicy_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"recommendation":"ALLOWED"}`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	client.timeout = 5 * time.Millisecond

	_, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestCheckDependencyPolicy_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
	if err == nil || !strings.Contains(err.Error(), "decode response JSON") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestCheckDependencyPolicy_RefreshesOnUnauthorized(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"recommendation":"ALLOWED"}`))
	}))
	defer srv.Close()

	provider := &stubProvider{token: "token"}
	client := NewClient(srv.URL, "1.0", provider)

	out, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["recommendation"] != "ALLOWED" {
		t.Fatalf("unexpected response: %#v", out)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if provider.invalidated != 1 {
		t.Fatalf("expected 1 invalidation, got %d", provider.invalidated)
	}
}

func TestCheckDependencyPolicy_StopsAfterOneRetry(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	provider := &stubProvider{token: "token"}
	client := NewClient(srv.URL, "1.0", provider)

	_, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected exactly 2 attempts, got %d", attempts)
	}
}

func TestCheckDependencyPolicy_AuthErrorMapping(t *testing.T) {
	tests := []struct {
		name        string
		providerErr error
		wantErr     error
	}{
		{name: "login unauthorized", providerErr: auth.ErrLoginUnauthorized, wantErr: ErrUnauthorized},
		{name: "login timeout", providerErr: auth.ErrLoginTimeout, wantErr: ErrTimeout},
		{name: "login status", providerErr: auth.ErrLoginStatus, wantErr: ErrAuth},
		{name: "login response", providerErr: auth.ErrLoginResponse, wantErr: ErrAuth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient("https://example.invalid", "1.0", &stubProvider{err: tt.providerErr})
			_, err := client.CheckDependencyPolicy(context.Background(), "pkg:npm/react@19.1.8", "https://github.com/acme/repo", "acme/repo")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}
