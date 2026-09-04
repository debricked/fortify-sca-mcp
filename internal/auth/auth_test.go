package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func jwtWithExp(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return "header." + payload + ".signature"
}

func newTestProvider(t *testing.T, handler http.HandlerFunc) (*RefreshTokenProvider, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return NewRefreshTokenProvider(srv.URL, "access-token"), srv
}

func TestToken_SendsFormEncodedRefreshToken(t *testing.T) {
	var gotContentType, gotRefreshToken, gotPath string

	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotContentType = r.Header.Get("Content-Type")
		gotRefreshToken = r.PostFormValue("refresh_token")
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"token":"bearer-1"}`))
	})

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "bearer-1" {
		t.Fatalf("unexpected token: %q", token)
	}
	if gotPath != "/api/login_refresh" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("unexpected content type: %q", gotContentType)
	}
	if gotRefreshToken != "access-token" {
		t.Fatalf("unexpected refresh_token: %q", gotRefreshToken)
	}
}

func TestToken_CachesUntilExpiry(t *testing.T) {
	calls := 0
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprintf(w, `{"token":%q}`, jwtWithExp(time.Now().Add(time.Hour)))
	})

	for i := 0; i < 3; i++ {
		if _, err := provider.Token(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if calls != 1 {
		t.Fatalf("expected 1 login call, got %d", calls)
	}
}

func TestToken_RefreshesAfterExpiry(t *testing.T) {
	calls := 0
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprintf(w, `{"token":"bearer-%d"}`, calls)
	})

	now := time.Now()
	provider.now = func() time.Time { return now }

	first, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now = now.Add(defaultFallbackTTL + time.Minute)

	second, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first == second || calls != 2 {
		t.Fatalf("expected refresh, got %q then %q after %d calls", first, second, calls)
	}
}

func TestInvalidate_ForcesRefresh(t *testing.T) {
	calls := 0
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprintf(w, `{"token":"bearer-%d"}`, calls)
	})

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	provider.Invalidate()
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 2 {
		t.Fatalf("expected 2 login calls, got %d", calls)
	}
}

func TestToken_UsesJWTExpiryWithSkew(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"token":%q}`, jwtWithExp(exp))
	})

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := exp.Add(-defaultSkew)
	if !provider.expiresAt.Equal(want) {
		t.Fatalf("expected expiry %v, got %v", want, provider.expiresAt)
	}
}

func TestToken_FallsBackToTTLForOpaqueToken(t *testing.T) {
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"opaque-token"}`))
	})

	now := time.Now()
	provider.now = func() time.Time { return now }

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := now.Add(defaultFallbackTTL)
	if !provider.expiresAt.Equal(want) {
		t.Fatalf("expected expiry %v, got %v", want, provider.expiresAt)
	}
}

func TestToken_ErrorMappings(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    error
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized, body: "nope", wantErr: ErrLoginUnauthorized},
		{name: "forbidden", statusCode: http.StatusForbidden, body: "nope", wantErr: ErrLoginUnauthorized},
		{name: "server error", statusCode: http.StatusInternalServerError, body: "boom", wantErr: ErrLoginStatus},
		{name: "malformed json", statusCode: http.StatusOK, body: "not-json", wantErr: ErrLoginResponse},
		{name: "empty token", statusCode: http.StatusOK, body: `{"token":""}`, wantErr: ErrLoginResponse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			})

			_, err := provider.Token(context.Background())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestToken_Timeout(t *testing.T) {
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		_, _ = w.Write([]byte(`{"token":"bearer-1"}`))
	})
	provider.timeout = 5 * time.Millisecond

	_, err := provider.Token(context.Background())
	if !errors.Is(err, ErrLoginTimeout) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestToken_ErrorDoesNotLeakAccessToken(t *testing.T) {
	provider, _ := newTestProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("access-token leaked in body"))
	})

	_, err := provider.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "login-status-error (500)" {
		t.Fatalf("unexpected error message: %q", got)
	}
}
