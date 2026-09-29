package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyAccessToken(t *testing.T) {
	tests := []struct {
		name      string
		accessTok string
		handler   http.HandlerFunc
		wantErr   bool
		wantErrIs error
	}{
		{
			name:      "missing token",
			accessTok: "",
			wantErr:   true,
		},
		{
			name:      "success",
			accessTok: "refresh-token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"token":"bearer-1"}`))
			},
		},
		{
			name:      "unauthorized",
			accessTok: "bad-token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			wantErr:   true,
			wantErrIs: ErrUnauthorized,
		},
		{
			name:      "server error",
			accessTok: "refresh-token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr:   true,
			wantErrIs: ErrLoginStatus,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL := ""
			if tt.handler != nil {
				srv := httptest.NewServer(tt.handler)
				t.Cleanup(srv.Close)
				baseURL = srv.URL
			}

			err := VerifyAccessToken(context.Background(), Options{AccessToken: tt.accessTok, BaseURL: baseURL})

			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("expected error to match %v, got %v", tt.wantErrIs, err)
			}
		})
	}
}

func TestVerifyAccessToken_WithTokenFetcher(t *testing.T) {
	err := VerifyAccessToken(context.Background(), Options{
		TokenFetcher: func(context.Context) (string, error) {
			return "bearer-1", nil
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestVerifyAccessToken_TokenFetcherError(t *testing.T) {
	wantErr := errors.New("no cached login")
	err := VerifyAccessToken(context.Background(), Options{
		TokenFetcher: func(context.Context) (string, error) {
			return "", wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

func TestVerifyAccessToken_NeitherAccessTokenNorFetcherSet(t *testing.T) {
	err := VerifyAccessToken(context.Background(), Options{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
