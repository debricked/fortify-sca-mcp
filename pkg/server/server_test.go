package server

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/debricked/fortify-sca-mcp/v26/internal/client"
)

type fakeChecker struct {
	data map[string]any
	err  error
}

func (f fakeChecker) CheckDependencyPolicy(context.Context, string, string, string) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}

func TestHandleCheckDependencyPolicyCompliance(t *testing.T) {
	tests := []struct {
		name   string
		input  CheckDependencyPolicyInput
		fake   fakeChecker
		assert func(t *testing.T, out map[string]any)
	}{
		{
			name: "validation failure",
			input: CheckDependencyPolicyInput{
				PURL:     "invalid",
				RepoURL:  "https://github.com/acme/repo",
				RepoName: "acme/repo",
			},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
		{
			name: "unauthorized mapping",
			input: CheckDependencyPolicyInput{
				PURL:     "pkg:npm/react@19.1.8",
				RepoURL:  "https://github.com/acme/repo",
				RepoName: "acme/repo",
			},
			fake: fakeChecker{err: client.ErrUnauthorized},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
		{
			name: "success passthrough",
			input: CheckDependencyPolicyInput{
				PURL:     "pkg:npm/react@19.1.8",
				RepoURL:  "https://github.com/acme/repo",
				RepoName: "acme/repo",
			},
			fake: fakeChecker{data: map[string]any{"recommendation": "ALLOWED"}},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != "ALLOWED" {
					t.Fatalf("expected passthrough data, got %#v", out)
				}
			},
		},
		{
			name: "api status mapping",
			input: CheckDependencyPolicyInput{
				PURL:     "pkg:npm/react@19.1.8",
				RepoURL:  "https://github.com/acme/repo",
				RepoName: "acme/repo",
			},
			fake: fakeChecker{err: errors.Join(client.ErrAPIStatus, errors.New("boom"))},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := handleCheckDependencyPolicyCompliance(
				context.Background(),
				tt.fake,
				tt.input.PURL,
				tt.input.RepoURL,
				tt.input.RepoName,
			)
			tt.assert(t, out)
		})
	}
}

func TestServe_RequiresAccessToken(t *testing.T) {
	err := Serve(context.Background(), Options{BaseURL: "https://fortify.example"}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatal("expected missing access token error")
	}
}

func TestNewServer_CreatesServerWithHostSuppliedOptions(t *testing.T) {
	server, err := newServer(Options{
		AccessToken: " access-token ",
		BaseURL:     "https://fortify.example/",
		APIVersion:  " 2.0 ",
	})
	if err != nil {
		t.Fatalf("expected server construction to succeed, got %v", err)
	}
	if server == nil {
		t.Fatal("expected configured server")
	}
}

func TestServe_RequiresStreams(t *testing.T) {
	tests := []struct {
		name   string
		input  io.Reader
		output io.Writer
	}{
		{name: "missing input", output: io.Discard},
		{name: "missing output", input: strings.NewReader("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Serve(context.Background(), Options{AccessToken: "token"}, tt.input, tt.output)
			if err == nil {
				t.Fatal("expected stream validation error")
			}
		})
	}
}
