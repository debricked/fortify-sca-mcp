package server

import (
	"context"
	"errors"
	"testing"

	"fortify-sca-mcp/internal/fortifysca"
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
			fake: fakeChecker{err: fortifysca.ErrUnauthorized},
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
			fake: fakeChecker{err: errors.Join(fortifysca.ErrAPIStatus, errors.New("boom"))},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := HandleCheckDependencyPolicyCompliance(
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
