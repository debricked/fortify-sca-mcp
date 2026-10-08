package fortifysca

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
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
			_, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestCheckDependencyPolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/1.0/open/agent/policy-check/check-dependency-policy" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !reflect.DeepEqual(request["purls"], []any{"pkg:npm/react@19.1.8"}) {
			t.Fatalf("expected one-item purls array, got %#v", request)
		}
		if request["repositoryUrl"] != "https://github.com/acme/repo" || request["repositoryName"] != "acme/repo" {
			t.Fatalf("unexpected repository fields: %#v", request)
		}
		if _, exists := request["remoteUrl"]; exists {
			t.Fatalf("unexpected legacy remoteUrl field: %#v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"status":"policy_checked",
			"repositoryId":2,
			"repositoryName":"acme/repo",
			"results":[{"purl":"pkg:npm/react@19.1.8","status":"policy_checked","isPolicyCompliant":false,"recommendation":"blocked","blockingRuleCount":1,"blockingRulesTruncated":false,"blockingRuleIds":[80],"nextAction":"find_alternative_and_recheck"}],
			"blockingRules":[
				{"ruleId":80,"configuredCondition":"If a dependency contains a vulnerability","matches":[{"purl":"pkg:npm/react@19.1.8","triggeredBy":[{"type":"vulnerability","values":["CVE-2018-6341"]}]}],"configurationUrl":"https://example.com/app/en/automations/2?ruleId=80"}
			],
			"rulesUrl":"https://example.com/app/en/automations/2"
		}`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	out, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := out["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected one result: %#v", out)
	}
	result := results[0].(map[string]any)
	if result["recommendation"] != "blocked" || result["blockingRuleCount"] != float64(1) || result["blockingRulesTruncated"] != false {
		t.Fatalf("unexpected response: %#v", out)
	}
	rules, ok := out["blockingRules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected one blocking rule: %#v", out)
	}
	first, ok := rules[0].(map[string]any)
	if !ok || first["configuredCondition"] != "If a dependency contains a vulnerability" || first["configurationUrl"] != "https://example.com/app/en/automations/2?ruleId=80" {
		t.Fatalf("missing first rule detail: %#v", rules[0])
	}
	matches := first["matches"].([]any)
	triggeredBy, ok := matches[0].(map[string]any)["triggeredBy"].([]any)
	if !ok || len(triggeredBy) != 1 || triggeredBy[0].(map[string]any)["type"] != "vulnerability" {
		t.Fatalf("expected package-scoped evidence: %#v", first)
	}
	if _, exists := out["reason"]; exists {
		t.Fatalf("unexpected top-level reason: %#v", out)
	}
}

func TestCheckDependencyPolicy_PreservesGroupedMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/1.0/open/agent/policy-check/check-dependency-policy" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if !reflect.DeepEqual(request["purls"], []any{"pkg:npm/react@16.0.0", "pkg:npm/react@19.0.0"}) {
			t.Fatalf("unexpected request: %#v", request)
		}
		_, _ = w.Write([]byte(`{
			"status":"policy_checked",
			"results":[
				{"purl":"pkg:npm/react@16.0.0","status":"policy_checked","isPolicyCompliant":false,"recommendation":"blocked","blockingRuleCount":2,"blockingRulesTruncated":false,"blockingRuleIds":[80,246]},
				{"purl":"pkg:npm/react@19.0.0","status":"policy_checked","isPolicyCompliant":false,"recommendation":"blocked","blockingRuleCount":1,"blockingRulesTruncated":false,"blockingRuleIds":[246]}
			],
			"blockingRules":[
				{"ruleId":80,"matches":[{"purl":"pkg:npm/react@16.0.0","triggeredBy":[{"type":"vulnerability","values":["CVE-2018-6341"]}]}]},
				{"ruleId":246,"matches":[{"purl":"pkg:npm/react@16.0.0","triggeredBy":[{"type":"license","values":["MIT"]}]},{"purl":"pkg:npm/react@19.0.0","triggeredBy":[{"type":"license","values":["MIT"]}]}]}
			]
		}`))
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	out, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@16.0.0", "pkg:npm/react@19.0.0"}, "https://github.com/acme/repo", "acme/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rules := out["blockingRules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("expected grouped rules unchanged: %#v", rules)
	}
	sharedRule := rules[1].(map[string]any)
	if len(sharedRule["matches"].([]any)) != 2 {
		t.Fatalf("expected rule matches grouped for both packages: %#v", sharedRule)
	}
}

func TestCheckDependencyPolicy_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"policy_checked","results":[{"purl":"pkg:npm/react@19.1.8","status":"policy_checked","isPolicyCompliant":true,"recommendation":"allowed","blockingRuleCount":0,"blockingRulesTruncated":false,"blockingRuleIds":[],"nextAction":"continue"}],"blockingRules":[]}`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	client.timeout = 5 * time.Millisecond

	_, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
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
	_, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
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
		_, _ = w.Write([]byte(`{"status":"policy_checked","results":[{"purl":"pkg:npm/react@19.1.8","status":"policy_checked","isPolicyCompliant":true,"recommendation":"allowed","blockingRuleCount":0,"blockingRulesTruncated":false,"blockingRuleIds":[],"nextAction":"continue"}],"blockingRules":[]}`))
	}))
	defer srv.Close()

	provider := &stubProvider{token: "token"}
	client := NewClient(srv.URL, "1.0", provider)

	out, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := out["results"].([]any)
	if len(results) != 1 || results[0].(map[string]any)["recommendation"] != "allowed" {
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

	_, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
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
			_, err := client.CheckDependencyPolicy(context.Background(), []string{"pkg:npm/react@19.1.8"}, "https://github.com/acme/repo", "acme/repo")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}
