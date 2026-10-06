package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/debricked/fortify-sca-mcp/v26/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeChecker struct {
	data  map[string]any
	err   error
	calls int
	purls []string
}

func (f *fakeChecker) CheckDependencyPolicy(_ context.Context, purls []string, _, _ string) (map[string]any, error) {
	f.calls++
	f.purls = append([]string(nil), purls...)
	return f.data, f.err
}

func TestPolicyReportingGuidance(t *testing.T) {
	for name, text := range map[string]string{
		"server instructions": serverInstructions,
		"tool description":    checkDependencyPolicyDescription,
	} {
		for _, required := range []string{
			"Fortify SCA (Debricked)",
			"configuredCondition",
			"triggeredBy",
			"configurationUrl",
			"blockingRulesTruncated",
			"isPolicyCompliant is false",
			"POLICY_CHECK_UNAVAILABLE",
			"purls",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s does not mention %q", name, required)
			}
		}
	}
}

func TestHandleCheckDependencyPolicyRequestUsesArrayForOneOrManyPURLs(t *testing.T) {
	groupedResponse := map[string]any{"status": "policy_checked"}
	tests := []struct {
		name  string
		purls []string
	}{
		{name: "one purl", purls: []string{"pkg:npm/react@16.0.0"}},
		{name: "multiple purls", purls: []string{"pkg:npm/react@16.0.0", "pkg:npm/react@19.0.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &fakeChecker{data: groupedResponse}
			out := handleCheckDependencyPolicyRequest(context.Background(), checker, CheckDependencyPolicyInput{
				PURLs: tt.purls, RepoURL: "https://github.com/acme/repo", RepoName: "acme/repo",
			})
			if checker.calls != 1 || !reflect.DeepEqual(checker.purls, tt.purls) {
				t.Fatalf("expected one array-based API check %v, got calls=%d purls=%v", tt.purls, checker.calls, checker.purls)
			}
			if !reflect.DeepEqual(out, groupedResponse) {
				t.Fatalf("expected API response passthrough, got %#v", out)
			}
		})
	}
}

func TestHandleCheckDependencyPolicyRequestRejectsEmptyPURLs(t *testing.T) {
	checker := &fakeChecker{data: map[string]any{"status": "policy_checked"}}
	out := handleCheckDependencyPolicyRequest(context.Background(), checker, CheckDependencyPolicyInput{
		RepoURL: "https://github.com/acme/repo", RepoName: "acme/repo",
	})
	if checker.calls != 0 {
		t.Fatalf("empty purls must not call checker, got %d calls", checker.calls)
	}
	if out["recommendation"] != unavailableRecommendation {
		t.Fatalf("expected unavailable response, got %#v", out)
	}
}

func TestHandleCheckDependencyPolicyRequestErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		purls  []string
		fake   fakeChecker
		assert func(t *testing.T, out map[string]any)
	}{
		{
			name:  "validation failure",
			purls: []string{"invalid"},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
		{
			name:  "unauthorized mapping",
			purls: []string{"pkg:npm/react@19.1.8"},
			fake:  fakeChecker{err: client.ErrUnauthorized},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
		{
			name:  "success passthrough",
			purls: []string{"pkg:npm/react@19.1.8"},
			fake:  fakeChecker{data: map[string]any{"recommendation": "ALLOWED"}},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != "ALLOWED" {
					t.Fatalf("expected passthrough data, got %#v", out)
				}
			},
		},
		{
			name:  "api status mapping",
			purls: []string{"pkg:npm/react@19.1.8"},
			fake:  fakeChecker{err: errors.Join(client.ErrAPIStatus, errors.New("boom"))},
			assert: func(t *testing.T, out map[string]any) {
				if out["recommendation"] != unavailableRecommendation {
					t.Fatalf("expected unavailable recommendation, got %#v", out)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := handleCheckDependencyPolicyRequest(context.Background(), &tt.fake, CheckDependencyPolicyInput{
				PURLs: tt.purls, RepoURL: "https://github.com/acme/repo", RepoName: "acme/repo",
			})
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

func TestNewServer_AcceptsTokenFetcherWithoutAccessToken(t *testing.T) {
	server, err := newServer(Options{
		TokenFetcher: func(context.Context) (string, error) { return "bearer-1", nil },
		BaseURL:      "https://fortify.example/",
	})
	if err != nil {
		t.Fatalf("expected server construction to succeed, got %v", err)
	}
	if server == nil {
		t.Fatal("expected configured server")
	}
}

func TestAuthenticateToolRecoversPolicyCallAfterUserConfirmation(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"status":"policy_checked","results":[{"purl":"pkg:npm/react@19.1.8","status":"policy_checked","recommendation":"allowed","isPolicyCompliant":true,"blockingRuleCount":0,"blockingRulesTruncated":false,"blockingRuleIds":[]}],"blockingRules":[]}`))
	}))
	defer api.Close()
	token := "old-token"
	logins := 0
	var loginErr error
	server, err := newServer(Options{
		BaseURL:      api.URL,
		TokenFetcher: func(context.Context) (string, error) { return token, nil },
		Authenticate: func(ctx context.Context) error {
			if _, bounded := ctx.Deadline(); !bounded {
				t.Error("login must have a deadline")
			}
			logins++
			if loginErr != nil {
				return loginErr
			}
			token = "new-token"
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	policyCall := &mcp.CallToolParams{
		Name:      "check_dependency_policy_compliance",
		Arguments: map[string]any{"purls": []string{"pkg:npm/react@19.1.8"}, "repo_url": "https://github.com/acme/repo", "repo_name": "acme/repo"},
	}
	result, err := session.CallTool(ctx, policyCall)
	if err != nil {
		t.Fatal(err)
	}
	if result.StructuredContent.(map[string]any)["errorCode"] != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("expected authentication required: %#v", result)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "authenticate", Arguments: map[string]any{"confirmed": false}})
	if err != nil || logins != 0 {
		t.Fatalf("unconfirmed login ran: %d, %v", logins, err)
	}
	if result.StructuredContent.(map[string]any)["status"] != "confirmation_required" {
		t.Fatalf("expected confirmation required: %#v", result)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "authenticate", Arguments: map[string]any{"confirmed": true}})
	if err != nil || logins != 1 {
		t.Fatalf("login failed: %d, %v", logins, err)
	}
	if result.StructuredContent.(map[string]any)["status"] != "credentials_loaded" {
		t.Fatalf("expected loaded credentials: %#v", result)
	}
	result, err = session.CallTool(ctx, policyCall)
	if err != nil {
		t.Fatal(err)
	}
	if result.StructuredContent.(map[string]any)["status"] != "policy_checked" {
		t.Fatalf("expected policy check after login: %#v", result)
	}
	loginErr = errors.New("test sensitive authentication details")
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "authenticate", Arguments: map[string]any{"confirmed": true}})
	if err != nil {
		t.Fatal(err)
	}
	content := result.StructuredContent.(map[string]any)
	if content["status"] != "authentication_failed" || strings.Contains(content["message"].(string), "sensitive") {
		t.Fatalf("login failure must not expose callback errors: %#v", result)
	}
}

func TestAuthenticateToolRequiresOAuthLoginCallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		options Options
		want    bool
	}{
		{name: "PAT", options: Options{AccessToken: "test-token", Authenticate: func(context.Context) error { return nil }}},
		{name: "fetch only", options: Options{TokenFetcher: func(context.Context) (string, error) { return "test-token", nil }}},
		{name: "OAuth login", options: Options{
			TokenFetcher: func(context.Context) (string, error) { return "test-token", nil },
			Authenticate: func(context.Context) error { return nil },
		}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := newServer(test.options)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			serverSession, err := server.Connect(ctx, serverTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer serverSession.Close()
			session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			tools, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, tool := range tools.Tools {
				found = found || tool.Name == "authenticate"
			}
			if found != test.want {
				t.Fatalf("authenticate tool present=%v, want %v", found, test.want)
			}
		})
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
