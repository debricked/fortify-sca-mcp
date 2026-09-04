package config

import "testing"

func TestLoad_ConfigValidation(t *testing.T) {
	t.Setenv("FORTIFY_SCA_ACCESS_TOKEN", "token")
	t.Setenv("MCP_TRANSPORT", "stdio")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load, got err: %v", err)
	}
	if cfg.FortifyAccessToken != "token" {
		t.Fatalf("unexpected token: %q", cfg.FortifyAccessToken)
	}
}

func TestLoad_UsesFortifyOptionalOverrides(t *testing.T) {
	t.Setenv("FORTIFY_SCA_ACCESS_TOKEN", "token")
	t.Setenv("FORTIFY_SCA_BASE_URL", "https://fortify.example")
	t.Setenv("FORTIFY_SCA_API_VERSION", "2.0")
	t.Setenv("MCP_TRANSPORT", "stdio")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load, got err: %v", err)
	}
	if cfg.FortifyBaseURL != "https://fortify.example" {
		t.Fatalf("unexpected base url: %q", cfg.FortifyBaseURL)
	}
	if cfg.FortifyVersion != "2.0" {
		t.Fatalf("unexpected api version: %q", cfg.FortifyVersion)
	}
}

func TestLoad_UsesFortifyOptionalDefaults(t *testing.T) {
	t.Setenv("FORTIFY_SCA_ACCESS_TOKEN", "token")
	t.Setenv("FORTIFY_SCA_BASE_URL", "")
	t.Setenv("FORTIFY_SCA_API_VERSION", "")
	t.Setenv("MCP_TRANSPORT", "stdio")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected config to load, got err: %v", err)
	}
	if cfg.FortifyBaseURL != "https://debricked.com" {
		t.Fatalf("unexpected default base url: %q", cfg.FortifyBaseURL)
	}
	if cfg.FortifyVersion != "1.0" {
		t.Fatalf("unexpected default api version: %q", cfg.FortifyVersion)
	}
}

func TestLoad_RequiresToken(t *testing.T) {
	t.Setenv("FORTIFY_SCA_ACCESS_TOKEN", "")
	t.Setenv("MCP_TRANSPORT", "stdio")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when token is missing")
	}
}

func TestLoad_RejectsNonStdioTransport(t *testing.T) {
	t.Setenv("FORTIFY_SCA_ACCESS_TOKEN", "token")
	t.Setenv("MCP_TRANSPORT", "http")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for non-stdio transport")
	}
}
