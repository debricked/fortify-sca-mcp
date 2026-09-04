package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

const (
	// defaultFortifyBaseURL points at the Debricked-backed Fortify SCA API.
	defaultFortifyBaseURL = "https://debricked.com"
	defaultFortifyVersion = "1.0"
	defaultTransport      = "stdio"
)

type Config struct {
	FortifyAccessToken string
	FortifyBaseURL     string
	FortifyVersion     string
	Transport          string
}

func Load() (Config, error) {
	if err := loadEnv(); err != nil {
		return Config{}, err
	}

	token, err := getRequiredEnv(
		"FORTIFY_SCA_ACCESS_TOKEN",
		"Your long-lived Fortify SCA access token. You can generate one at https://debricked.com/app/en/admin/tools",
	)
	if err != nil {
		return Config{}, fmt.Errorf("configuration validation failed: %w", err)
	}

	cfg := Config{
		FortifyAccessToken: token,
		FortifyBaseURL:     getOptionalEnv("FORTIFY_SCA_BASE_URL", defaultFortifyBaseURL),
		FortifyVersion:     getOptionalEnv("FORTIFY_SCA_API_VERSION", defaultFortifyVersion),
		Transport:          strings.ToLower(getOptionalEnv("MCP_TRANSPORT", defaultTransport)),
	}

	if cfg.Transport != "stdio" {
		return Config{}, fmt.Errorf("configuration validation failed: MCP_TRANSPORT must be 'stdio' for this Go build")
	}

	return cfg, nil
}

func loadEnv() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}

	envPath := filepath.Join(cwd, ".env")
	if _, err := os.Stat(envPath); err == nil {
		if err := godotenv.Load(envPath); err != nil {
			return fmt.Errorf("load .env: %w", err)
		}
	}

	return nil
}

func getRequiredEnv(key, description string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value != "" {
		return value, nil
	}

	msg := fmt.Sprintf("missing required environment variable: %s", key)
	if description != "" {
		msg += fmt.Sprintf(" (%s)", description)
	}
	return "", errors.New(msg)
}

func getOptionalEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
