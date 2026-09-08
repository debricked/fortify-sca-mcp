package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/debricked/Fortify-SCA-MCP/internal/config"
	"github.com/debricked/Fortify-SCA-MCP/pkg/server"
)

func main() {
	// stdout is reserved for MCP protocol messages; logs must go to stderr.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := run(); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration load failed", "error", err)
		return err
	}
	if cfg.Transport != "stdio" {
		return fmt.Errorf("unsupported transport: %s", cfg.Transport)
	}

	slog.Info("starting fortify sca mcp server",
		"transport", cfg.Transport,
		"fortify_sca_base_url", cfg.FortifyBaseURL,
		"fortify_sca_api_version", cfg.FortifyVersion,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("server ready, listening on stdio transport")
	err = server.Serve(ctx, server.Options{
		AccessToken: cfg.FortifyAccessToken,
		BaseURL:     cfg.FortifyBaseURL,
		APIVersion:  cfg.FortifyVersion,
	}, os.Stdin, os.Stdout)
	if errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled {
		slog.Info("shutdown signal received, stopping server")
		return nil
	}
	return err
}
