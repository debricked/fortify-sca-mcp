package main

import (
	"log/slog"
	"os"

	"fortify-sca-mcp/internal/server"
)

func main() {
	// stdout is reserved for MCP protocol messages; logs must go to stderr.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := server.Run(); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}
