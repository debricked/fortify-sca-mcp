package policy

import "context"

// Checker is the policy operation required by the MCP adapter.
type Checker interface {
	CheckDependencyPolicy(ctx context.Context, purl, repoURL, repoName string) (map[string]any, error)
}
