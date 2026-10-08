package policy

import "context"

// Checker checks one or more package URLs in a single policy request.
type Checker interface {
	CheckDependencyPolicy(ctx context.Context, purls []string, repoURL, repoName string) (map[string]any, error)
}
