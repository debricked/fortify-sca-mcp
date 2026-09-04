package validators

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	purlPattern      = regexp.MustCompile(`^pkg:[a-zA-Z0-9]+/.+@.+$`)
	httpsRepoPattern = regexp.MustCompile(`^https?://[a-zA-Z0-9.\-]+/(.+)$`)
	sshRepoPattern   = regexp.MustCompile(`^git@[a-zA-Z0-9.\-]+:(.+)$`)
	slugPartPattern  = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)
)

func ValidatePURL(purl string) (bool, string) {
	purl = strings.TrimSpace(purl)
	if purl == "" {
		return false, "purl cannot be empty"
	}

	if !purlPattern.MatchString(purl) {
		return false, fmt.Sprintf(
			"Invalid purl format: '%s'. Expected format: pkg:type/namespace/name@version (e.g., pkg:npm/lodash@4.17.21)",
			purl,
		)
	}

	if !strings.Contains(purl, "@") {
		return false, "purl must include a version after '@' (e.g., pkg:npm/lodash@4.17.21)"
	}

	return true, ""
}

func ValidateRepoURL(repoURL string) (bool, string) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return false, "repo_url cannot be empty"
	}

	var path string
	if m := httpsRepoPattern.FindStringSubmatch(repoURL); len(m) == 2 {
		path = strings.TrimSpace(m[1])
	} else if m := sshRepoPattern.FindStringSubmatch(repoURL); len(m) == 2 {
		path = strings.TrimSpace(m[1])
	} else {
		return false, fmt.Sprintf(
			"Invalid repo_url format: '%s'. Must be a valid Git repository URL in SSH or HTTPS format (e.g., https://github.com/owner/repo or git@github.com:owner/repo.git)",
			repoURL,
		)
	}

	path = strings.TrimSuffix(path, ".git")
	parts := splitPathParts(path)
	if len(parts) < 2 {
		return false, fmt.Sprintf(
			"Invalid repo_url format: '%s'. Repository path must include at least owner/repo",
			repoURL,
		)
	}

	for _, part := range parts {
		if !slugPartPattern.MatchString(part) {
			return false, fmt.Sprintf(
				"Invalid repo_url format: '%s'. Path segment '%s' contains invalid characters",
				repoURL,
				part,
			)
		}
	}

	return true, ""
}

func ValidateRepoName(repoName string) (bool, string) {
	repoName = strings.Trim(strings.TrimSpace(repoName), "/")
	if repoName == "" {
		return false, "repo_name cannot be empty"
	}

	parts := strings.Split(repoName, "/")
	if len(parts) < 2 {
		return false, fmt.Sprintf(
			"Invalid repo_name format: '%s'. Must include at least owner/repo (e.g., my-org/my-repo)",
			repoName,
		)
	}

	for i, part := range parts {
		if part == "" {
			return false, fmt.Sprintf("repo_name part %d is empty", i+1)
		}
		if !slugPartPattern.MatchString(part) {
			return false, fmt.Sprintf(
				"repo_name part '%s' contains invalid characters. Use only alphanumeric characters, dots, hyphens, and underscores",
				part,
			)
		}
	}

	return true, ""
}

func ValidateInputs(purl, repoURL, repoName string) (bool, string) {
	if ok, errMsg := ValidatePURL(purl); !ok {
		return false, errMsg
	}

	if ok, errMsg := ValidateRepoURL(repoURL); !ok {
		return false, errMsg
	}

	if ok, errMsg := ValidateRepoName(repoName); !ok {
		return false, errMsg
	}

	return true, ""
}

func splitPathParts(path string) []string {
	raw := strings.Split(path, "/")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}
