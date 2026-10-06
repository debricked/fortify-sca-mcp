package validators

import "testing"

func TestValidateInputs(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		repoURL  string
		repoName string
		wantOK   bool
	}{
		{
			name:     "valid inputs",
			purl:     "pkg:npm/lodash@4.17.21",
			repoURL:  "https://github.com/acme/platform.git",
			repoName: "acme/platform",
			wantOK:   true,
		},
		{
			name:     "invalid purl",
			purl:     "lodash@4.17.21",
			repoURL:  "https://github.com/acme/platform",
			repoName: "acme/platform",
			wantOK:   false,
		},
		{
			name:     "invalid repo url",
			purl:     "pkg:npm/lodash@4.17.21",
			repoURL:  "not-a-git-url",
			repoName: "acme/platform",
			wantOK:   false,
		},
		{
			name:     "invalid repo name",
			purl:     "pkg:npm/lodash@4.17.21",
			repoURL:  "git@github.com:acme/platform.git",
			repoName: "acme",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := ValidateInputs(tt.purl, tt.repoURL, tt.repoName)
			if ok != tt.wantOK {
				t.Fatalf("ValidateInputs() = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestValidateBatchInputs(t *testing.T) {
	validRepoURL := "https://github.com/acme/platform.git"
	validRepoName := "acme/platform"
	tests := []struct {
		name   string
		purls  []string
		wantOK bool
	}{
		{name: "one purl", purls: []string{"pkg:npm/a@1.0.0"}, wantOK: true},
		{name: "five purls", purls: []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1", "pkg:npm/d@1", "pkg:npm/e@1"}, wantOK: true},
		{name: "empty", purls: []string{}, wantOK: false},
		{name: "too many", purls: []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1", "pkg:npm/d@1", "pkg:npm/e@1", "pkg:npm/f@1"}, wantOK: false},
		{name: "invalid purl", purls: []string{"pkg:npm/a"}, wantOK: false},
		{name: "duplicate", purls: []string{"pkg:npm/a@1", "pkg:npm/a@1"}, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := ValidateBatchInputs(tt.purls, validRepoURL, validRepoName)
			if ok != tt.wantOK {
				t.Fatalf("ValidateBatchInputs() = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}
