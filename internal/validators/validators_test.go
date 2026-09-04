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
