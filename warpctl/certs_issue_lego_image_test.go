package main

import (
	"regexp"
	"testing"
)

// An unpinned or floating lego tag changes the CLI under certsIssue's fixed
// arguments: `latest` moved to lego v5, which rejects `--accept-tos`, and every
// issuance failed on its first domain. The image must name one exact v4 release.
func TestCertsIssueLegoImageIsAnExactV4Release(t *testing.T) {
	exactV4 := regexp.MustCompile(`^goacme/lego:v4\.[0-9]+\.[0-9]+$`)
	if !exactV4.MatchString(legoImage) {
		t.Fatalf("certsIssue runs %q; it must pin an exact lego v4 release (goacme/lego:v4.X.Y)", legoImage)
	}
}
