package adapters

import (
	"strings"
	"testing"
)

// RouterOS otherwise follows redirects itself before a script can validate
// the next endpoint. Keep that security property in the ordinary host gate.
func TestArchiveFetchChecksEachHTTPSHop(t *testing.T) {
	p, _ := Installed("7.25", "x86_64", "CHR")
	a, err := describeArchive(p, "tikray", fixtureImage(t, "tikray", "amd64"), "https://downloads.example/release")
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, line := range strings.Split(archiveChecks([]VerifiedArchive{a}), "\n") {
		if strings.Contains(line, "/tool/fetch ") {
			seen = true
			if !strings.Contains(line, "check-certificate=yes ") || !strings.Contains(line, "http-max-redirect-count=0 ") {
				t.Fatal("archive fetch may follow an unchecked redirect")
			}
		}
	}
	if !seen {
		t.Fatal("online release has no download path")
	}
}
