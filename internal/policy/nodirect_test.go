// Package policy holds repository-wide tests.
package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Calls that open network connections or resolve names on the host.
var forbidden = regexp.MustCompile(`\bnet\.(Dial|DialTimeout|DialTCP|DialUDP|DialIP|DialUnix|Lookup\w*|ResolveIPAddr|ResolveTCPAddr|ResolveUDPAddr)\b|\bnet\.Resolver\b|\bnet\.Dialer\b|\bhttp\.(Get|Post|Head|DefaultClient|DefaultTransport)\b|\bhttp\.Client\{`)

// allowed lists files that may contain such calls, with the reason.
var allowed = map[string]string{
	"internal/upstream/upstream.go":   "the only dialer: connects to the configured proxy server itself",
	"internal/vm/image.go":            "downloads the public guest OS image (host infrastructure, not profile traffic)",
	"internal/vm/client.go":           "unix socket to the local daemon",
	"internal/preflight/preflight.go": "HTTP client whose DialContext is the upstream proxy dialer",
}

func TestNoDirectNetworkAccess(t *testing.T) {
	root := "../.."
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == "internal/e2e" || rel == "internal/testproxy" || strings.HasPrefix(d.Name(), ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, _ := os.ReadFile(path)
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if forbidden.MatchString(line) {
				if _, ok := allowed[rel]; !ok {
					t.Errorf("%s:%d: direct network call outside internal/upstream: %s", rel, i+1, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
}
