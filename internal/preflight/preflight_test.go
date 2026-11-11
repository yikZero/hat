package preflight

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hat/internal/clierr"
	"hat/internal/config"
	"hat/internal/testproxy"
)

func setup(t *testing.T, body string) (*config.Profile, *testproxy.Server, *int) {
	t.Helper()
	t.Setenv(config.EnvHome, t.TempDir())
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	up := testproxy.StartSOCKS5("", "")
	up.Resolve = func(string) string { return "127.0.0.1" }
	t.Cleanup(up.Close)
	EgressURLs = []string{"http://whoami.test:" + port + "/json"}
	ProbeTarget = "probe.test:" + port
	PlatformCheck = func(context.Context, *config.Profile) Item { return Item{"platform", Pass, "test"} }
	p := config.New("pf")
	p.Proxy.URL = "socks5://" + up.Addr()
	p.Proxy.AllowLocalUpstream = true
	p.Timezone = "America/New_York"
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	return p, up, &hits
}

func TestFullPassAndCache(t *testing.T) {
	p, up, hits := setup(t, `{"ip":"203.0.113.9","country":"US","timezone":"America/New_York"}`)
	p.Checks.ExpectCountry = "US"
	r, err := Run(context.Background(), p, Options{})
	if err != nil || !r.OK || r.Egress.IP != "203.0.113.9" {
		t.Fatalf("%v %+v", err, r)
	}
	// all traffic went through the proxy, by name
	for _, tg := range up.Targets() {
		if !strings.HasSuffix(strings.Split(tg, ":")[0], ".test") {
			t.Fatalf("unexpected target %s", tg)
		}
	}
	r2, err := Run(context.Background(), p, Options{})
	if err != nil || !r2.Cached || *hits != 1 {
		t.Fatalf("expected cached result: %v cached=%v hits=%d", err, r2.Cached, *hits)
	}
	// changing an expectation invalidates the cache
	p.Checks.ExpectCountry = "JP"
	_, err = Run(context.Background(), p, Options{})
	if c, _, _ := clierr.Classify(err); c != clierr.EgressMismatch {
		t.Fatalf("expected mismatch, got %v", err)
	}
	// a failed result is never served from cache
	if _, err := Run(context.Background(), p, Options{}); err == nil {
		t.Fatal("failed result was cached")
	}
}

func TestTimezoneWarnOnly(t *testing.T) {
	p, _, _ := setup(t, `{"query":"198.51.100.2","countryCode":"JP","timezone":"Asia/Tokyo"}`)
	r, err := Run(context.Background(), p, Options{Force: true})
	if err != nil || !r.OK {
		t.Fatal(err)
	}
	found := false
	for _, it := range r.Items {
		if it.Name == "timezone" && it.Status == Warn {
			found = true
		}
	}
	if !found || r.Egress.Country != "JP" {
		t.Fatalf("%+v", r)
	}
}

func TestProxyDown(t *testing.T) {
	p, up, _ := setup(t, `{}`)
	up.Close()
	_, err := Run(context.Background(), p, Options{Level: config.CheckQuick})
	var ce *clierr.Error
	if !errors.As(err, &ce) || ce.Code != clierr.ProxyUnreachable || clierr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
}

func TestOff(t *testing.T) {
	p, up, _ := setup(t, `{}`)
	up.Close()
	p.Checks.OnStart = config.CheckOff
	if r, err := Run(context.Background(), p, Options{}); err != nil || !r.OK {
		t.Fatal(err)
	}
	_ = time.Second
}
