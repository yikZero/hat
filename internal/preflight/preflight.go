// Package preflight is the checklist hat runs before every launch of a
// profile (and on demand with `hat preflight`). Results are cached so that
// repeated launches (shims, agents running many commands) stay instant.
//
// Checklist:
//
//	config     profile valid, files private            (always, local)
//	platform   sandbox-exec (lite) / vfkit (vm)        (always, local)
//	proxy      proxy reachable and credentials OK      (quick, network via proxy)
//	egress     exit IP, country, timezone               (full,  network via proxy)
//	expect     exit IP/country match expectations       (full)
//
// The kill switch does not depend on these checks: if the proxy dies
// after a passing preflight, connections still fail closed.
package preflight

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"hat/internal/clierr"
	"hat/internal/config"
	"hat/internal/secret"
	"hat/internal/upstream"
)

const (
	Pass = "pass"
	Fail = "fail"
	Warn = "warn"
	Skip = "skip"
)

type Item struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Egress struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Timezone string `json:"timezone"`
	Source   string `json:"source"`
}

type Report struct {
	Profile string    `json:"profile"`
	Level   string    `json:"level"`
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Cached  bool      `json:"cached"`
	Items   []Item    `json:"items"`
	Egress  *Egress   `json:"egress,omitempty"`
	// Fingerprint of the settings the result depends on; a cached report
	// is only reused if it matches.
	Key string `json:"key"`
}

// Hooks allow tests and platform code to replace parts of the checklist.
var (
	// PlatformCheck verifies local prerequisites for a mode.
	PlatformCheck = defaultPlatformCheck
	// EgressURLs are queried in order through the proxy.
	EgressURLs = []string{"https://ipinfo.io/json", "http://ip-api.com/json/?fields=query,countryCode,timezone"}
	// ProbeTarget is the CONNECT target used to verify the proxy.
	ProbeTarget = "ipinfo.io:443"
	now         = time.Now
)

func defaultPlatformCheck(ctx context.Context, p *config.Profile) Item {
	if runtime.GOOS != "darwin" {
		return Item{"platform", Fail, "hat runs profiles on macOS only"}
	}
	if p.Mode == config.ModeLite {
		if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
			return Item{"platform", Fail, "/usr/bin/sandbox-exec missing"}
		}
		return Item{"platform", Pass, "sandbox-exec"}
	}
	return Item{"platform", Pass, "vm (vfkit is checked when the VM starts)"}
}

func key(p *config.Profile, level string) string {
	return strings.Join([]string{level, p.Mode, p.Proxy.URL, p.Proxy.Password, p.Timezone,
		p.Checks.ExpectCountry, p.Checks.ExpectIP}, "|")
}

func cachePath(name string) (string, error) {
	dir, err := config.Dir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "preflight.json"), nil
}

// Last returns the last stored report, if any.
func Last(name string) (*Report, error) {
	f, err := cachePath(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var r Report
	return &r, json.Unmarshal(b, &r)
}

// Options for Run.
type Options struct {
	// Level overrides the profile's checks.on_start ("" = profile setting).
	Level string
	// Force ignores the cache.
	Force bool
}

// Run executes the checklist. A failing report is returned together with a
// classified error.
func Run(ctx context.Context, p *config.Profile, o Options) (*Report, error) {
	level := o.Level
	if level == "" {
		level = p.Checks.Level()
	}
	if level == config.CheckOff {
		return &Report{Profile: p.Name, Level: level, At: now(), OK: true}, nil
	}
	k := key(p, level)
	if !o.Force {
		if last, err := Last(p.Name); err == nil && last.OK && last.Key == k && now().Sub(last.At) < p.Checks.Cache() {
			last.Cached = true
			return last, nil
		}
	}
	r := &Report{Profile: p.Name, Level: level, At: now(), Key: k}
	add := func(it Item) { r.Items = append(r.Items, it) }
	add(Item{"config", Pass, "profile valid; files private"})

	var failErr error
	fail := func(err error) {
		if failErr == nil {
			failErr = err
		}
	}
	if it := PlatformCheck(ctx, p); it.Status == Fail {
		add(it)
		fail(clierr.New(clierr.PreflightFailed, "hat doctor", "%s: %s", it.Name, it.Detail))
	} else {
		add(it)
	}
	rawURL, err := secret.ProxyURL(p)
	var dialer upstream.Dialer
	if err == nil {
		dialer, err = upstream.New(rawURL)
	}
	if err != nil {
		add(Item{"proxy", Fail, err.Error()})
		fail(clierr.Wrap(clierr.ProxyAuth, "hat proxy-password "+p.Name, err))
	} else {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		start := time.Now()
		c, err := dialer.DialContext(pctx, "tcp", ProbeTarget)
		cancel()
		if err != nil {
			add(Item{"proxy", Fail, err.Error()})
			fail(clierr.Wrap(clierr.ProxyUnreachable, "check the proxy; nothing was sent directly", err))
		} else {
			c.Close()
			add(Item{"proxy", Pass, fmt.Sprintf("%s accepted a tunnel in %s", dialer.String(), time.Since(start).Round(time.Millisecond))})
		}
	}

	if level == config.CheckFull && failErr == nil {
		eg, err := LookupEgress(ctx, dialer)
		if err != nil {
			add(Item{"egress", Fail, err.Error()})
			fail(clierr.Wrap(clierr.PreflightFailed, "the proxy accepted the tunnel but the exit IP lookup failed; retry or run: hat check "+p.Name, err))
		} else {
			r.Egress = eg
			add(Item{"egress", Pass, fmt.Sprintf("exit IP %s (%s, %s) via %s", eg.IP, eg.Country, eg.Timezone, eg.Source)})
			if c := p.Checks.ExpectCountry; c != "" {
				if !strings.EqualFold(eg.Country, c) {
					add(Item{"expect_country", Fail, fmt.Sprintf("exit country %s, expected %s", eg.Country, c)})
					fail(clierr.New(clierr.EgressMismatch, "the proxy now exits elsewhere; fix the proxy or change checks.expect_country",
						"exit IP %s is in %s, expected %s", eg.IP, eg.Country, c))
				} else {
					add(Item{"expect_country", Pass, c})
				}
			}
			if ip := p.Checks.ExpectIP; ip != "" {
				if eg.IP != ip {
					add(Item{"expect_ip", Fail, fmt.Sprintf("exit IP %s, expected %s", eg.IP, ip)})
					fail(clierr.New(clierr.EgressMismatch, "the proxy exit IP changed; fix the proxy or change checks.expect_ip",
						"exit IP %s, expected %s", eg.IP, ip))
				} else {
					add(Item{"expect_ip", Pass, ip})
				}
			}
			if eg.Timezone != "" && eg.Timezone != p.Timezone {
				add(Item{"timezone", Warn, fmt.Sprintf("profile uses %s, exit IP suggests %s", p.Timezone, eg.Timezone)})
			} else if eg.Timezone != "" {
				add(Item{"timezone", Pass, p.Timezone})
			}
		}
	}
	for _, it := range r.Items {
		if it.Status == Fail && failErr == nil {
			failErr = clierr.New(clierr.PreflightFailed, "run: hat preflight "+p.Name, "%s: %s", it.Name, it.Detail)
		}
	}
	r.OK = failErr == nil
	if f, err := cachePath(p.Name); err == nil {
		if b, err := json.MarshalIndent(r, "", "  "); err == nil {
			config.WriteFileAtomic(f, b, 0o600)
		}
	}
	return r, failErr
}

// LookupEgress asks public "what is my IP" services, through the proxy.
func LookupEgress(ctx context.Context, d upstream.Dialer) (*Egress, error) {
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         d.DialContext, // every connection goes through the proxy
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	var errs []error
	for _, u := range EgressURLs {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		var v struct {
			IP, Query, Country, CountryCode, Timezone string
		}
		if resp.StatusCode != 200 || json.Unmarshal(b, &v) != nil {
			errs = append(errs, fmt.Errorf("%s: %s", u, resp.Status))
			continue
		}
		e := &Egress{IP: v.IP, Country: v.Country, Timezone: v.Timezone, Source: hostOf(u)}
		if e.IP == "" {
			e.IP = v.Query
		}
		if v.CountryCode != "" {
			e.Country = v.CountryCode
		}
		if net.ParseIP(e.IP) == nil {
			errs = append(errs, fmt.Errorf("%s: no IP in response", u))
			continue
		}
		return e, nil
	}
	return nil, fmt.Errorf("exit IP lookup failed: %w", errors.Join(errs...))
}

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	return s
}
