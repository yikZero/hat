// Package seatbelt generates the macOS sandbox (SBPL) profile used by lite
// mode. The profile is deny-by-default: the only network egress allowed is a
// TCP connection to the local bridge proxy port.
package seatbelt

import (
	_ "embed"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed base.sb
var base string

type Options struct {
	// ProxyPort is the bridge port on localhost. Required.
	ProxyPort int
	// HatHome is the application home (~/.hat). Reading or writing it is
	// denied, except for the paths below.
	HatHome string
	// ProfileHome is the per-profile HOME (inside HatHome) that the
	// sandboxed program may use. May be empty.
	ProfileHome string
	// ReadableInHatHome are extra paths inside HatHome that may be read
	// (e.g. the shim directory and shims.toml for nested invocations).
	ReadableInHatHome []string
	// ReadOnly paths are made non-writable.
	ReadOnly []string
	// AllowTrustd lets programs verify TLS through the system trust
	// service (which may contact OCSP/CRL servers directly).
	AllowTrustd bool
	// LogTag is attached to denial messages in the system log.
	LogTag string
}

// Generate returns the SBPL profile text.
func Generate(o Options) (string, error) {
	if o.ProxyPort <= 0 || o.ProxyPort > 65535 {
		return "", fmt.Errorf("seatbelt: invalid proxy port %d", o.ProxyPort)
	}
	if o.HatHome == "" || !filepath.IsAbs(o.HatHome) {
		return "", fmt.Errorf("seatbelt: HatHome must be absolute")
	}
	tag := o.LogTag
	if tag == "" {
		tag = "hat"
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("(version 1)")
	w("(deny default (with message %s))", q(tag))
	b.WriteString(base)
	w("")

	if o.AllowTrustd {
		w("; trustd: system TLS certificate verification (opt-in; may fetch OCSP/CRL directly)")
		w(`(allow mach-lookup (global-name "com.apple.trustd.agent"))`)
		w("")
	}

	w("; Network: the ONLY egress is TCP to the local bridge proxy.")
	w("(allow network-outbound (remote tcp %s))", q("localhost:"+strconv.Itoa(o.ProxyPort)))
	w("; Local listeners (dev servers, OAuth loopback callbacks). These grant no egress.")
	w(`(allow network-bind (local ip "*:*"))`)
	w(`(allow network-inbound (local ip "*:*"))`)
	w("")

	w("; Files: read and write allowed by default ...")
	w("(allow file-read*)")
	w("(allow file-write*)")
	for _, p := range o.ReadOnly {
		w("(deny file-write* (subpath %s))", q(p))
	}
	w("; ... except the %s home (profiles, secrets, sockets).", tag)
	w("(deny file-read* file-write* (subpath %s))", q(o.HatHome))
	w("(allow file-read-metadata (literal %s))", q(o.HatHome))
	for _, p := range o.ReadableInHatHome {
		w("(allow file-read* (subpath %s))", q(p))
	}
	if o.ProfileHome != "" {
		w("(allow file-read* file-write* (subpath %s))", q(o.ProfileHome))
	}
	w("")

	w("; Defence in depth: explicitly refuse services that resolve names or make")
	w("; requests from the real network on the program's behalf.")
	w("(deny mach-lookup")
	for _, s := range []string{"com.apple.dnssd.service", "com.apple.mDNSResponder",
		"com.apple.nsurlsessiond", "com.apple.nsurlsessiond.NSURLSessionProxyService",
		"com.apple.coreservices.appleevents", "com.apple.CoreServices.coreservicesd"} {
		w("  (global-name %s)", q(s))
	}
	w(")")
	if !o.AllowTrustd {
		w(`(deny mach-lookup (global-name "com.apple.trustd.agent") (global-name "com.apple.trustd"))`)
	}
	w("(deny lsopen)")
	w("(deny appleevent-send)")
	return b.String(), nil
}

// q quotes a string for SBPL (JSON-style escaping is accepted).
func q(s string) string { return strconv.Quote(s) }
