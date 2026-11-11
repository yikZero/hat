package netstack

import (
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSTTL is the TTL of fake answers.
const DNSTTL = 60

// localOnlyName reports names that must never be sent to the proxy.
func localOnlyName(name string) bool {
	n := Canonical(name)
	if n == "" || !strings.Contains(n, ".") { // single-label names
		return true
	}
	for _, suf := range []string{".local", ".localhost", ".internal", ".lan", ".home.arpa", ".arpa", ".localdomain", ".invalid"} {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return false
}

// AnswerDNS builds a reply for a raw DNS query. It never contacts any
// resolver: A records get fake IPs, everything else gets an empty answer
// (or NXDOMAIN for local-only names and PTR lookups).
func AnswerDNS(fake *FakeIP, query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	resp := dnsmessage.Message{Header: dnsmessage.Header{
		ID: hdr.ID, Response: true, OpCode: hdr.OpCode, RecursionDesired: hdr.RecursionDesired,
		RecursionAvailable: true, RCode: dnsmessage.RCodeSuccess,
	}}
	if hdr.Response || hdr.OpCode != 0 || len(qs) != 1 {
		resp.RCode = dnsmessage.RCodeNotImplemented
		if len(qs) == 1 {
			resp.Questions = qs
		}
		return resp.Pack()
	}
	q := qs[0]
	resp.Questions = qs
	name := q.Name.String()
	switch {
	case q.Class != dnsmessage.ClassINET:
		resp.RCode = dnsmessage.RCodeNotImplemented
	case q.Type == dnsmessage.TypePTR || localOnlyName(name):
		resp.RCode = dnsmessage.RCodeNameError
	case q.Type == dnsmessage.TypeA:
		ip := fake.Get(name)
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: DNSTTL},
			Body:   &dnsmessage.AResource{A: ip.As4()},
		}}
	default:
		// AAAA, HTTPS, MX, TXT, SRV...: no data (NOERROR, empty answer).
	}
	return resp.Pack()
}
