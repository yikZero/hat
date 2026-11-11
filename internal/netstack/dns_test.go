package netstack

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	f := testFake
	out, err := AnswerDNS(f, b)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	return m
}

var testFake = NewFakeIP(FakeIPRange, 0)

func TestDNSAnswers(t *testing.T) {
	m := query(t, "Example.COM.", dnsmessage.TypeA)
	if m.ID != 7 || m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("%+v", m)
	}
	ip := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A)
	if !FakeIPRange.Contains(ip) {
		t.Fatalf("not a fake ip: %v", ip)
	}
	if name, ok := testFake.Lookup(ip); !ok || name != "example.com" {
		t.Fatalf("lookup %q %v", name, ok)
	}
	// stable
	m2 := query(t, "example.com.", dnsmessage.TypeA)
	if netip.AddrFrom4(m2.Answers[0].Body.(*dnsmessage.AResource).A) != ip {
		t.Fatal("unstable mapping")
	}
	if m := query(t, "example.com.", dnsmessage.TypeAAAA); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("AAAA: %+v", m)
	}
	for _, n := range []string{"printer.local.", "metadata.google.internal.", "myhost.", "1.0.0.127.in-addr.arpa."} {
		if m := query(t, n, dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("%s: rcode %v", n, m.RCode)
		}
	}
}

func TestFakeIPRecycle(t *testing.T) {
	f := NewFakeIP(netip.MustParsePrefix("198.18.0.0/29"), 3)
	a := f.Get("a.com")
	f.Get("b.com")
	f.Get("c.com")
	f.Get("a.com") // touch a
	d := f.Get("d.com")
	if _, ok := f.Lookup(d); !ok {
		t.Fatal("d missing")
	}
	if _, ok := f.Lookup(a); !ok {
		t.Fatal("recently used entry evicted")
	}
	if got := f.Get("a.com"); got != a {
		t.Fatal("a changed")
	}
}
