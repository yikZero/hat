package netstack

import (
	"container/list"
	"net/netip"
	"strings"
	"sync"
)

// FakeIPRange is where fake addresses are allocated (RFC 2544 benchmarking
// range, never routed on the internet).
var FakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// FakeIP maps domain names to stable fake IPv4 addresses so that TCP
// connections can be sent to the proxy by name (no local resolution).
type FakeIP struct {
	mu     sync.Mutex
	prefix netip.Prefix
	next   netip.Addr
	byName map[string]*list.Element
	byIP   map[netip.Addr]*list.Element
	lru    *list.List // front = most recently used
	max    int
}

type fakeEntry struct {
	name string
	ip   netip.Addr
}

// NewFakeIP returns a pool. max <= 0 means the whole range.
func NewFakeIP(prefix netip.Prefix, max int) *FakeIP {
	size := 1 << (32 - prefix.Bits())
	if max <= 0 || max > size-2 {
		max = size - 2
	}
	return &FakeIP{prefix: prefix, next: prefix.Addr().Next(), byName: map[string]*list.Element{},
		byIP: map[netip.Addr]*list.Element{}, lru: list.New(), max: max}
}

// Canonical lowercases and strips the trailing dot.
func Canonical(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

// Get returns the fake IP for name, allocating one if needed.
func (f *FakeIP) Get(name string) netip.Addr {
	name = Canonical(name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if el, ok := f.byName[name]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*fakeEntry).ip
	}
	var ip netip.Addr
	if f.lru.Len() >= f.max {
		// Recycle the least recently used address.
		el := f.lru.Back()
		e := el.Value.(*fakeEntry)
		delete(f.byName, e.name)
		delete(f.byIP, e.ip)
		f.lru.Remove(el)
		ip = e.ip
	} else {
		ip = f.next
		f.next = f.next.Next()
		if !f.prefix.Contains(f.next) || f.next == lastAddr(f.prefix) {
			f.next = f.prefix.Addr().Next()
		}
	}
	el := f.lru.PushFront(&fakeEntry{name: name, ip: ip})
	f.byName[name] = el
	f.byIP[ip] = el
	return ip
}

// Lookup returns the name for a fake IP.
func (f *FakeIP) Lookup(ip netip.Addr) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byIP[ip]
	if !ok {
		return "", false
	}
	f.lru.MoveToFront(el)
	return el.Value.(*fakeEntry).name, true
}

// Contains reports whether ip is inside the fake range.
func (f *FakeIP) Contains(ip netip.Addr) bool { return f.prefix.Contains(ip) }

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
