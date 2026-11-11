package vm

// Control protocol: one JSON line request, one JSON line response. After a
// successful "dial" response the connection becomes a raw byte stream to
// the guest's SSH port.

const ProtoVersion = 1

type CtlRequest struct {
	V  int    `json:"v"`
	Op string `json:"op"` // status | dial | stop
}

type CtlResponse struct {
	V        int    `json:"v"`
	OK       bool   `json:"ok"`
	State    string `json:"state,omitempty"` // starting | booting | ready | stopping | failed
	Error    string `json:"error,omitempty"`
	GuestIP  string `json:"guest_ip,omitempty"`
	Sessions int    `json:"sessions,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	// Counters from the network stack.
	UpstreamOK     uint64 `json:"upstream_ok"`
	UpstreamFailed uint64 `json:"upstream_failed"`
	Refused        uint64 `json:"refused"`
	UDPDropped     uint64 `json:"udp_dropped"`
	DNSQueries     uint64 `json:"dns_queries"`
	LastError      string `json:"last_error,omitempty"`
	PID            int    `json:"pid,omitempty"`
}
