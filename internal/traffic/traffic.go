// Package traffic holds the live traffic numbers a node reports: per port
// forward and HTTPS route (on the edge), per access rule (where it is
// enforced) and per mesh device (its WireGuard peers).
package traffic

// Rate is a byte count with its current speed. In is toward the target /
// received by this node, Out the other way.
type Rate struct {
	In      uint64  `json:"in"`
	Out     uint64  `json:"out"`
	InRate  float64 `json:"in_rate"` // bytes per second
	OutRate float64 `json:"out_rate"`
}

// Route is an HTTPS route's traffic.
type Route struct {
	Rate
	Requests uint64  `json:"requests"`
	Errors   uint64  `json:"errors"`
	ReqRate  float64 `json:"req_rate"` // requests per second
}

// HostStats counts requests to one hostname (kept by the HTTPS proxy).
type HostStats struct {
	Requests uint64 `json:"requests"`
	Errors   uint64 `json:"errors"` // 5xx answers (incl. backend unreachable)
	In       uint64 `json:"in"`     // request body bytes
	Out      uint64 `json:"out"`    // response body bytes
}

// Request is one entry of the recent HTTPS requests list.
type Request struct {
	Time   int64  `json:"time"`
	Client string `json:"client"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Bytes  uint64 `json:"bytes"`
	Ms     int64  `json:"ms"`
}

// Node is what one server reports. Totals count since meshgate started.
type Node struct {
	Node     string            `json:"node"`     // node ID
	Forwards map[string]Rate   `json:"forwards"` // forward ID (this node is the edge)
	Routes   map[string]Route  `json:"routes"`   // HTTPS route ID (this node is the edge)
	ACLs     map[string]uint64 `json:"acls"`     // access rule ID -> connections allowed
	Peers    map[string]Rate   `json:"peers"`    // node ID -> WireGuard traffic with that device
	Recent   []Request         `json:"recent"`   // newest last
}
