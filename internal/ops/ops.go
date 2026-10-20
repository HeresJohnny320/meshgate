// Package ops is the admin API shared by the TUI/CLI (over a local unix
// socket) and the web UI (over HTTP with a login). Both talk to the node's
// own store, so they keep working with nothing else online; changes made with
// scope "cluster" replicate to every node, scope "local" stays on this node.
package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/changelog"
	"github.com/heresjohnny320/meshgate/internal/diag"
	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/traffic"
)

// PeerRuntime is live data about one peer, provided by the agent.
type PeerRuntime struct {
	Path          string    `json:"path"` // "direct", "via <relay>", or ""
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}

// Runtime is what the agent reports.
type Runtime struct {
	HomeRelay  string                 `json:"home_relay,omitempty"`
	Peers      map[string]PeerRuntime `json:"peers"`
	LastSync   map[string]time.Time   `json:"last_sync"`
	Warnings   []string               `json:"warnings"`
	Userspace  bool                   `json:"userspace"`
	StartedAt  time.Time              `json:"started_at"`
	ProxyError string                 `json:"proxy_error,omitempty"`
	// Latest is the newest meshgate release (checked every few hours).
	Latest string `json:"latest,omitempty"`
	// WebCertFP is the SHA-256 fingerprint of this server's web UI
	// certificate (self-signed), to check the browser shows the same.
	WebCertFP string `json:"web_cert_fp,omitempty"`
	// WebCAFP is the fingerprint of the CA that signs it (installed on a
	// device, the browser trusts the web UI without a warning).
	WebCAFP string `json:"web_ca_fp,omitempty"`
}

// Service implements the operations.
type Service struct {
	Store   *store.Store
	SelfID  string
	Runtime func() Runtime
	// Traffic gathers live traffic from every server (nil: not available).
	Traffic func() []traffic.Node
	// History returns traffic history: a range ("6h", "1d", "1w", "1m",
	// "1y"), or from/to (unix seconds) with a step for downloads.
	History func(q url.Values) (any, error)
	// Update makes node update itself to the latest release (nil: not
	// available here).
	Update func(node string) (string, error)
}

// Item wraps a record with its local-override flag.
type Item[T any] struct {
	Value T    `json:"value"`
	Local bool `json:"local"`
}

// View is everything a UI needs to render.
type View struct {
	SelfID     string                  `json:"self_id"`
	Network    model.Network           `json:"network"`
	Nodes      []Item[model.Node]      `json:"nodes"`
	Forwards   []Item[model.Forward]   `json:"forwards"`
	Routes     []Item[model.HTTPRoute] `json:"routes"`
	ACLs       []Item[model.ACL]       `json:"acls"`
	ExitRoutes []Item[model.ExitRoute] `json:"exit_routes"`
	Tokens     []model.Token           `json:"tokens"`
	Statuses   map[string]model.Status `json:"statuses"`
	Runtime    Runtime                 `json:"runtime"`
}

// View builds the current view.
func (s *Service) View() View {
	v := View{SelfID: s.SelfID, Statuses: map[string]model.Status{}}
	v.Network, _ = store.Get[model.Network](s.Store, model.Key(model.KindNetwork, "main"))
	v.Nodes = items[model.Node](s.Store, model.KindNode)
	v.Forwards = items[model.Forward](s.Store, model.KindForward)
	v.Routes = items[model.HTTPRoute](s.Store, model.KindRoute)
	v.ACLs = items[model.ACL](s.Store, model.KindACL)
	v.ExitRoutes = items[model.ExitRoute](s.Store, model.KindExitRoute)
	for _, t := range store.List[model.Token](s.Store, model.KindToken) {
		t.SecretHash = ""
		v.Tokens = append(v.Tokens, t)
	}
	for _, st := range store.List[model.Status](s.Store, model.KindStatus) {
		v.Statuses[st.NodeID] = st
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Value.Name < v.Nodes[j].Value.Name })
	sort.Slice(v.Forwards, func(i, j int) bool { return v.Forwards[i].Value.Name < v.Forwards[j].Value.Name })
	sort.Slice(v.Routes, func(i, j int) bool { return v.Routes[i].Value.Hostname < v.Routes[j].Value.Hostname })
	sort.Slice(v.ACLs, func(i, j int) bool { return v.ACLs[i].Value.Name < v.ACLs[j].Value.Name })
	if s.Runtime != nil {
		v.Runtime = s.Runtime()
	}
	return v
}

func items[T any](s *store.Store, kind string) []Item[T] {
	var out []Item[T]
	for _, k := range s.Keys(kind) {
		if val, ok := store.Get[T](s, k); ok {
			out = append(out, Item[T]{Value: val, Local: s.IsLocal(k)})
		}
	}
	return out
}

func (s *Service) self() model.Node {
	n, _ := store.Get[model.Node](s.Store, model.Key(model.KindNode, s.SelfID))
	return n
}

func (s *Service) requireWriter() error {
	if !s.self().Writer() {
		return errors.New("only server nodes can change mesh config")
	}
	return nil
}

func (s *Service) nodeExists(id string) bool {
	_, ok := s.Store.Raw(model.Key(model.KindNode, id))
	return ok
}

// PutForward creates or updates a forward.
func (s *Service) PutForward(f model.Forward, scope store.Scope) (model.Forward, error) {
	if err := s.requireWriter(); err != nil {
		return f, err
	}
	if f.ID == "" {
		f.ID = join.RandomID()
	}
	f.Name = strings.TrimSpace(f.Name)
	if err := f.Validate(); err != nil {
		return f, err
	}
	if err := model.CheckName(f.Name); err != nil {
		return f, err
	}
	if !s.nodeExists(f.EdgeNode) || !s.nodeExists(f.TargetNode) {
		return f, errors.New("unknown edge or target node")
	}
	for _, o := range store.List[model.Forward](s.Store, model.KindForward) {
		if o.ID == f.ID || !o.Enabled || !f.Enabled || o.EdgeNode != f.EdgeNode {
			continue
		}
		if overlaps(o, f) {
			return f, fmt.Errorf("port overlaps forward %q on the same edge", o.Name)
		}
	}
	_, err := s.Store.Put(model.Key(model.KindForward, f.ID), f, scope)
	return f, err
}

func overlaps(a, b model.Forward) bool {
	protoClash := a.Proto == b.Proto || a.Proto == model.ProtoBoth || b.Proto == model.ProtoBoth
	al, ah := a.Ports()
	bl, bh := b.Ports()
	return protoClash && al <= bh && bl <= ah
}

// PutRoute creates or updates an HTTP route.
func (s *Service) PutRoute(r model.HTTPRoute, scope store.Scope) (model.HTTPRoute, error) {
	if err := s.requireWriter(); err != nil {
		return r, err
	}
	if r.ID == "" {
		r.ID = join.RandomID()
	}
	r.Hostname = strings.ToLower(strings.TrimSpace(r.Hostname))
	if err := r.Validate(); err != nil {
		return r, err
	}
	if !s.nodeExists(r.EdgeNode) || !s.nodeExists(r.TargetNode) {
		return r, errors.New("unknown edge or target node")
	}
	for _, o := range store.List[model.HTTPRoute](s.Store, model.KindRoute) {
		if o.ID != r.ID && o.Hostname == r.Hostname {
			return r, fmt.Errorf("hostname %s is already routed", r.Hostname)
		}
	}
	_, err := s.Store.Put(model.Key(model.KindRoute, r.ID), r, scope)
	return r, err
}

// PutACL creates or updates an access rule.
// SetHistorySettings picks the traffic log server ("" = automatic) and the
// retention in days.
func (s *Service) SetHistorySettings(server string, days int) error {
	if err := s.requireWriter(); err != nil {
		return err
	}
	if server != "" {
		n, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, server))
		if !ok || n.Kind != model.NodeServer {
			return errors.New("the log server must be a server node")
		}
	}
	if days < 0 || days > 3650 {
		return errors.New("keep history for 1-3650 days")
	}
	netw, _ := store.Get[model.Network](s.Store, model.Key(model.KindNetwork, "main"))
	netw.LogServer, netw.LogDays = server, days
	_, err := s.Store.Put(model.Key(model.KindNetwork, "main"), netw, store.Cluster)
	return err
}

// PutExitRoute creates or updates an exit route. Without a router it picks
// the server that shares a subnet containing the device.
func (s *Service) PutExitRoute(r model.ExitRoute, scope store.Scope) (model.ExitRoute, error) {
	if err := s.requireWriter(); err != nil {
		return r, err
	}
	if r.ID == "" {
		r.ID = join.RandomID()
	}
	r.Name = strings.TrimSpace(r.Name)
	if err := model.CheckName(r.Name); err != nil {
		return r, err
	}
	pfx, err := r.Prefix()
	if err != nil {
		return r, err
	}
	r.Src = pfx.String()
	if netw, ok := store.Get[model.Network](s.Store, model.Key(model.KindNetwork, "main")); ok {
		if mesh, err := netw.Prefix(); err == nil && mesh.Overlaps(pfx) {
			return r, errors.New("that is the mesh range, not a LAN device")
		}
	}
	nodes := store.List[model.Node](s.Store, model.KindNode)
	if r.Router == "" {
		for _, n := range nodes {
			for _, sub := range n.Routes {
				if p, err := netip.ParsePrefix(sub); err == nil && n.Kind == model.NodeServer && p.Masked().Contains(pfx.Addr()) && p.Bits() <= pfx.Bits() {
					r.Router = n.ID
				}
			}
		}
		if r.Router == "" {
			return r, fmt.Errorf("no node shares a subnet containing %s: add it to the router's Shared LAN subnets, or pick the router", r.Src)
		}
	}
	router, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, r.Router))
	if !ok || router.Kind != model.NodeServer {
		return r, errors.New("pick the router those devices use (a server node)")
	}
	ex, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, r.Via))
	if !ok || !ex.Exit || r.Via == r.Router {
		return r, errors.New("pick a node offered as an exit node")
	}
	if r.Enabled {
		for _, o := range store.List[model.ExitRoute](s.Store, model.KindExitRoute) {
			if o.ID != r.ID && o.Enabled && o.Router == r.Router && o.Via != r.Via {
				return r, fmt.Errorf("%s already sends LAN devices through %s (route %q): one router uses one exit node at a time for now",
					router.Name, nameOf(nodes, o.Via), o.Name)
			}
		}
	}
	_, err = s.Store.Put(model.Key(model.KindExitRoute, r.ID), r, scope)
	return r, err
}

func nameOf(nodes []model.Node, id string) string {
	for _, n := range nodes {
		if n.ID == id {
			return n.Name
		}
	}
	return id
}

func (s *Service) PutACL(a model.ACL, scope store.Scope) (model.ACL, error) {
	if err := s.requireWriter(); err != nil {
		return a, err
	}
	if a.ID == "" {
		a.ID = join.RandomID()
	}
	a.Name = strings.TrimSpace(a.Name)
	a.To = strings.TrimSpace(a.To)
	if a.Name != "" {
		if err := model.CheckName(a.Name); err != nil {
			return a, err
		}
	}
	if a.Name == "" {
		a.Name = a.To
	}
	if err := a.Validate(); err != nil {
		return a, err
	}
	n, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, a.Node))
	if !ok || n.Kind != model.NodeServer {
		return a, errors.New("rules are enforced by server nodes; pick one")
	}
	for _, id := range a.From {
		if !s.nodeExists(id) {
			return a, fmt.Errorf("unknown device %s", id)
		}
	}
	_, err := s.Store.Put(model.Key(model.KindACL, a.ID), a, scope)
	return a, err
}

// Toggle switches a forward, HTTPS route or access rule on or off. A record
// with a local override stays local; otherwise the change is cluster-wide.
func (s *Service) Toggle(kind, id string, enabled bool) error {
	if err := s.requireWriter(); err != nil {
		return err
	}
	key := model.Key(kind, id)
	scope := store.Cluster
	if s.Store.IsLocal(key) {
		scope = store.Local
	}
	switch kind {
	case model.KindForward:
		v, ok := store.Get[model.Forward](s.Store, key)
		if !ok {
			return errors.New("no such forward")
		}
		v.Enabled = enabled
		_, err := s.PutForward(v, scope)
		return err
	case model.KindRoute:
		v, ok := store.Get[model.HTTPRoute](s.Store, key)
		if !ok {
			return errors.New("no such route")
		}
		v.Enabled = enabled
		_, err := s.PutRoute(v, scope)
		return err
	case model.KindACL:
		v, ok := store.Get[model.ACL](s.Store, key)
		if !ok {
			return errors.New("no such rule")
		}
		v.Enabled = enabled
		_, err := s.PutACL(v, scope)
		return err
	case model.KindExitRoute:
		v, ok := store.Get[model.ExitRoute](s.Store, key)
		if !ok {
			return errors.New("no such exit route")
		}
		v.Enabled = enabled
		_, err := s.PutExitRoute(v, scope)
		return err
	}
	return errors.New("only forwards, routes, rules and exit routes can be toggled")
}

func validPort(p int) bool { return p > 0 && p < 65536 }

// NodePatch is the editable part of a node.
type NodePatch struct {
	Name         *string          `json:"name,omitempty"`
	Endpoints    *[]string        `json:"endpoints,omitempty"`
	Routes       *[]string        `json:"routes,omitempty"`
	Relay        *bool            `json:"relay,omitempty"`
	ViaRelay     *string          `json:"via_relay,omitempty"`
	LANPolicy    *string          `json:"lan_policy,omitempty"`
	Exit         *bool            `json:"exit,omitempty"`
	ExitVia      *string          `json:"exit_via,omitempty"`
	TestPort     *int             `json:"test_port,omitempty"`
	AppAdmin     *bool            `json:"app_admin,omitempty"`
	LANExits     *[]model.LANExit `json:"lan_exits,omitempty"`
	ExitOnly     *bool            `json:"exit_only,omitempty"`
	ExitsAllowed *[]string        `json:"exits_allowed,omitempty"`
	Iptables     *bool            `json:"iptables,omitempty"`
}

// UpdateNode edits a node.
func (s *Service) UpdateNode(id string, p NodePatch, scope store.Scope) (model.Node, error) {
	if err := s.requireWriter(); err != nil {
		return model.Node{}, err
	}
	n, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, id))
	if !ok {
		return n, errors.New("no such node")
	}
	if p.Name != nil {
		name := strings.TrimSpace(*p.Name)
		if err := model.CheckName(name); err != nil {
			return n, err
		}
		n.Name = name
	}
	if p.Endpoints != nil {
		for _, e := range *p.Endpoints {
			if err := model.CheckEndpoint(e); err != nil {
				return n, err
			}
		}
		n.Endpoints = *p.Endpoints
	}
	if p.Routes != nil {
		for _, r := range *p.Routes {
			if _, err := netip.ParsePrefix(r); err != nil {
				return n, fmt.Errorf("route %q: %v", r, err)
			}
		}
		n.Routes = *p.Routes
	}
	if p.Relay != nil {
		n.Relay = *p.Relay && n.Kind == model.NodeServer
	}
	if p.ViaRelay != nil {
		n.ViaRelay = *p.ViaRelay
	}
	if p.Exit != nil {
		n.Exit = *p.Exit && n.Kind == model.NodeServer
	}
	if p.LANExits != nil {
		via := ""
		for i, e := range *p.LANExits {
			pfx, err := e.Prefix()
			if err != nil {
				return n, fmt.Errorf("LAN exit: %v", err)
			}
			if netw, ok := store.Get[model.Network](s.Store, model.Key(model.KindNetwork, "main")); ok {
				if mesh, err := netw.Prefix(); err == nil && mesh.Overlaps(pfx) {
					return n, fmt.Errorf("LAN exit %s: that is the mesh range, not a LAN", e.Src)
				}
			}
			ex, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, e.Via))
			if !ok || !ex.Exit || e.Via == id {
				return n, fmt.Errorf("LAN exit %s: pick a node offered as an exit node", e.Src)
			}
			if via != "" && e.Via != via {
				return n, errors.New("a router can send LAN devices through one exit node at a time")
			}
			via = e.Via
			(*p.LANExits)[i].Src = pfx.String()
		}
		if len(*p.LANExits) > 0 && n.Kind != model.NodeServer {
			return n, errors.New("LAN exits are set on the router (a server node that shares the LAN)")
		}
		n.LANExits = *p.LANExits
	}
	if p.ExitsAllowed != nil {
		for _, a := range *p.ExitsAllowed {
			if a == "*" {
				continue
			}
			if ex, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, a)); !ok || !ex.Exit {
				return n, fmt.Errorf("allowed exit %q is not an exit node", a)
			}
		}
		n.ExitsAllowed = *p.ExitsAllowed
	}
	if p.Iptables != nil {
		n.IptablesOff = !*p.Iptables
	}
	if p.ExitOnly != nil {
		n.ExitOnly = *p.ExitOnly
	}
	if p.AppAdmin != nil {
		n.AppAdminOff = !*p.AppAdmin
	}
	if p.TestPort != nil {
		if v := *p.TestPort; v != 0 && (!validPort(v) || n.Kind != model.NodeServer) {
			return n, errors.New("test service: server nodes only, port 1-65535")
		}
		n.TestPort = *p.TestPort
	}
	if p.ExitVia != nil {
		if v := *p.ExitVia; v != "" {
			ex, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, v))
			if !ok || !ex.Exit || v == id {
				return n, errors.New("that node is not an exit node")
			}
		}
		n.ExitVia = *p.ExitVia
	}
	if p.LANPolicy != nil {
		switch *p.LANPolicy {
		case model.PolicyOpen, model.PolicyRestricted, model.PolicyFirewall, "":
			n.LANPolicy = *p.LANPolicy
		default:
			return n, errors.New("lan policy must be open, restricted or firewall")
		}
	}
	_, err := s.Store.Put(model.Key(model.KindNode, id), n, scope)
	return n, err
}

// RemoveNode deletes a node from the mesh, along with forwards that use it.
func (s *Service) RemoveNode(id string) error {
	if err := s.requireWriter(); err != nil {
		return err
	}
	if id == s.SelfID {
		return errors.New("cannot remove the node you are on; run `meshgate leave` there")
	}
	for _, f := range store.List[model.Forward](s.Store, model.KindForward) {
		if f.EdgeNode == id || f.TargetNode == id {
			s.Store.Delete(model.Key(model.KindForward, f.ID), store.Cluster)
		}
	}
	for _, r := range store.List[model.HTTPRoute](s.Store, model.KindRoute) {
		if r.EdgeNode == id || r.TargetNode == id {
			s.Store.Delete(model.Key(model.KindRoute, r.ID), store.Cluster)
		}
	}
	for _, a := range store.List[model.ACL](s.Store, model.KindACL) {
		if a.Node == id {
			s.Store.Delete(model.Key(model.KindACL, a.ID), store.Cluster)
		}
	}
	s.Store.Delete(model.Key(model.KindStatus, id), store.Cluster)
	_, err := s.Store.Delete(model.Key(model.KindNode, id), store.Cluster)
	return err
}

// CreateToken issues a join token.
func (s *Service) CreateToken(kind model.NodeKind, uses int, ttl time.Duration, note string) (string, error) {
	if err := s.requireWriter(); err != nil {
		return "", err
	}
	if kind != model.NodeServer && kind != model.NodeClient {
		return "", errors.New("kind must be server or client")
	}
	tok, _, err := join.NewToken(s.Store, kind, uses, ttl, note, time.Now())
	return tok, err
}

// StaticDevice is a stock-WireGuard-app device config.
type StaticDevice struct {
	Node   model.Node `json:"node"`
	Config string     `json:"config"` // wg-quick format, also used for the QR code
}

// AddStaticDevice registers a device that uses the official WireGuard app.
// Its private key is generated here and returned once, never stored.
func (s *Service) AddStaticDevice(name, relayID string) (StaticDevice, error) {
	if err := s.requireWriter(); err != nil {
		return StaticDevice{}, err
	}
	relay, ok := store.Get[model.Node](s.Store, model.Key(model.KindNode, relayID))
	if !ok || !relay.Relay || len(relay.Endpoints) == 0 {
		return StaticDevice{}, errors.New("pick a relay node (a server with a public endpoint)")
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return StaticDevice{}, err
	}
	resp, err := join.Register(s.Store, join.Request{Name: name, Kind: model.NodeStatic, PublicKey: key.PublicKey().String()}, time.Now())
	if err != nil {
		return StaticDevice{}, err
	}
	n := resp.Node
	n.ViaRelay = relayID
	if _, err := s.Store.Put(model.Key(model.KindNode, n.ID), n, store.Cluster); err != nil {
		return StaticDevice{}, err
	}
	allowed := []string{resp.Network.CIDR}
	for _, o := range store.List[model.Node](s.Store, model.KindNode) {
		allowed = append(allowed, o.Routes...)
	}
	cfg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n",
		key.String(), n.MeshIP, relay.PublicKey, relay.Endpoints[0], strings.Join(allowed, ", "))
	return StaticDevice{Node: n, Config: cfg}, nil
}

// SetNetwork updates network-wide settings.
func (s *Service) SetNetwork(acmeEmail string) error {
	if err := s.requireWriter(); err != nil {
		return err
	}
	n, _ := store.Get[model.Network](s.Store, model.Key(model.KindNetwork, "main"))
	n.ACMEEmail = strings.TrimSpace(acmeEmail)
	_, err := s.Store.Put(model.Key(model.KindNetwork, "main"), n, store.Cluster)
	return err
}

// SetAdmin creates or changes a web UI login.
func (s *Service) SetAdmin(user, pass string) error {
	user = strings.TrimSpace(user)
	if user == "" || len(pass) < 8 {
		return errors.New("username required and password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.Store.Put(model.Key(model.KindAdmin, user), model.Admin{Username: user, PasswordHash: string(h)}, store.Cluster)
	return err
}

// dummyHash keeps failed logins for unknown users as slow as real ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("meshgate-dummy"), bcrypt.DefaultCost)

// AdminHash returns the stored password hash of an admin login.
func (s *Service) AdminHash(user string) (string, bool) {
	a, ok := store.Get[model.Admin](s.Store, model.Key(model.KindAdmin, user))
	return a.PasswordHash, ok
}

// CheckAdmin verifies a web UI login.
func (s *Service) CheckAdmin(user, pass string) bool {
	a, ok := store.Get[model.Admin](s.Store, model.Key(model.KindAdmin, user))
	if !ok {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(pass)) == nil
}

// Handler exposes the operations as a JSON API (mounted at /v1/ by the
// local socket and /api/ by the web UI).
func (s *Service) Handler(prefix string) http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h func(r *http.Request) (any, error)) {
		method, path, _ := strings.Cut(pattern, " ")
		mux.HandleFunc(method+" "+prefix+path, func(w http.ResponseWriter, r *http.Request) {
			v, err := h(r)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(v)
		})
	}
	route("GET view", func(r *http.Request) (any, error) { return s.View(), nil })
	route("POST update", func(r *http.Request) (any, error) {
		var b struct {
			Node string `json:"node"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		if s.Update == nil {
			return nil, errors.New("updates are not available here")
		}
		msg, err := s.Update(b.Node)
		return map[string]string{"message": msg}, err
	})
	route("GET history", func(r *http.Request) (any, error) {
		if s.History == nil {
			return nil, errors.New("traffic history is not available here")
		}
		return s.History(r.URL.Query())
	})
	route("POST history-settings", func(r *http.Request) (any, error) {
		var b struct {
			LogServer string `json:"log_server"`
			LogDays   int    `json:"log_days"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.SetHistorySettings(b.LogServer, b.LogDays)
	})
	route("GET changelog", func(r *http.Request) (any, error) {
		return map[string]string{"text": changelog.Text}, nil
	})
	route("GET traffic", func(r *http.Request) (any, error) {
		if s.Traffic == nil {
			return []traffic.Node{}, nil
		}
		return s.Traffic(), nil
	})
	route("POST diag", func(r *http.Request) (any, error) {
		var c diag.Check
		if err := decode(r, &c); err != nil {
			return nil, err
		}
		return diag.Run(r.Context(), c), nil
	})
	route("POST forward", func(r *http.Request) (any, error) {
		var b struct {
			Forward model.Forward `json:"forward"`
			Scope   store.Scope   `json:"scope"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return s.PutForward(b.Forward, scopeOf(b.Scope))
	})
	route("POST route", func(r *http.Request) (any, error) {
		var b struct {
			Route model.HTTPRoute `json:"route"`
			Scope store.Scope     `json:"scope"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return s.PutRoute(b.Route, scopeOf(b.Scope))
	})
	route("POST exitroute", func(r *http.Request) (any, error) {
		var b struct {
			Route model.ExitRoute `json:"exit_route"`
			Scope store.Scope     `json:"scope"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return s.PutExitRoute(b.Route, scopeOf(b.Scope))
	})
	route("POST acl", func(r *http.Request) (any, error) {
		var b struct {
			ACL   model.ACL   `json:"acl"`
			Scope store.Scope `json:"scope"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return s.PutACL(b.ACL, scopeOf(b.Scope))
	})
	route("POST node", func(r *http.Request) (any, error) {
		var b struct {
			ID    string      `json:"id"`
			Patch NodePatch   `json:"patch"`
			Scope store.Scope `json:"scope"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return s.UpdateNode(b.ID, b.Patch, scopeOf(b.Scope))
	})
	route("POST delete", func(r *http.Request) (any, error) {
		var b struct {
			Kind  string      `json:"kind"`
			ID    string      `json:"id"`
			Scope store.Scope `json:"scope"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		if err := s.requireWriter(); err != nil {
			return nil, err
		}
		switch b.Kind {
		case model.KindNode:
			return nil, s.RemoveNode(b.ID)
		case model.KindForward, model.KindRoute, model.KindToken, model.KindACL, model.KindExitRoute:
			_, err := s.Store.Delete(model.Key(b.Kind, b.ID), scopeOf(b.Scope))
			return map[string]bool{"ok": true}, err
		}
		return nil, errors.New("cannot delete that kind")
	})
	route("POST toggle", func(r *http.Request) (any, error) {
		var b struct {
			Kind    string `json:"kind"`
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.Toggle(b.Kind, b.ID, b.Enabled)
	})
	route("POST clear-local", func(r *http.Request) (any, error) {
		var b struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.Store.ClearLocal(model.Key(b.Kind, b.ID))
	})
	route("POST token", func(r *http.Request) (any, error) {
		var b struct {
			Kind     model.NodeKind `json:"kind"`
			Uses     int            `json:"uses"`
			TTLHours int            `json:"ttl_hours"`
			Note     string         `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		if b.Uses == 0 {
			b.Uses = 1
		}
		tok, err := s.CreateToken(b.Kind, b.Uses, time.Duration(b.TTLHours)*time.Hour, b.Note)
		return map[string]string{"token": tok}, err
	})
	route("POST static-device", func(r *http.Request) (any, error) {
		var b struct {
			Name  string `json:"name"`
			Relay string `json:"relay"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return s.AddStaticDevice(b.Name, b.Relay)
	})
	route("POST network", func(r *http.Request) (any, error) {
		var b struct {
			ACMEEmail string `json:"acme_email"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.SetNetwork(b.ACMEEmail)
	})
	route("POST admin", func(r *http.Request) (any, error) {
		var b struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.SetAdmin(b.Username, b.Password)
	})
	return mux
}

func scopeOf(s store.Scope) store.Scope {
	if s == store.Local {
		return store.Local
	}
	return store.Cluster
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		return fmt.Errorf("bad request: %v", err)
	}
	return nil
}

func netSplit(hostport string) (string, string, error) {
	i := strings.LastIndex(hostport, ":")
	if i <= 0 || i == len(hostport)-1 {
		return "", "", errors.New("missing port")
	}
	return hostport[:i], hostport[i+1:], nil
}
