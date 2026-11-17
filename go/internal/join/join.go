package join

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// Request is sent by a device that wants to join.
type Request struct {
	TokenID    string         `json:"token_id"`
	Secret     string         `json:"secret"`
	Name       string         `json:"name"`
	Kind       model.NodeKind `json:"kind"`
	PublicKey  string         `json:"public_key"`
	Endpoints  []string       `json:"endpoints,omitempty"`
	Routes     []string       `json:"routes,omitempty"`
	Relay      bool           `json:"relay,omitempty"`
	ListenPort int            `json:"listen_port,omitempty"`
	JoinAddr   string         `json:"join_addr,omitempty"`
	JoinFP     string         `json:"join_fp,omitempty"`
	WebUI      bool           `json:"webui,omitempty"`
	LANPolicy  string         `json:"lan_policy,omitempty"`
	MeshPort   int            `json:"mesh_port,omitempty"`
	WebPort    int            `json:"web_port,omitempty"`
}

// Response tells the device who it is and seeds its store.
type Response struct {
	Node    model.Node    `json:"node"`
	Network model.Network `json:"network"`
	Entries []store.Entry `json:"entries"`
	// APISecret lets clients sync through the public join API (needed on
	// iOS, where a VPN extension cannot reach the mesh through its own
	// tunnel). Only returned once, at join.
	APISecret string `json:"api_secret,omitempty"`
}

// VisibleTo reports whether a record of key may be sent to a node of kind.
// Clients only need the topology; config, tokens and admin logins stay on
// servers.
func VisibleTo(kind model.NodeKind, key string) bool {
	if kind == model.NodeServer {
		return true
	}
	k, _ := model.SplitKey(key)
	return k == model.KindNetwork || k == model.KindNode || k == model.KindStatus
}

// FilterFor keeps what node n may see. Besides Filter's records, a client
// sees the access rules that name it (or apply to every device), so its app
// can show what it may reach; any other rule reaches it only as a deletion,
// which also removes a rule that stopped applying to it.
func FilterFor(n model.Node, in []store.Entry) []store.Entry {
	if n.Kind == model.NodeServer {
		return in
	}
	out := Filter(n.Kind, in)
	for _, e := range in {
		if k, _ := model.SplitKey(e.Key); k != model.KindACL {
			continue
		}
		var a model.ACL
		if !e.Deleted && json.Unmarshal(e.Value, &a) == nil && aclNames(a, n.ID) {
			out = append(out, e)
			continue
		}
		out = append(out, store.Entry{Key: e.Key, Deleted: true, Version: e.Version, Origin: e.Origin, Seq: e.Seq})
	}
	return out
}

func aclNames(a model.ACL, id string) bool {
	if len(a.From) == 0 {
		return true
	}
	for _, f := range a.From {
		if f == id {
			return true
		}
	}
	return false
}

// Filter keeps entries visible to kind.
func Filter(kind model.NodeKind, in []store.Entry) []store.Entry {
	if kind == model.NodeServer {
		return in
	}
	out := in[:0:0]
	for _, e := range in {
		if VisibleTo(kind, e.Key) {
			out = append(out, e)
		}
	}
	return out
}

var allocMu sync.Mutex

// Admit validates a join request against the store and registers the node.
// It is used by the join API and by the web UI/TUI for stock-app devices.
func Admit(s *store.Store, req Request, now time.Time) (Response, error) {
	allocMu.Lock()
	defer allocMu.Unlock()

	tok, ok := store.Get[model.Token](s, model.Key(model.KindToken, req.TokenID))
	if !ok || !CheckSecret(req.Secret, tok.SecretHash) {
		return Response{}, errors.New("invalid token")
	}
	if !tok.Usable(now) {
		return Response{}, errors.New("token expired or used up")
	}
	if req.Kind == "" {
		req.Kind = tok.Kind
	}
	if req.Kind != tok.Kind && !(tok.Kind == model.NodeServer && req.Kind == model.NodeClient) {
		return Response{}, fmt.Errorf("this token is for %s nodes", tok.Kind)
	}
	return register(s, req, now, func() error {
		if tok.UsesLeft > 0 {
			tok.UsesLeft--
		}
		_, err := s.Put(model.Key(model.KindToken, tok.ID), tok, store.Cluster)
		return err
	})
}

// Register adds a node without a token (used locally by admins).
func Register(s *store.Store, req Request, now time.Time) (Response, error) {
	allocMu.Lock()
	defer allocMu.Unlock()
	return register(s, req, now, nil)
}

func register(s *store.Store, req Request, now time.Time, consume func() error) (Response, error) {
	if _, err := wgtypes.ParseKey(req.PublicKey); err != nil {
		return Response{}, errors.New("invalid public key")
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := model.CheckName(req.Name); err != nil {
		return Response{}, err
	}
	for _, ep := range req.Endpoints {
		if err := model.CheckEndpoint(ep); err != nil {
			return Response{}, err
		}
	}
	switch req.LANPolicy {
	case "", model.PolicyOpen, model.PolicyRestricted, model.PolicyFirewall:
	default:
		return Response{}, errors.New("bad lan policy")
	}
	netw, ok := store.Get[model.Network](s, model.Key(model.KindNetwork, "main"))
	if !ok {
		return Response{}, errors.New("mesh not initialised")
	}
	nodes := store.List[model.Node](s, model.KindNode)
	for _, n := range nodes {
		if n.PublicKey == req.PublicKey {
			// Retried join: hand back the existing identity, but only to the
			// kind the token admits. Public keys are visible to every device,
			// so otherwise a phone token plus a server's key would fetch the
			// server's full snapshot (admin password hash included).
			if n.Kind != req.Kind {
				return Response{}, fmt.Errorf("this key is already registered as a %s node", n.Kind)
			}
			return snapshot(s, n, netw), nil
		}
	}
	for _, n := range nodes {
		if strings.EqualFold(n.Name, req.Name) {
			return Response{}, fmt.Errorf("a node named %q already exists", req.Name)
		}
	}
	for _, r := range req.Routes {
		if _, err := netip.ParsePrefix(r); err != nil {
			return Response{}, fmt.Errorf("bad route %q", r)
		}
	}
	ip, err := AllocateIP(netw, nodes)
	if err != nil {
		return Response{}, err
	}
	n := model.Node{
		ID: RandomID(), Name: req.Name, Kind: req.Kind, PublicKey: req.PublicKey,
		MeshIP: ip.String(), ListenPort: req.ListenPort, Endpoints: req.Endpoints,
		Relay: req.Relay && req.Kind == model.NodeServer, Routes: req.Routes,
		JoinAddr: req.JoinAddr, JoinFP: req.JoinFP, WebUI: req.WebUI, LANPolicy: req.LANPolicy,
		MeshPort: req.MeshPort, WebPort: req.WebPort, CreatedAt: now.Unix(),
	}
	if n.Kind != model.NodeServer {
		n.Relay, n.Routes, n.JoinAddr, n.JoinFP, n.WebUI = false, nil, "", "", false
	}
	var apiSecret string
	if n.Kind == model.NodeClient {
		apiSecret, n.APIHash = NewSecret()
	}
	if consume != nil {
		if err := consume(); err != nil {
			return Response{}, err
		}
	}
	if _, err := s.Put(model.Key(model.KindNode, n.ID), n, store.Cluster); err != nil {
		return Response{}, err
	}
	resp := snapshot(s, n, netw)
	resp.APISecret = apiSecret
	return resp, nil
}

func snapshot(s *store.Store, n model.Node, netw model.Network) Response {
	all, _ := s.Since(0)
	return Response{Node: n, Network: netw, Entries: FilterFor(n, all)}
}

// AllocateIP picks a random free address in the mesh. Random allocation
// keeps collisions negligible even if two servers admit nodes at the same
// moment while partitioned.
func AllocateIP(netw model.Network, nodes []model.Node) (netip.Addr, error) {
	pfx, err := netw.Prefix()
	if err != nil {
		return netip.Addr{}, err
	}
	if !pfx.Addr().Is4() || pfx.Bits() > 30 {
		return netip.Addr{}, errors.New("mesh must be an IPv4 /30 or larger")
	}
	used := map[netip.Addr]bool{}
	for _, n := range nodes {
		if a, err := netip.ParseAddr(n.MeshIP); err == nil {
			used[a] = true
		}
	}
	size := uint32(1) << (32 - pfx.Bits())
	base := pfx.Masked().Addr().As4()
	b := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	for i := 0; i < 64; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(size-2)))
		if a := u32(b + 1 + uint32(r.Int64())); !used[a] {
			return a, nil
		}
	}
	for off := uint32(1); off < size-1; off++ {
		if a := u32(b + off); !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("mesh address space is full")
}

func u32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Handler serves POST /v1/join.
func Handler(s *store.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := Admit(s, req, time.Now())
		if err != nil {
			// Slow down secret guessing.
			time.Sleep(500 * time.Millisecond)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("POST /v1/client/sync", func(w http.ResponseWriter, r *http.Request) {
		node, ok := authClient(s, r.Header.Get("Authorization"))
		if !ok {
			time.Sleep(500 * time.Millisecond)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req ClientSync
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// A client may only publish its own status.
		own := model.Key(model.KindStatus, node.ID)
		var accepted []store.Entry
		for _, e := range req.Entries {
			if e.Key == own && e.Origin == node.ID {
				accepted = append(accepted, e)
			}
		}
		s.Merge(accepted)
		entries, seq := s.Since(req.Since)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ClientSync{Entries: FilterFor(node, entries), Since: seq})
	})
	return mux
}

// ClientSync is the body of /v1/client/sync in both directions: the client
// sends its own status and the last seq it saw; the server answers with
// everything newer and its current seq.
type ClientSync struct {
	Since   uint64        `json:"since"`
	Entries []store.Entry `json:"entries,omitempty"`
}

// authClient checks "Bearer <node id>:<secret>".
func authClient(s *store.Store, h string) (model.Node, bool) {
	cred, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return model.Node{}, false
	}
	id, secret, ok := strings.Cut(cred, ":")
	if !ok {
		return model.Node{}, false
	}
	n, ok := store.Get[model.Node](s, model.Key(model.KindNode, id))
	if !ok || n.Kind != model.NodeClient || n.APIHash == "" || !CheckSecret(secret, n.APIHash) {
		return model.Node{}, false
	}
	return n, true
}

// SyncClient performs one client sync round against a server's join API.
func SyncClient(ctx context.Context, srv Server, nodeID, secret string, body ClientSync, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (ClientSync, error) {
	b, _ := json.Marshal(body)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: PinnedTLS(srv.FP), DialContext: dial}, Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://"+srv.Addr+"/v1/client/sync", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+nodeID+":"+secret)
	res, err := c.Do(req)
	if err != nil {
		return ClientSync{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return ClientSync{}, fmt.Errorf("sync: %s", res.Status)
	}
	var out ClientSync
	err = json.NewDecoder(res.Body).Decode(&out)
	return out, err
}

// Do redeems a token against the first server that answers.
func Do(ctx context.Context, tok Token, req Request, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (Response, error) {
	req.TokenID, req.Secret = tok.ID, tok.Secret
	body, _ := json.Marshal(req)
	var lastErr error
	for _, srv := range tok.Servers {
		resp, err := doOne(ctx, srv, body, dial)
		if err == nil {
			return resp, nil
		}
		lastErr = fmt.Errorf("%s: %w", srv.Addr, err)
		var perm permanentError
		if errors.As(err, &perm) {
			break
		}
	}
	return Response{}, lastErr
}

type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

func doOne(ctx context.Context, srv Server, body []byte, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (Response, error) {
	tr := &http.Transport{
		TLSClientConfig: PinnedTLS(srv.FP),
		DialContext:     dial,
	}
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://"+srv.Addr+"/v1/join", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return Response{}, permanentError{strings.TrimSpace(string(msg))}
	}
	var out Response
	err = json.NewDecoder(res.Body).Decode(&out)
	return out, err
}

// PinnedTLS trusts exactly the certificate with fingerprint fp.
func PinnedTLS(fp string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the fingerprint check below
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if !strings.EqualFold(hex.EncodeToString(sum[:]), fp) {
				return errors.New("join server certificate does not match token")
			}
			return nil
		},
	}
}

// EnsureCert loads or creates the join API certificate and returns it with
// its fingerprint.
func EnsureCert(certPath, keyPath string) (tls.Certificate, string, error) {
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		sum := sha256.Sum256(c.Certificate[0])
		return c, hex.EncodeToString(sum[:]), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "meshgate-join"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	return EnsureCert(certPath, keyPath)
}

// NewToken creates and stores a token, returning its string form.
func NewToken(s *store.Store, kind model.NodeKind, uses int, ttl time.Duration, note string, now time.Time) (string, model.Token, error) {
	var servers []Server
	for _, n := range store.List[model.Node](s, model.KindNode) {
		if n.Kind == model.NodeServer && n.JoinAddr != "" && n.JoinFP != "" {
			servers = append(servers, Server{Addr: n.JoinAddr, FP: n.JoinFP})
		}
	}
	if len(servers) == 0 {
		return "", model.Token{}, errors.New("no server node accepts joins yet: run `meshgate init` on a VPS (public IP) so it becomes a relay with a join address")
	}
	secret, hash := NewSecret()
	t := model.Token{ID: RandomID(), SecretHash: hash, Kind: kind, UsesLeft: uses, Note: note, CreatedAt: now.Unix()}
	if ttl > 0 {
		t.ExpiresAt = now.Add(ttl).Unix()
	}
	if _, err := s.Put(model.Key(model.KindToken, t.ID), t, store.Cluster); err != nil {
		return "", t, err
	}
	return Token{ID: t.ID, Secret: secret, Servers: servers}.Encode(), t, nil
}
