// Package config holds the node-local settings that never replicate:
// identity, private key and listen addresses.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/heresjohnny320/meshgate/internal/model"
)

// DefaultIface is the mesh interface name.
const DefaultIface = "mg0"

// Node is /etc/meshgate/node.json.
type Node struct {
	NodeID     string         `json:"node_id"`
	PrivateKey string         `json:"private_key"`
	Kind       model.NodeKind `json:"kind"`
	Iface      string         `json:"iface"`
	DataDir    string         `json:"data_dir"`
	Socket     string         `json:"socket"`
	ProbePort  int            `json:"probe_port"`
	MeshPort   int            `json:"mesh_port"`
	// Join API (public, TLS). Enabled on server nodes with a public endpoint.
	JoinListen string `json:"join_listen,omitempty"`
	// Web UI listeners; empty disables the web UI on this node.
	WebListen []string `json:"web_listen,omitempty"`
	// Userspace forces wireguard-go even when the kernel module exists.
	Userspace bool `json:"userspace,omitempty"`
	// pf anchors on FreeBSD/pfSense (defaults: natrules/meshgate,
	// userrules/meshgate).
	PFNatAnchor    string `json:"pf_nat_anchor,omitempty"`
	PFRdrAnchor    string `json:"pf_rdr_anchor,omitempty"`
	PFFilterAnchor string `json:"pf_filter_anchor,omitempty"`
}

// StatePath is the replicated store file.
func (n Node) StatePath() string { return filepath.Join(n.DataDir, "state.json") }

// CertPath / KeyPath hold the join API's self-signed certificate.
func (n Node) CertPath() string { return filepath.Join(n.DataDir, "join.crt") }
func (n Node) KeyPath() string  { return filepath.Join(n.DataDir, "join.key") }

// CertMagicDir stores ACME certificates for HTTPS routes.
func (n Node) CertMagicDir() string { return filepath.Join(n.DataDir, "certs") }

// Defaults fills empty fields.
func (n *Node) Defaults() {
	if n.Iface == "" {
		n.Iface = DefaultIface
	}
	if n.DataDir == "" {
		n.DataDir = DefaultData
	}
	if n.Socket == "" {
		n.Socket = DefaultSocket
	}
	if n.ProbePort == 0 {
		n.ProbePort = model.DefaultProbePort
	}
	if n.MeshPort == 0 {
		n.MeshPort = model.DefaultMeshPort
	}
}

// Load reads the node config.
func Load(path string) (Node, error) {
	var n Node
	b, err := os.ReadFile(path)
	if err != nil {
		return n, err
	}
	if err := json.Unmarshal(b, &n); err != nil {
		return n, err
	}
	n.Defaults()
	return n, nil
}

// Save writes the node config with owner-only permissions.
func Save(path string, n Node) error {
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	if err := SecureDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
