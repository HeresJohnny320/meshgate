package tui

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
)

// TestPreview prints screens when MESHGATE_TUI_PREVIEW=1 (for eyeballing).
func TestPreview(t *testing.T) {
	if os.Getenv("MESHGATE_TUI_PREVIEW") == "" {
		t.Skip("set MESHGATE_TUI_PREVIEW=1")
	}
	m := &model_{width: 100, height: 38, v: ops.View{
		SelfID:  "vps",
		Network: model.Network{CIDR: "100.88.0.0/16"},
		Nodes: []ops.Item[model.Node]{
			{Value: model.Node{ID: "vps", Name: "vps", Kind: model.NodeServer, Relay: true, WebUI: true, MeshIP: "100.88.0.1", Endpoints: []string{"203.0.113.10:51820"}}},
			{Value: model.Node{ID: "home", Name: "pfsense", Kind: model.NodeServer, MeshIP: "100.88.0.2", Routes: []string{"192.168.1.0/24", "192.168.20.0/24"}, LANPolicy: "restricted"}},
			{Value: model.Node{ID: "phone", Name: "pixel", Kind: model.NodeClient, MeshIP: "100.88.0.9"}},
		},
		Forwards: []ops.Item[model.Forward]{
			{Value: model.Forward{ID: "a1b2c3d4", Name: "Minecraft", Proto: "tcp", EdgeNode: "vps", ListenPort: 25565, TargetNode: "home", TargetPort: 25565, PreserveClientIP: true, Enabled: true}},
			{Value: model.Forward{ID: "e5f6a7b8", Name: "Valheim", Proto: "udp", EdgeNode: "vps", ListenPort: 2456, ListenEnd: 2458, TargetNode: "home", TargetIP: "192.168.1.30", TargetPort: 2456}, Local: true},
		},
		Runtime: ops.Runtime{HomeRelay: "", Peers: map[string]ops.PeerRuntime{
			"home":  {Path: "direct", Endpoint: "198.51.100.20:51820", LastHandshake: time.Now().Add(-12 * time.Second)},
			"phone": {Path: "direct", LastHandshake: time.Now().Add(-5 * time.Minute)},
		}},
	}}
	for _, tab := range []int{tabForwards, tabNodes} {
		m.tab = tab
		fmt.Println(m.View())
		fmt.Println()
	}
	m.tab = tabForwards
	m.message = "Forward Valheim disabled. Its public port is now blocked."
	m.forwardForm(&m.v.Forwards[0])
	fmt.Println(m.View())
}
