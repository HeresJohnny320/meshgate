package main

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/hostfw"
	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/localapi"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
	"github.com/heresjohnny320/meshgate/internal/ports"
	"github.com/heresjohnny320/meshgate/internal/probe"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/wg"
)

func cmdStatus(socket string) error {
	v, err := localapi.New(socket).View()
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, n := range v.Nodes {
		names[n.Value.ID] = n.Value.Name
	}
	fmt.Printf("mesh %s   this node: %s", v.Network.CIDR, names[v.SelfID])
	if v.Runtime.HomeRelay != "" {
		fmt.Printf("   preferred relay: %s", names[v.Runtime.HomeRelay])
	}
	fmt.Println()
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tMESH IP\tPATH\tHANDSHAKE\tENDPOINT")
	for _, it := range v.Nodes {
		n := it.Value
		p, ok := v.Runtime.Peers[n.ID]
		path, hs := "", ""
		if n.ID == v.SelfID {
			path = "(this node)"
		} else if ok {
			path = p.Path
			if strings.HasPrefix(path, "via ") {
				path = "via " + names[strings.TrimPrefix(path, "via ")]
			}
			hs = "never"
			if p.LastHandshake.Year() > 2000 {
				hs = time.Since(p.LastHandshake).Round(time.Second).String() + " ago"
			}
		}
		kind := string(n.Kind)
		if n.Relay {
			kind += ",relay"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", n.Name, kind, n.MeshIP, path, hs, p.Endpoint)
	}
	w.Flush()
	if len(v.Forwards) > 0 {
		fmt.Println("\nForwards:")
		for _, it := range v.Forwards {
			f := it.Value
			state := "on"
			if !f.Enabled {
				state = "off"
			}
			fmt.Printf("  %-16s %s %s:%d -> %s:%d [%s]\n", f.Name, f.Proto, names[f.EdgeNode], f.ListenPort, names[f.TargetNode], f.TargetPort, state)
		}
	}
	printWebFPs(v.Nodes, v.SelfID, v.Runtime.WebCertFP, v.Runtime.WebCAFP)
	for _, w := range v.Runtime.Warnings {
		fmt.Println("warning:", w)
	}
	return nil
}

// cmdWebUICA shows this server's web UI CA and how to install it, prints it
// (--pem), or replaces it (--new: every device must install the new one).
func cmdWebUICA(cfgPath string, args []string) error {
	fs := newFlags("webui ca")
	printPEM := fs.Bool("pem", false, "print the CA certificate (PEM) to stdout")
	renew := fs.Bool("new", false, "make a new CA (devices that installed the old one must install the new one)")
	fs.Parse(args)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if *renew {
		for _, p := range []string{cfg.WebCACertPath(), cfg.WebCAKeyPath(), cfg.WebCertPath(), cfg.WebKeyPath()} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := restartService(); err != nil {
			return fmt.Errorf("removed the old CA, but restarting meshgate failed: %w", err)
		}
		fmt.Println("Made a new web UI CA. Install it on your devices again (meshgate webui ca).")
		return nil
	}
	b, err := os.ReadFile(cfg.WebCACertPath())
	if err != nil {
		return fmt.Errorf("no web UI CA yet (it is made when the web UI starts with https): %w", err)
	}
	if *printPEM {
		os.Stdout.Write(b)
		return nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return fmt.Errorf("%s: not a PEM certificate", cfg.WebCACertPath())
	}
	sum := sha256.Sum256(blk.Bytes)
	fmt.Printf(`Web UI CA of this server: %s
SHA-256 fingerprint: %s

Install it once on each device you open the web UI from; the browser then
trusts the web UI without a warning, and a man in the middle gets an error.
It can only vouch for this server's names and addresses and the mesh range.

Get it: from this file, "sudo meshgate webui ca --pem > meshgate-ca.crt", or the
web UI (Settings -> Web UI certificate) opened over the mesh IP. Before
installing, check its fingerprint matches the one above.
  Windows:  double-click it -> Install Certificate -> Local Machine ->
            "Trusted Root Certification Authorities"
  macOS:    open it, then in Keychain Access set it to "Always Trust"
  Linux:    sudo cp meshgate-ca.crt /usr/local/share/ca-certificates/ &&
            sudo update-ca-certificates  (Firefox: Settings -> Certificates -> Import)
  Android:  Settings -> Security -> Encryption & credentials -> Install a
            certificate -> CA certificate
  iPhone:   open it, install the profile in Settings, then turn it on in
            General -> About -> Certificate Trust Settings
`, cfg.WebCACertPath(), colonHex(sum[:]))
	return nil
}

func colonHex(b []byte) string {
	s := make([]string, len(b))
	for i, c := range b {
		s[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(s, ":")
}

// printWebFPs lists the web UI certificate fingerprints. This output comes
// from the local socket and the node records synced over WireGuard, so
// unlike the web UI's own Settings page, a man in the middle on the way to
// the browser cannot change it.
func printWebFPs(nodes []ops.Item[model.Node], selfID, selfFP, selfCAFP string) {
	var lines []string
	for _, it := range nodes {
		n := it.Value
		fp, ca := n.WebFP, n.WebCAFP
		if n.ID == selfID && selfFP != "" {
			fp, ca = selfFP, selfCAFP
		}
		if n.WebUI && n.WebTLS && fp != "" {
			lines = append(lines, fmt.Sprintf("  %-16s %s", n.Name, fp))
			if ca != "" {
				lines = append(lines, fmt.Sprintf("  %-16s %s", "  its CA", ca))
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Println("\nWeb UI certificates (SHA-256; the browser must show the same; CA: see meshgate webui ca):")
	for _, l := range lines {
		fmt.Println(l)
	}
}

func cmdToken(cfgPath string, args []string) error {
	fs := newFlags("token")
	kind := fs.String("kind", "client", "client (phone/laptop) or server")
	uses := fs.Int("uses", 1, "how many devices may use it (-1 = unlimited)")
	ttl := fs.Duration("ttl", 24*time.Hour, "validity (0 = forever)")
	note := fs.String("note", "", "note shown in the UI")
	fs.Parse(args)
	return withSocket(cfgPath, func(socket string) error {
		var out struct{ Token string }
		err := localapi.New(socket).Post("token", map[string]any{
			"kind": *kind, "uses": *uses, "ttl_hours": int(ttl.Hours()), "note": *note,
		}, &out)
		if err != nil {
			return err
		}
		if q, err := qrcode.New(out.Token, qrcode.Low); err == nil {
			fmt.Println(q.ToSmallString(false))
		}
		fmt.Println(out.Token)
		if *kind == "server" {
			linux, pfsense, windows := join.InstallCommands(out.Token)
			fmt.Printf("\nLinux server (shell):\n  %s\n\npfSense (Diagnostics > Command Prompt > Execute Shell Command):\n  %s\n\nWindows (PowerShell as Administrator):\n  %s\n", linux, pfsense, windows)
		} else {
			linux, _, windows := join.InstallCommands(out.Token)
			fmt.Printf("\nPhone: scan the QR code with the meshgate app.\nLinux laptop:\n  %s --kind client\nWindows PC (PowerShell as Administrator):\n  %s --kind client\n", linux, windows)
		}
		return nil
	})
}

func cmdLeave(cfgPath string, args []string) error {
	fs := newFlags("leave")
	yes := fs.Bool("y", false, "do not ask for confirmation")
	fs.Parse(args)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if !*yes {
		fmt.Print("This stops meshgate and deletes its config and keys from this machine. Continue? (y/N): ")
		if a, _ := in.ReadString('\n'); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(a)), "y") {
			return nil
		}
	}
	stopService()
	wg.DestroyInterface(cfg.Iface)
	fw.Remove()
	hostfw.RemoveAll(cfg.HostFirewallStatePath())
	os.RemoveAll(cfg.DataDir)
	os.Remove(cfgPath)
	fmt.Println("Removed. Also remove this node from the mesh in the web UI or TUI on another node.")
	return nil
}

// cmdWebUI turns the web UI on or off for this node. The web UI is optional
// per node; the TUI works everywhere.
func cmdWebUI(cfgPath string, args []string) error {
	if len(args) > 0 && args[0] == "ca" {
		return cmdWebUICA(cfgPath, args[1:])
	}
	if len(args) == 0 || (args[0] != "enable" && args[0] != "disable") {
		return fmt.Errorf("usage: meshgate webui enable [--public] [--http] | disable | ca [--pem] [--new]")
	}
	fs := newFlags("webui")
	public := fs.Bool("public", false, "serve on all interfaces instead of localhost + mesh IP")
	port := fs.Int("port", 0, "TCP port (default: 8080, or the next free one)")
	plain := fs.Bool("http", false, "serve plain http instead of https (self-signed certificate)")
	user := fs.String("admin-user", "admin", "admin username to create if the mesh has none")
	pass := fs.String("admin-pass", "", "admin password to create if the mesh has none")
	fs.Parse(args[1:])
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Kind != "" && cfg.Kind != "server" {
		return fmt.Errorf("the web UI runs on server nodes only")
	}
	api := localapi.New(cfg.Socket)
	v, err := api.View()
	if err != nil {
		return err
	}
	if args[0] == "disable" {
		cfg.WebListen = nil
	} else {
		var meshIP string
		for _, n := range v.Nodes {
			if n.Value.ID == v.SelfID {
				meshIP = n.Value.MeshIP
			}
		}
		want := model.DefaultWebPort
		switch {
		case *port != 0:
			want = *port
		case len(cfg.WebListen) > 0:
			want = listenPort(cfg.WebListen[0]) // already on: keep its port
		}
		got := want
		if len(cfg.WebListen) == 0 || *port != 0 {
			p, ok := ports.TCP(want, nil)
			switch {
			case !ok:
				return fmt.Errorf("no free TCP port near %d", want)
			case p != want && *port != 0:
				return fmt.Errorf("TCP port %d is already in use; choose another --port", want)
			case p != want:
				fmt.Printf("TCP %d is already in use; the web UI will use %d instead.\n", want, p)
			}
			got = p
		}
		cfg.WebListen = webListen(meshIP, got, *public, true)
		cfg.WebPlainHTTP = *plain
		if *pass != "" {
			if err := api.Post("admin", map[string]string{"username": *user, "password": *pass}, nil); err != nil {
				return err
			}
		}
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return err
	}
	if err := restartService(); err != nil {
		return fmt.Errorf("saved, but restarting meshgate failed: %w", err)
	}
	if len(cfg.WebListen) == 0 {
		fmt.Println("Web UI disabled on this node.")
	} else {
		fmt.Println("Web UI enabled:", strings.Join(cfg.WebListen, ", "))
		if *public {
			fmt.Println("Note: on LAN or public addresses only the certificate protects the login. Prefer the")
			fmt.Println("mesh IP (WireGuard checks the server); otherwise compare the browser's certificate")
			fmt.Println("fingerprint with `meshgate status` before typing the admin password.")
		}
		if *plain {
			fmt.Println("Note: plain http sends the admin password unencrypted on any address but the mesh IP.")
		}
		fmt.Println("If this mesh has no admin login yet, rerun with --admin-pass.")
	}
	return nil
}

// cmdPorts prints the ports this node listens on publicly, one
// "proto port" per line.
func cmdPorts(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	s, err := store.Open(cfg.StatePath(), cfg.NodeID)
	if err != nil {
		return err
	}
	self, _ := store.Get[model.Node](s, model.Key(model.KindNode, cfg.NodeID))
	wgPort := self.ListenPort
	if wgPort == 0 {
		wgPort = model.DefaultWGPort
	}
	fmt.Printf("udp %d\nudp %d\n", wgPort, wgPort+probe.Offset)
	if p := listenPort(cfg.JoinListen); p != 0 {
		fmt.Printf("tcp %d\n", p)
	}
	return nil
}
