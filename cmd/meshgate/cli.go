package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/localapi"
	"github.com/heresjohnny320/meshgate/internal/model"
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
	for _, w := range v.Runtime.Warnings {
		fmt.Println("warning:", w)
	}
	return nil
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
	os.RemoveAll(cfg.DataDir)
	os.Remove(cfgPath)
	fmt.Println("Removed. Also remove this node from the mesh in the web UI or TUI on another node.")
	return nil
}

// cmdWebUI turns the web UI on or off for this node. The web UI is optional
// per node; the TUI works everywhere.
func cmdWebUI(cfgPath string, args []string) error {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "disable") {
		return fmt.Errorf("usage: meshgate webui enable [--public] [--http] | disable")
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
		fmt.Println("If this mesh has no admin login yet, rerun with --admin-pass.")
	}
	return nil
}

// cmdPorts prints the ports this node listens on publicly, one
// "proto port" per line (used by the installer to open host firewalls).
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
