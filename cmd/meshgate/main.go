// Command meshgate is a self-hosted WireGuard mesh with built-in port
// forwarding and HTTPS publishing. One binary does everything:
//
//	meshgate init           set up this machine (web UI/first server, or join)
//	meshgate join <token>   join an existing mesh
//	meshgate agent          run the node (systemd runs this)
//	meshgate tui            manage the mesh from the terminal
//	meshgate status         show nodes and paths
//	meshgate token          create a join token
//	meshgate leave          remove meshgate from this machine
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/heresjohnny320/meshgate/internal/agent"
	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/tui"
)

const usage = `meshgate - self-hosted WireGuard mesh, port forwarding and HTTPS tunnels

Usage:
  meshgate init                 set up this machine (asks: web UI or node)
  meshgate join <token>         join an existing mesh
  meshgate agent                run the node (started by systemd)
  meshgate tui                  manage the mesh in the terminal
  meshgate status               show nodes and connection paths
  meshgate token [flags]        create a join token (--kind client|server)
  meshgate webui enable|disable host the web UI on this node (or stop)
  meshgate service install|uninstall  run at boot (Windows service; systemd/rc.d are set up by the installer)
  meshgate leave                stop and remove meshgate config from this machine
  meshgate version

Global flags:
  -config path                  node config (default %s)
`

func main() {
	log.SetFlags(0)
	cfgPath := config.DefaultPath
	args := os.Args[1:]
	if len(args) >= 2 && (args[0] == "-config" || args[0] == "--config") {
		cfgPath, args = args[1], args[2:]
	}
	if len(args) == 0 {
		fmt.Printf(usage, config.DefaultPath)
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(cfgPath, rest)
	case "join":
		err = cmdJoin(cfgPath, rest)
	case "agent", "up":
		err = cmdAgent(cfgPath)
	case "tui":
		err = withSocket(cfgPath, tui.Run)
	case "status":
		err = withSocket(cfgPath, cmdStatus)
	case "token":
		err = cmdToken(cfgPath, rest)
	case "leave":
		err = cmdLeave(cfgPath, rest)
	case "webui":
		err = cmdWebUI(cfgPath, rest)
	case "service":
		err = cmdService(cfgPath, rest)
	case "ports":
		err = cmdPorts(cfgPath)
	case "version", "--version", "-v":
		fmt.Println("meshgate", agent.Version)
	case "help", "-h", "--help":
		fmt.Printf(usage, config.DefaultPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, config.DefaultPath)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdAgent(cfgPath string) error {
	log.SetFlags(log.LstdFlags)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load %s: %w (run `meshgate init` first)", cfgPath, err)
	}
	a, err := agent.New(cfg)
	if err != nil {
		return err
	}
	return runService(a.Run)
}

// runInForeground runs f until Ctrl-C / SIGTERM.
func runInForeground(f func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return f(ctx)
}

func withSocket(cfgPath string, f func(socket string) error) error {
	socket := config.DefaultSocket
	if cfg, err := config.Load(cfgPath); err == nil {
		socket = cfg.Socket
	} else if os.IsPermission(err) {
		return fmt.Errorf("permission denied; run as root/Administrator")
	}
	return f(socket)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return fs
}

type listFlag []string

func (l *listFlag) String() string     { return fmt.Sprint(*l) }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }
