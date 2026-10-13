//go:build linux

// Command phonesim runs the mobile engine (meshcore) on Linux with a fake
// platform layer, so the phone code path can be tested end to end without a
// phone. It behaves like the iOS app: one TUN device whose settings are
// updated in place.
//
//	phonesim -dir /tmp/phone -join mg1.... -name phone
//	kill -USR1 <pid>   # simulate a Wi-Fi/LTE change
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/heresjohnny320/meshgate/internal/diag"
	meshcore "github.com/heresjohnny320/meshgate/mobile/core"
)

const (
	ifname     = "mgphone"
	table      = "51820" // tunnel routes, like Android's VPN routing
	bypassMark = 0x4d46  // fw.MarkBypass
)

type platform struct {
	fd     int32
	routes []string
}

// Protect marks the socket like Android's VpnService.protect: marked
// traffic skips the tunnel's routing table.
func (p *platform) Protect(fd int32) bool {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, bypassMark) == nil
}
func (p *platform) Log(msg string) { log.Print(msg) }

func (p *platform) LocalAddresses() string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Name == ifname || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				out = append(out, n.IP.String())
			}
		}
	}
	return strings.Join(out, ",")
}

func (p *platform) ConfigureTunnel(settings string) int32 {
	var ts meshcore.TunnelSettings
	if err := json.Unmarshal([]byte(settings), &ts); err != nil {
		log.Print(err)
		return -1
	}
	if p.fd < 0 {
		fd, err := openTun(ifname)
		if err != nil {
			log.Printf("tun: %v", err)
			return -1
		}
		p.fd = int32(fd)
	}
	ip := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			log.Printf("ip %v: %v %s", args, err, out)
		}
	}
	ip("link", "set", ifname, "mtu", strconv.Itoa(ts.MTU), "up")
	ip("addr", "replace", fmt.Sprintf("%s/%d", ts.Address, ts.Prefix), "dev", ifname)
	// Tunnel routes live in their own table, used by every unmarked packet
	// unless the main table has a more specific route (wg-quick style), so
	// an exit node's 0.0.0.0/0 does not swallow the phone's own uplink.
	if p.routes == nil {
		ip("rule", "add", "prio", "99", "lookup", "main", "suppress_prefixlength", "0")
		ip("rule", "add", "prio", "100", "not", "fwmark", strconv.Itoa(bypassMark), "lookup", table)
	}
	keep := map[string]bool{}
	for _, r := range ts.Routes {
		keep[r] = true
		ip("route", "replace", r, "dev", ifname, "table", table)
	}
	for _, r := range p.routes {
		if !keep[r] {
			ip("route", "del", r, "dev", ifname, "table", table)
		}
	}
	if len(ts.DNS) > 0 {
		log.Printf("dns: %v", ts.DNS)
	}
	p.routes = ts.Routes
	log.Printf("tunnel settings: %s", settings)
	return p.fd
}

func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var req [unix.IFNAMSIZ + 64]byte
	copy(req[:], name)
	*(*uint16)(unsafe.Pointer(&req[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		unix.Close(fd)
		return -1, e
	}
	return fd, nil
}

func main() {
	dir := flag.String("dir", "", "state directory")
	tok := flag.String("join", "", "join token (first run)")
	name := flag.String("name", "phone", "device name")
	statusFile := flag.String("status", "", "write StatusJSON here every second")
	myIP := flag.String("myip-url", "", "URL answering with the caller's IP (the app's \"My public IP\" test)")
	cmdFile := flag.String("cmd", "", `file of app dashboard requests to run, one "METHOD PATH [JSON]" per line (read and removed every second)`)
	flag.Parse()
	log.SetFlags(log.Ltime)

	p := &platform{fd: -1}
	e, err := meshcore.NewEngine(*dir, p)
	if err != nil {
		log.Fatal(err)
	}
	if !e.IsJoined() {
		if err := e.Join(*tok, *name); err != nil {
			log.Fatalf("join: %v", err)
		}
		log.Print("joined")
	}
	if err := e.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	sig := make(chan os.Signal, 1)
	if *myIP != "" {
		diag.MyIPURL = *myIP
	}
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM)
	t := time.NewTicker(time.Second)
	for {
		select {
		case s := <-sig:
			if s == syscall.SIGUSR1 {
				log.Print("network changed")
				e.NetworkChanged()
				continue
			}
			if s == syscall.SIGUSR2 { // run the app's "My public IP" test
				go func() { log.Printf("diag myip: %s", e.Diag("myip", "", 0)) }()
				continue
			}
			e.Stop()
			return
		case <-t.C:
			if *cmdFile != "" {
				if b, err := os.ReadFile(*cmdFile); err == nil {
					os.Remove(*cmdFile)
					go runAdmin(e, string(b))
				}
			}
			if *statusFile != "" {
				os.WriteFile(*statusFile+".tmp", []byte(e.StatusJSON()), 0o644)
				os.Rename(*statusFile+".tmp", *statusFile)
			}
		}
	}
}

// runAdmin replays dashboard requests the way the app's Admin screen sends
// them, logging each reply.
func runAdmin(e *meshcore.Engine, lines string) {
	for _, l := range strings.Split(strings.TrimSpace(lines), "\n") {
		f := strings.SplitN(strings.TrimSpace(l), " ", 3)
		if len(f) < 2 {
			continue
		}
		body := ""
		if len(f) == 3 {
			body = f[2]
		}
		var r struct {
			Status int
			Body   string
			Server string
		}
		json.Unmarshal([]byte(e.Admin(f[0], f[1], body)), &r)
		if len(r.Body) > 200 {
			r.Body = r.Body[:200] + "…"
		}
		log.Printf("admin %s %s: status=%d server=%s %s", f[0], f[1], r.Status, r.Server, r.Body)
	}
}
