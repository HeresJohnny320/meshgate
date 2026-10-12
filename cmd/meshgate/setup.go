package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
	"github.com/heresjohnny320/meshgate/internal/ports"
	"github.com/heresjohnny320/meshgate/internal/probe"
	"github.com/heresjohnny320/meshgate/internal/store"
)

var in = bufio.NewReader(os.Stdin)

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askYes(prompt string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	a := strings.ToLower(ask(prompt+" ("+d+")", ""))
	if a == "" {
		return def
	}
	return strings.HasPrefix(a, "y")
}

func askPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal for the password prompt; pass --admin-pass")
	}
	for {
		fmt.Print(prompt + ": ")
		p, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\nRepeat: ")
		p2, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		switch {
		case len(p) < 8:
			fmt.Println("  password must be at least 8 characters")
		case string(p) != string(p2):
			fmt.Println("  passwords do not match")
		default:
			return string(p), nil
		}
	}
}

// machineFlags describe how this machine is reached; shared by init and join.
type machineFlags struct {
	name      *string
	endpoints listFlag
	routes    listFlag
	noRoutes  *bool
	relay     *bool
	port      *int
	dataDir   *string
	userspace *bool
	lanPolicy *string
	webPort   *int
	yes       *bool
	explicit  map[string]bool // flags the user actually typed
}

// markExplicit records which flags were given on the command line, so only
// default ports are switched automatically.
func (m *machineFlags) markExplicit(fs *flag.FlagSet) {
	m.explicit = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { m.explicit[f.Name] = true })
}

// portPlan holds the ports chosen during setup.
type portPlan struct{ wg, join, mesh, web int }

// choosePorts picks free ports. Default ports that are already in use (an
// existing WireGuard on 51820, something on 8080, ...) are moved to the next
// free one; a port given explicitly with a flag is never moved silently.
func choosePorts(mf *machineFlags, kind model.NodeKind, webui bool) (portPlan, error) {
	var p portPlan
	wg, ok := ports.WireGuard(*mf.port)
	switch {
	case !ok:
		return p, fmt.Errorf("no free UDP port pair found near %d", *mf.port)
	case wg != *mf.port && mf.explicit["port"]:
		return p, fmt.Errorf("UDP port %d (or %d for probes) is already in use; choose another --port, or leave it out to pick one automatically", *mf.port, *mf.port+probe.Offset)
	case wg != *mf.port:
		fmt.Printf("UDP %d is already in use (another WireGuard?); using %d instead (probes on %d).\n", *mf.port, wg, wg+probe.Offset)
	}
	p.wg, *mf.port = wg, wg
	taken := map[int]bool{}
	pick := func(want int, what string, explicit bool) (int, error) {
		got, ok := ports.TCP(want, taken)
		switch {
		case !ok:
			return 0, fmt.Errorf("no free TCP port found near %d for %s", want, what)
		case got != want && explicit:
			return 0, fmt.Errorf("TCP port %d for %s is already in use; choose another, or leave it out to pick one automatically", want, what)
		case got != want:
			fmt.Printf("TCP %d is already in use; %s will use %d instead.\n", want, what, got)
		}
		taken[got] = true
		return got, nil
	}
	var err error
	if p.mesh, err = pick(model.DefaultMeshPort, "mesh sync", false); err != nil {
		return p, err
	}
	if kind == model.NodeServer {
		if p.join, err = pick(model.DefaultJoinPort, "joins", false); err != nil {
			return p, err
		}
	}
	if webui {
		if p.web, err = pick(*mf.webPort, "the web UI", mf.explicit["web-port"]); err != nil {
			return p, err
		}
	}
	return p, nil
}

func addMachineFlags(fs *flag.FlagSet) *machineFlags {
	m := &machineFlags{
		name:      fs.String("name", "", "node name (default: hostname)"),
		noRoutes:  fs.Bool("no-routes", false, "do not share any LAN subnet"),
		relay:     fs.Bool("relay", false, "act as relay (this node has a public endpoint)"),
		port:      fs.Int("port", model.DefaultWGPort, "WireGuard UDP port (probes use port+2)"),
		dataDir:   fs.String("data-dir", config.DefaultData, "state directory"),
		userspace: fs.Bool("userspace", false, "always use built-in wireguard-go"),
		lanPolicy: fs.String("lan-policy", "", "open | restricted: who may reach shared subnets (default: restricted on pfSense/FreeBSD, open on Linux)"),
		webPort:   fs.Int("web-port", model.DefaultWebPort, "web UI TCP port"),
		yes:       fs.Bool("y", false, "do not ask questions; use flags and defaults"),
	}
	fs.Var(&m.endpoints, "endpoint", "host:port others can reach this node at (repeatable)")
	fs.Var(&m.routes, "route", "LAN subnet to share, e.g. 192.168.1.0/24 (repeatable)")
	return m
}

// setupAnswers is what both init and join collect about this machine.
type setupAnswers struct {
	name      string
	kind      model.NodeKind
	endpoints []string
	relay     bool
	routes    []string
	port      int
	joinPort  int
	lanPolicy string
}

func newNodeConfig(mf *machineFlags, kind model.NodeKind, pp portPlan) (config.Node, wgtypes.Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return config.Node{}, key, err
	}
	cfg := config.Node{PrivateKey: key.String(), Kind: kind, DataDir: *mf.dataDir, Userspace: *mf.userspace}
	if *mf.dataDir != config.DefaultData {
		cfg.Socket = filepath.Join(*mf.dataDir, "meshgate.sock")
	}
	cfg.MeshPort = pp.mesh
	cfg.Defaults()
	if kind == model.NodeServer {
		cfg.JoinListen = ":" + strconv.Itoa(pp.join)
	}
	return cfg, key, os.MkdirAll(cfg.DataDir, 0o700)
}

func cmdInit(cfgPath string, args []string) error {
	fs := newFlags("init")
	role := fs.String("role", "", "controller (web UI, new mesh) | webui (web UI, join mesh) | server (node, join mesh) | standalone (node, new mesh)")
	cidr := fs.String("cidr", "100.88.0.0/16", "mesh address range")
	adminUser := fs.String("admin-user", "admin", "web UI admin username")
	adminPass := fs.String("admin-pass", "", "web UI admin password (prompted if empty)")
	acme := fs.String("acme-email", "", "Let's Encrypt email for HTTPS routes")
	webPublic := fs.Bool("web-public", false, "serve the web UI on all interfaces")
	mf := addMachineFlags(fs)
	fs.Parse(args)
	if _, err := os.Stat(cfgPath); err == nil {
		return fmt.Errorf("%s already exists; this machine is already set up (use `meshgate leave` to start over)", cfgPath)
	}
	r := *role
	if r == "" {
		fmt.Println(`Welcome to meshgate. What is this machine?
  1) Web UI   - start a new mesh and host the dashboard here
  2) Web UI   - add the dashboard to an existing mesh (needs a server token)
  3) Node     - join an existing mesh (managed with the TUI or the web UI)
  4) Node     - start a new mesh without a web UI (TUI only)

Every node has the TUI (sudo meshgate tui); the web UI only runs where you
install it, and nodes keep working when it is offline.`)
		switch ask("Choose 1-4", "1") {
		case "1":
			r = "controller"
		case "2":
			r = "webui"
		case "3":
			r = "server"
		case "4":
			r = "standalone"
		default:
			return errors.New("invalid choice")
		}
	}
	switch r {
	case "server", "webui":
		extra := []string{"--kind", "server"}
		if r == "webui" {
			extra = append(extra, "--webui")
			if *webPublic {
				extra = append(extra, "--web-public")
			}
		}
		return cmdJoin(cfgPath, append(append([]string{ask("Paste the join token (server type)", "")}, extra...), args...))
	case "controller", "standalone":
	default:
		return fmt.Errorf("unknown role %q", r)
	}
	webui := r == "controller"
	mf.markExplicit(fs)
	pp, err := choosePorts(mf, model.NodeServer, webui)
	if err != nil {
		return err
	}

	a := gatherMachine(model.NodeServer, mf)
	a.joinPort = pp.join
	if !*mf.yes {
		*cidr = ask("Mesh address range", *cidr)
	}
	if _, err := netip.ParsePrefix(*cidr); err != nil {
		return fmt.Errorf("mesh range: %w", err)
	}
	if webui && *adminPass == "" {
		if !*mf.yes {
			*adminUser = ask("Web UI admin username", *adminUser)
		}
		p, err := askPassword("Web UI admin password")
		if err != nil {
			return err
		}
		*adminPass = p
	}
	if !*mf.yes && *acme == "" {
		*acme = ask("Email for Let's Encrypt certificates (needed for HTTPS routes, optional)", "")
	}

	cfg, key, err := newNodeConfig(mf, model.NodeServer, pp)
	if err != nil {
		return err
	}
	cfg.NodeID = join.RandomID()
	_, fp, err := join.EnsureCert(cfg.CertPath(), cfg.KeyPath())
	if err != nil {
		return err
	}
	s, err := store.Open(cfg.StatePath(), cfg.NodeID)
	if err != nil {
		return err
	}
	netw := model.Network{Name: "main", CIDR: *cidr, ACMEEmail: *acme, CreatedAt: time.Now().Unix()}
	s.Put(model.Key(model.KindNetwork, "main"), netw, store.Cluster)
	// The first node is registered directly; everyone else uses a token.
	ip, err := join.AllocateIP(netw, nil)
	if err != nil {
		return err
	}
	self := model.Node{
		ID: cfg.NodeID, Name: a.name, Kind: model.NodeServer, PublicKey: key.PublicKey().String(),
		MeshIP: ip.String(), ListenPort: a.port, Endpoints: a.endpoints, Relay: a.relay, Routes: a.routes,
		LANPolicy: a.lanPolicy, WebUI: webui, WebPort: pp.web, MeshPort: pp.mesh, CreatedAt: time.Now().Unix(),
	}
	if addr := joinAddr(a); addr != "" {
		self.JoinAddr, self.JoinFP = addr, fp
	}
	s.Put(model.Key(model.KindNode, self.ID), self, store.Cluster)
	if webui {
		o := &ops.Service{Store: s, SelfID: self.ID}
		if err := o.SetAdmin(*adminUser, *adminPass); err != nil {
			return err
		}
		cfg.WebListen = webListen(self.MeshIP, pp.web, *webPublic, *mf.yes)
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("\nCreated mesh %s. This node is %s (%s).\n", *cidr, self.Name, self.MeshIP)
	printNextSteps(self, cfg, a)
	return nil
}

func cmdJoin(cfgPath string, args []string) error {
	fs := newFlags("join")
	kind := fs.String("kind", "", "server or client (default: ask)")
	webui := fs.Bool("webui", false, "also host the web UI on this node")
	webPublic := fs.Bool("web-public", false, "serve the web UI on all interfaces")
	adminUser := fs.String("admin-user", "admin", "web UI admin username (only if the mesh has none yet)")
	adminPass := fs.String("admin-pass", "", "web UI admin password")
	mf := addMachineFlags(fs)
	// Allow the token before or after flags.
	var tokStr string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		tokStr, args = args[0], args[1:]
	}
	fs.Parse(args)
	if tokStr == "" {
		tokStr = fs.Arg(0)
	}
	if tokStr == "" {
		tokStr = ask("Paste the join token", "")
	}
	tok, err := join.Decode(tokStr)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return fmt.Errorf("%s already exists; this machine is already set up", cfgPath)
	}
	k := model.NodeKind(*kind)
	if *webui {
		k = model.NodeServer
	}
	if k == "" && !*mf.yes {
		if strings.HasPrefix(ask("Is this a server (VPS / home server) or a client (laptop)? s/c", "s"), "c") {
			k = model.NodeClient
		}
	}
	if k == "" {
		k = model.NodeServer
	}
	mf.markExplicit(fs)
	pp, err := choosePorts(mf, k, *webui)
	if err != nil {
		return err
	}
	a := gatherMachine(k, mf)
	a.joinPort = pp.join

	cfg, key, err := newNodeConfig(mf, k, pp)
	if err != nil {
		return err
	}
	req := join.Request{Name: a.name, Kind: k, PublicKey: key.PublicKey().String(), Endpoints: a.endpoints,
		Routes: a.routes, Relay: a.relay, ListenPort: a.port, LANPolicy: a.lanPolicy, WebUI: *webui,
		MeshPort: pp.mesh, WebPort: pp.web}
	if k == model.NodeServer {
		_, fp, err := join.EnsureCert(cfg.CertPath(), cfg.KeyPath())
		if err != nil {
			return err
		}
		if addr := joinAddr(a); addr != "" {
			req.JoinAddr, req.JoinFP = addr, fp
		}
	}
	fmt.Println("Joining...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var d net.Dialer
	resp, err := join.Do(ctx, tok, req, d.DialContext)
	if err != nil {
		return fmt.Errorf("join failed: %w", err)
	}
	cfg.NodeID = resp.Node.ID
	s, err := store.Open(cfg.StatePath(), cfg.NodeID)
	if err != nil {
		return err
	}
	if _, err := s.Merge(resp.Entries); err != nil {
		return err
	}
	if *webui {
		cfg.WebListen = webListen(resp.Node.MeshIP, pp.web, *webPublic, *mf.yes)
		if err := ensureAdmin(s, resp.Node.ID, *adminUser, *adminPass); err != nil {
			return err
		}
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("Joined as %s (%s).\n", resp.Node.Name, resp.Node.MeshIP)
	printNextSteps(resp.Node, cfg, a)
	return nil
}

// gatherMachine works out how this machine is reached, from flags and (unless
// -y) questions.
func gatherMachine(kind model.NodeKind, mf *machineFlags) setupAnswers {
	host, _ := os.Hostname()
	a := setupAnswers{kind: kind, port: *mf.port, name: *mf.name, relay: *mf.relay,
		endpoints: mf.endpoints, routes: mf.routes}
	interactive := !*mf.yes
	if a.name == "" {
		a.name = host
		if interactive {
			a.name = ask("Name for this node", host)
		}
	}
	if kind != model.NodeServer {
		return a
	}
	if runtime.GOOS == "windows" {
		// Windows nodes cannot route into their LAN; share nothing.
		*mf.noRoutes = true
	}
	if len(mf.endpoints) > 0 || !interactive {
		// Explicit flags (or -y): auto-detect only what was not given.
		autoEndpoints := len(a.endpoints) == 0
		if autoEndpoints {
			if src := outboundIP(); src.IsValid() {
				a.endpoints = []string{net.JoinHostPort(src.String(), strconv.Itoa(a.port))}
				// A VPS with a public IP becomes a relay. A home router
				// (pfSense) does not unless asked: relaying uses its upload.
				a.relay = a.relay || (!src.IsPrivate() && !isCGNAT(src) && !fw.IsPfSense())
			}
		}
		if len(a.routes) == 0 && !*mf.noRoutes && !a.relay {
			a.routes = autoRoutes()
		}
		if *mf.noRoutes {
			a.routes = nil
		}
		if autoEndpoints {
			a.endpoints = appendLANEndpoints(a.endpoints, a.routes, a.port)
		}
		a.lanPolicy = defaultPolicy(*mf.lanPolicy)
		return a
	}

	src := outboundIP()
	pub := ""
	if src.IsValid() && !src.IsPrivate() && !isCGNAT(src) {
		pub = src.String()
	}
	fmt.Println("\nHow can other devices reach this machine?")
	pub = ask("Public IP or DNS name (leave empty if behind home NAT with no port forward)", pub)
	if pub != "" {
		a.endpoints = append(a.endpoints, net.JoinHostPort(pub, strconv.Itoa(a.port)))
		a.relay = askYes("Use this node as a relay for devices that cannot connect directly (recommended for a VPS)", true)
	}
	if src.IsValid() && (src.IsPrivate() || isCGNAT(src)) {
		lan := net.JoinHostPort(src.String(), strconv.Itoa(a.port))
		if askYes("Add LAN address "+lan+" so devices on the same network connect directly", true) {
			a.endpoints = append(a.endpoints, lan)
		}
	}
	if *mf.noRoutes {
		return a
	}
	var sugg []string
	fmt.Println("\nShare LAN subnets (VLANs) so mesh devices can reach other machines on this network.")
	for _, l := range fw.LocalLANs(config.DefaultIface) {
		fmt.Printf("  %-18s on %s\n", l.CIDR, l.Iface)
		sugg = append(sugg, l.CIDR)
	}
	def := ""
	if !a.relay {
		def = strings.Join(sugg, ",")
	}
	for _, r := range strings.Split(ask("Subnets to share (comma separated, empty for none)", def), ",") {
		if r = strings.TrimSpace(r); r != "" {
			a.routes = append(a.routes, r)
		}
	}
	before := len(a.endpoints)
	a.endpoints = appendLANEndpoints(a.endpoints, a.routes, a.port)
	for _, e := range a.endpoints[before:] {
		fmt.Println("  devices on that network will connect directly via", e)
	}
	a.lanPolicy = defaultPolicy(*mf.lanPolicy)
	if len(a.routes) > 0 && *mf.lanPolicy == "" {
		fmt.Println(`
Who may reach these subnets (and this machine) through the mesh?
  1) Any mesh device
  2) Only what access rules allow (lock down: add rules per IP/port/VLAN
     in the TUI or web UI; port forwards and HTTPS routes keep working)`)
		def := "1"
		if a.lanPolicy == model.PolicyRestricted {
			def = "2"
		}
		if ask("Choose 1 or 2", def) == "2" {
			a.lanPolicy = model.PolicyRestricted
		} else {
			a.lanPolicy = model.PolicyOpen
		}
	}
	return a
}

// autoRoutes picks the local private networks to share. On pfSense the WAN
// network is skipped: only LAN and VLAN interfaces are shared.
func autoRoutes() []string {
	wan := ""
	if fw.IsPfSense() {
		wan = fw.DetectWAN()
	}
	var out []string
	for _, l := range fw.LocalLANs(config.DefaultIface) {
		if l.Iface != wan {
			out = append(out, l.CIDR)
		}
	}
	return out
}

// appendLANEndpoints adds this machine's own address in every shared subnet
// (LAN, each VLAN), so a phone on home Wi-Fi or a VLAN connects directly.
func appendLANEndpoints(eps, routes []string, port int) []string {
	have := map[string]bool{}
	for _, e := range eps {
		have[e] = true
	}
	ifs, _ := net.Interfaces()
	for _, r := range routes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			for _, ad := range addrs {
				n, ok := ad.(*net.IPNet)
				if !ok || n.IP.To4() == nil {
					continue
				}
				ip, _ := netip.AddrFromSlice(n.IP.To4())
				if pfx.Contains(ip) {
					e := net.JoinHostPort(ip.String(), strconv.Itoa(port))
					if !have[e] {
						have[e] = true
						eps = append(eps, e)
					}
				}
			}
		}
	}
	return eps
}

// defaultPolicy locks down by default on pfSense/FreeBSD (a firewall) and
// leaves Linux servers open unless asked.
func defaultPolicy(flag string) string {
	switch flag {
	case model.PolicyOpen, model.PolicyRestricted:
		return flag
	}
	if runtime.GOOS == "freebsd" {
		return model.PolicyRestricted
	}
	return model.PolicyOpen
}

func webListen(meshIP string, port int, public, yes bool) []string {
	if public || (!yes && askYes("Also serve the web UI on all interfaces (0.0.0.0)? Only do this behind a firewall", false)) {
		return []string{":" + strconv.Itoa(port)}
	}
	return []string{"127.0.0.1:" + strconv.Itoa(port), net.JoinHostPort(meshIP, strconv.Itoa(port))}
}

func listenPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// ensureAdmin makes sure the mesh has a web UI login, creating one if the
// replicated config has none (or a password was given explicitly).
func ensureAdmin(s *store.Store, selfID, user, pass string) error {
	if len(s.Keys(model.KindAdmin)) > 0 && pass == "" {
		return nil
	}
	if pass == "" {
		p, err := askPassword("Web UI admin password")
		if err != nil {
			return err
		}
		pass = p
	}
	return (&ops.Service{Store: s, SelfID: selfID}).SetAdmin(user, pass)
}

// joinAddr is where new devices can redeem tokens: the public endpoint's host.
func joinAddr(a setupAnswers) string {
	if !a.relay || len(a.endpoints) == 0 {
		return ""
	}
	host, _, err := net.SplitHostPort(a.endpoints[0])
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(a.joinPort))
}

func outboundIP() netip.Addr {
	c, err := net.Dial("udp4", "1.1.1.1:80") // no packets are sent
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	ip, _ := netip.AddrFromSlice(c.LocalAddr().(*net.UDPAddr).IP.To4())
	return ip
}

func isCGNAT(a netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func printNextSteps(self model.Node, cfg config.Node, a setupAnswers) {
	sudo := "sudo "
	if runtime.GOOS != "linux" {
		sudo = "" // pfSense/FreeBSD shells run as root
	}
	fmt.Println("\nNext steps:")
	fmt.Printf("  %-40s # start the node (the installer does this)\n", startHint)
	if self.Kind == model.NodeServer {
		fmt.Printf("  %-40s # manage forwards, HTTPS routes, rules, devices\n", sudo+"meshgate tui")
		fmt.Printf("  %-40s # add a phone or laptop\n", sudo+"meshgate token --kind client")
	}
	if len(cfg.WebListen) > 0 {
		wp := listenPort(cfg.WebListen[0])
		fmt.Printf("  web UI: http://%s  (from this machine: http://127.0.0.1:%d)\n", net.JoinHostPort(self.MeshIP, strconv.Itoa(wp)), wp)
	}
	if a.relay {
		fmt.Printf("\nOpen these ports on this machine's firewall / cloud security group:\n  UDP %d (WireGuard), UDP %d (probes), TCP %d (joins)\n",
			a.port, a.port+2, a.joinPort)
	} else if self.Kind == model.NodeServer && fw.IsPfSense() {
		fmt.Printf("\nmeshgate opens UDP %d and %d on the WAN itself (pf anchor userrules/meshgate).\n", a.port, a.port+2)
		if self.LANPolicy == model.PolicyRestricted {
			fmt.Println("LAN policy is restricted: add access rules for what mesh devices may reach.")
		}
	} else if self.Kind == model.NodeServer {
		fmt.Printf("\nOptional: forward UDP %d and %d on your router to this machine for direct connections from outside.\n", a.port, a.port+2)
	}
}
