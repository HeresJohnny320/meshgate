// Package diag is meshgate's built-in test kit: a small test service that
// answers on one TCP+UDP port (point a forward or an HTTPS route at it), and
// checks run from this node (ping, traceroute, TCP, UDP, HTTP/HTTPS).
package diag

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// UDPProbe is what the UDP check sends; the test service answers it.
const UDPProbe = "meshgate?"

// MyIPURL answers with the caller's public IP in plain text (the "myip"
// check: which address do websites see, e.g. through an exit node).
var MyIPURL = "https://api.ipify.org"

// Serve runs the test service on port (all interfaces) until ctx ends:
// HTTP on TCP, a one-line echo on UDP. Both say which node answered and
// which address the request came from.
func Serve(ctx context.Context, port int, node string) error {
	addr := ":" + strconv.Itoa(port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "meshgate test service: it works\n\nnode:      %s\nyou are:   %s\nhost:      %s\nprotocol:  %s\n",
			node, r.RemoteAddr, r.Host, r.Proto)
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			fmt.Fprintf(w, "forwarded for: %s (HTTPS route; original %s)\n", v, r.Header.Get("X-Forwarded-Proto"))
		}
		fmt.Fprintf(w, "time:      %s\n", time.Now().Format(time.RFC3339))
	}), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				pc.WriteTo([]byte(fmt.Sprintf("meshgate test service on %s: you are %s\n", node, from)), from)
			}
		}
	}()
	go func() {
		<-ctx.Done()
		srv.Close()
		pc.Close()
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Check is one diagnostic request.
type Check struct {
	Kind   string `json:"kind"`   // ping, trace, tcp, udp, http, myip
	Target string `json:"target"` // host or IP; a URL for http
	Port   int    `json:"port,omitempty"`
}

// Result is a check's outcome; Output is human-readable.
type Result struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-:]*$`)

// Run performs c from this node.
func Run(ctx context.Context, c Check) Result {
	target := strings.TrimSpace(c.Target)
	if c.Kind == "myip" {
		ip, err := PublicIP(ctx)
		if err != nil {
			return Result{Output: "could not get the public IP: " + err.Error()}
		}
		return Result{OK: true, Output: "Websites see this device as " + ip}
	}
	if c.Kind != "http" && !hostRE.MatchString(target) {
		return Result{Output: "enter a host name or IP address"}
	}
	switch c.Kind {
	case "ping":
		return command(ctx, 20*time.Second, pingArgs(target))
	case "trace":
		return command(ctx, 60*time.Second, traceArgs(target))
	case "tcp":
		return tcpCheck(ctx, target, c.Port)
	case "udp":
		return udpCheck(target, c.Port)
	case "http":
		return httpCheck(ctx, target)
	}
	return Result{Output: "unknown check " + c.Kind}
}

// PublicIP asks MyIPURL which address our traffic leaves from.
func PublicIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, MyIPURL, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64))
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected answer %q", ip)
	}
	return ip, nil
}

func pingArgs(host string) []string {
	if runtime.GOOS == "windows" {
		return []string{"ping", "-n", "4", host}
	}
	return []string{"ping", "-c", "4", host}
}

func traceArgs(host string) []string {
	switch {
	case runtime.GOOS == "windows":
		return []string{"tracert", "-d", "-h", "20", host}
	case has("traceroute"):
		return []string{"traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", host}
	case has("tracepath"):
		return []string{"tracepath", "-n", "-m", "20", host}
	}
	return []string{"traceroute", host} // reports "not found" below
}

func has(name string) bool { _, err := exec.LookPath(name); return err == nil }

func command(ctx context.Context, limit time.Duration, args []string) Result {
	if !has(args[0]) {
		return Result{Output: args[0] + " is not installed on this node"}
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if ctx.Err() != nil {
		s += "\n(stopped after " + limit.String() + ")"
	}
	return Result{OK: err == nil, Output: "$ " + strings.Join(args, " ") + "\n" + s}
}

func tcpCheck(ctx context.Context, host string, port int) Result {
	if port < 1 || port > 65535 {
		return Result{Output: "enter a port"}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{Output: fmt.Sprintf("TCP %s: not reachable (%v)", addr, err)}
	}
	c.Close()
	return Result{OK: true, Output: fmt.Sprintf("TCP %s: open, connected in %s", addr, time.Since(start).Round(time.Millisecond))}
}

func udpCheck(host string, port int) Result {
	if port < 1 || port > 65535 {
		return Result{Output: "enter a port"}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return Result{Output: fmt.Sprintf("UDP %s: %v", addr, err)}
	}
	defer c.Close()
	start := time.Now()
	c.SetDeadline(start.Add(3 * time.Second))
	c.Write([]byte(UDPProbe))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return Result{Output: fmt.Sprintf("UDP %s: no answer within 3s. UDP has no handshake, so this only works against a meshgate test service (or another service that replies).", addr)}
	}
	return Result{OK: true, Output: fmt.Sprintf("UDP %s: answered in %s\n%s", addr, time.Since(start).Round(time.Millisecond), strings.TrimSpace(string(buf[:n])))}
}

func httpCheck(ctx context.Context, raw string) Result {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return Result{Output: "enter an http:// or https:// address"}
	}
	start := time.Now()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Output: fmt.Sprintf("GET %s: %v", raw, err)}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 600))
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s\nstatus:  %s in %s\n", res.Request.URL, res.Status, time.Since(start).Round(time.Millisecond))
	if s := res.Header.Get("Server"); s != "" {
		fmt.Fprintf(&b, "server:  %s\n", s)
	}
	if st := res.TLS; st != nil && len(st.PeerCertificates) > 0 {
		crt := st.PeerCertificates[0]
		fmt.Fprintf(&b, "tls:     %s, certificate for %s\nissuer:  %s\nexpires: %s (%d days)\n",
			tls.VersionName(st.Version), strings.Join(crt.DNSNames, ", "), crt.Issuer.CommonName,
			crt.NotAfter.Format("2006-01-02"), int(time.Until(crt.NotAfter).Hours()/24))
	}
	fmt.Fprintf(&b, "\n%s", strings.TrimSpace(string(body)))
	return Result{OK: res.StatusCode < 400, Output: b.String()}
}
