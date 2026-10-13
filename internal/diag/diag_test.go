package diag

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestServiceAndChecks(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, port, "home")
	time.Sleep(200 * time.Millisecond)

	if r := Run(ctx, Check{Kind: "tcp", Target: "127.0.0.1", Port: port}); !r.OK || !strings.Contains(r.Output, "open") {
		t.Errorf("tcp: %+v", r)
	}
	if r := Run(ctx, Check{Kind: "udp", Target: "127.0.0.1", Port: port}); !r.OK || !strings.Contains(r.Output, "on home: you are 127.0.0.1") {
		t.Errorf("udp: %+v", r)
	}
	r := Run(ctx, Check{Kind: "http", Target: "http://127.0.0.1:" + itoa(port) + "/"})
	if !r.OK || !strings.Contains(r.Output, "node:      home") || !strings.Contains(r.Output, "you are:   127.0.0.1") {
		t.Errorf("http: %+v", r)
	}
	if r := Run(ctx, Check{Kind: "tcp", Target: "127.0.0.1", Port: freePort(t)}); r.OK {
		t.Errorf("closed port reported open: %+v", r)
	}
}

func TestRejectsBadTargets(t *testing.T) {
	for _, c := range []Check{
		{Kind: "ping", Target: "-f 1.2.3.4"},
		{Kind: "trace", Target: "1.2.3.4; reboot"},
		{Kind: "tcp", Target: "host", Port: 0},
		{Kind: "http", Target: "file:///etc/passwd"},
		{Kind: "rm", Target: "x"},
	} {
		if r := Run(context.Background(), c); r.OK || strings.HasPrefix(r.Output, "$ ") {
			t.Errorf("%+v ran: %+v", c, r)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestMyIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.10\n")) }))
	defer srv.Close()
	old := MyIPURL
	MyIPURL = srv.URL
	defer func() { MyIPURL = old }()
	if r := Run(context.Background(), Check{Kind: "myip"}); !r.OK || !strings.Contains(r.Output, "203.0.113.10") {
		t.Errorf("myip: %+v", r)
	}
}
