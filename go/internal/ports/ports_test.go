package ports

import (
	"net"
	"strconv"
	"testing"
)

func TestWireGuardSkipsBusyPort(t *testing.T) {
	// Find a free pair, occupy it, and expect the picker to move 10 up.
	base, ok := WireGuard(41820)
	if !ok {
		t.Skip("no free UDP ports")
	}
	c, err := net.ListenPacket("udp4", ":"+itoa(base))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, ok := WireGuard(base)
	if !ok || got == base || (got-base)%10 != 0 {
		t.Fatalf("got %d (base %d busy)", got, base)
	}
	// Busy probe port (base+2) must also be skipped.
	c.Close()
	p, err := net.ListenPacket("udp4", ":"+itoa(base+2))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if got, _ := WireGuard(base); got == base {
		t.Fatal("ignored busy probe port")
	}
}

func TestTCPSkipsBusyAndTaken(t *testing.T) {
	l, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := l.Addr().(*net.TCPAddr).Port
	got, ok := TCP(busy, map[int]bool{busy + 1: true})
	if !ok || got == busy || got == busy+1 {
		t.Fatalf("got %d, busy %d, taken %d", got, busy, busy+1)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
