package wg

import "testing"

func TestParseDump(t *testing.T) {
	out := "privkey\tpubkey\t51820\toff\n" +
		"PEER1=\t(none)\t203.0.113.10:51820\t100.88.0.1/32,192.168.1.0/24\t1791595117\t508\t1716\t20\n" +
		"PEER2=\t(none)\t(none)\t100.88.0.9/32\t0\t0\t0\toff\n"
	st := parseDump(out)
	if len(st) != 2 {
		t.Fatalf("got %d peers", len(st))
	}
	p := st["PEER1="]
	if p.Endpoint != "203.0.113.10:51820" || p.RxBytes != 508 || p.TxBytes != 1716 || p.LastHandshake.Unix() != 1791595117 {
		t.Fatalf("peer1 %+v", p)
	}
	if q := st["PEER2="]; q.Endpoint != "" || !q.LastHandshake.IsZero() {
		t.Fatalf("peer2 %+v", q)
	}
}
