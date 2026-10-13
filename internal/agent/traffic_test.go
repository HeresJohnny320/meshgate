package agent

import (
	"testing"
	"time"
)

func TestMetersSurviveCounterRestart(t *testing.T) {
	var ms meters
	ms.observe(map[string]uint64{"f_1_in": 1000})
	ms.at = ms.at.Add(-5 * time.Second)
	ms.observe(map[string]uint64{"f_1_in": 6000})
	total, rate := ms.get("f_1_in")
	if total != 6000 || rate < 900 || rate > 1100 {
		t.Fatalf("total %d rate %.0f", total, rate)
	}
	// Table reloaded: the counter starts again from zero.
	ms.at = ms.at.Add(-5 * time.Second)
	ms.observe(map[string]uint64{"f_1_in": 500})
	if total, _ := ms.get("f_1_in"); total != 6500 {
		t.Fatalf("total after restart %d, want 6500", total)
	}
}
