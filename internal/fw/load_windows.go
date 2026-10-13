package fw

// Windows nodes do not manage firewall rules: they cannot be forward edges,
// subnet routers or enforce LAN policies (the agent warns if configured).
// Allow the forwarded ports in Windows Defender Firewall yourself.

// Render returns nothing on Windows.
func Render(p Plan) string { return "" }

// Load is a no-op on Windows.
func Load(string) error { return nil }

// Remove is a no-op on Windows.
func Remove() error { return nil }

// DetectWAN is only needed for pf.
func DetectWAN() string { return "" }

// IsPfSense is always false on Windows.
func IsPfSense() bool { return false }

// ReadCounters is not implemented here yet (traffic stats come from Linux edges).
func ReadCounters() map[string][2]uint64 { return nil }
