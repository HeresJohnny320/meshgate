//go:build !linux

package hostfw

// Detect is Linux only (pfSense/FreeBSD open their ports in pf anchors;
// Windows gets its firewall rule from the installer).
func Detect() string { return "" }

// Sync is Linux only.
func Sync(statePath string, rules []Rule, off bool) (string, error) { return "", nil }

// RemoveAll is Linux only.
func RemoveAll(statePath string) {}
