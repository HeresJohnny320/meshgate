//go:build !linux && !freebsd && !windows

package config

// Default locations elsewhere (development builds only).
const (
	DefaultPath   = "/etc/meshgate/node.json"
	DefaultData   = "/var/lib/meshgate"
	DefaultSocket = "/var/run/meshgate.sock"
)
