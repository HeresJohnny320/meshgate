package config

// Default locations on FreeBSD/pfSense. Everything lives under
// /usr/local/etc because pfSense's "Use RAM Disks" option wipes /var on
// every reboot.
const (
	DefaultPath   = "/usr/local/etc/meshgate/node.json"
	DefaultData   = "/usr/local/etc/meshgate/data"
	DefaultSocket = "/var/run/meshgate.sock"
)
