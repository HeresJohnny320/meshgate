//go:build !freebsd

package agent

// beep: servers on Linux and Windows rarely have a speaker; the log line
// is the signal there.
func beep(bool) {}
