//go:build darwin

package meshcore

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// openTUN wraps the utun descriptor owned by NEPacketTunnelProvider.
func openTUN(fd int32) (tun.Device, error) {
	dup, err := unix.Dup(int(fd))
	if err != nil {
		return nil, err
	}
	return tun.CreateTUNFromFile(os.NewFile(uintptr(dup), "/dev/tun"), 0)
}
