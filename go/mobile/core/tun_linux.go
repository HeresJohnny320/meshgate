//go:build linux && !android

package meshcore

import (
	"golang.zx2c4.com/wireguard/tun"

	"github.com/heresjohnny320/meshgate/internal/fw"
)

// Desktop Linux runs as root (phonesim), so WireGuard's sockets can carry
// the bypass mark.
func init() { wgMark = fw.MarkBypass }

// openTUN is used by tests and desktop experiments on Linux.
func openTUN(fd int32) (tun.Device, error) {
	t, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	return t, err
}
