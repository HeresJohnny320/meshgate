//go:build linux && !android

package meshcore

import "golang.zx2c4.com/wireguard/tun"

// openTUN is used by tests and desktop experiments on Linux.
func openTUN(fd int32) (tun.Device, error) {
	t, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	return t, err
}
