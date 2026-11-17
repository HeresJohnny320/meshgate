//go:build android

package meshcore

import "golang.zx2c4.com/wireguard/tun"

// openTUN wraps the file descriptor from VpnService.Builder.establish().
func openTUN(fd int32) (tun.Device, error) {
	t, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	return t, err
}
