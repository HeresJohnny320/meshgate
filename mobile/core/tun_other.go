//go:build !android && !darwin && !linux

package meshcore

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

func openTUN(fd int32) (tun.Device, error) {
	return nil, errors.New("meshcore: platform not supported")
}
