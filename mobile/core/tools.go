//go:build tools

package meshcore

// Keeps golang.org/x/mobile in go.mod; `gomobile bind` needs its bind package.
import _ "golang.org/x/mobile/bind"
