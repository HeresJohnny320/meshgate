//go:build !windows

package config

import "os"

// SecureDir creates dir readable by root only.
func SecureDir(dir string) error { return os.MkdirAll(dir, 0o700) }
