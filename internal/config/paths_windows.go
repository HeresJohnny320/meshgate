package config

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var programData = func() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}()

// Default locations on Windows.
var (
	DefaultPath   = filepath.Join(programData, "meshgate", "node.json")
	DefaultData   = filepath.Join(programData, "meshgate", "data")
	DefaultSocket = filepath.Join(programData, "meshgate", "meshgate.sock")
)

// SecureDir restricts dir to SYSTEM and Administrators: it holds the private
// key and the local control socket.
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
