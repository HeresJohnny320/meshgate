// Package pfsense puts meshgate into the pfSense GUI: a VPN > meshgate page
// with the full dashboard behind the pfSense login, and the mesh interface
// assigned as MESHGATE so that Firewall > Rules > MESHGATE decides what mesh
// devices may reach (the node's LAN policy becomes "firewall").
//
// pfSense has no API for packages outside its own repository, so the PHP
// helper edits config.xml through pfSense's own config functions (which keep
// a backup of every revision under Diagnostics > Backup & Restore).
package pfsense

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed files
var files embed.FS

// Iface is the mesh interface name on pfSense. The tun_ prefix makes pfSense
// skip it in its boot-time interface mismatch check (meshgate creates it
// after pfSense has configured its interfaces), like its own WireGuard
// package does with tun_wg*.
const Iface = "tun_mg0"

const (
	www       = "/usr/local/www"
	assetsDir = www + "/meshgate"
	helperDir = "/usr/local/share/meshgate"
	php       = "/usr/local/bin/php"
)

// WriteFiles installs the GUI pages, the dashboard assets (from dash, the
// web UI's static files) and the config helper.
func WriteFiles(dash fs.FS, socket, version string) error {
	page, _ := files.ReadFile("files/vpn_meshgate.php")
	proxy, _ := files.ReadFile("files/meshgate_api.php")
	helper, _ := files.ReadFile("files/meshgate_config.php")
	proxy = []byte(strings.ReplaceAll(string(proxy), "@@SOCKET@@", socket))

	index, err := fs.ReadFile(dash, "index.html")
	if err != nil {
		return err
	}
	s := dashIndex(string(index), version)

	out := map[string][]byte{
		filepath.Join(www, "vpn_meshgate.php"): page,
		filepath.Join(www, "meshgate_api.php"): proxy,
		filepath.Join(helperDir, "config.php"): helper,
		filepath.Join(assetsDir, "index.html"): []byte(s),
	}
	for _, name := range []string{"app.js", "app.css"} {
		b, err := fs.ReadFile(dash, name)
		if err != nil {
			return err
		}
		out[filepath.Join(assetsDir, name)] = b
	}
	for path, b := range out {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// dashIndex routes the dashboard's API calls through the proxy and versions
// its assets so browsers pick up new ones after an upgrade.
func dashIndex(index, version string) string {
	s := strings.Replace(index, "<html", `<html data-api="/meshgate_api.php?p="`, 1)
	s = strings.Replace(s, `href="app.css"`, `href="app.css?v=`+version+`"`, 1)
	return strings.Replace(s, `src="app.js"`, `src="app.js?v=`+version+`"`, 1)
}

// RemoveFiles deletes everything WriteFiles installed.
func RemoveFiles() {
	os.Remove(filepath.Join(www, "vpn_meshgate.php"))
	os.Remove(filepath.Join(www, "meshgate_api.php"))
	os.RemoveAll(assetsDir)
	os.RemoveAll(helperDir)
}

// Configure edits config.xml: "install" adds the menu entry, the MESHGATE
// interface and (first time only) its default pass rule, and returns the
// interface's pfSense name (optN); "remove" undoes it.
func Configure(action string) (string, error) {
	args := []string{"-f", filepath.Join(helperDir, "config.php"), action}
	if action == "install" {
		args = append(args, Iface)
	}
	out, err := exec.Command(php, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return "", fmt.Errorf("pfSense config: %v: %s", err, s)
	}
	return s, nil
}

// Installed reports whether the GUI integration is installed here.
func Installed() bool {
	_, err := os.Stat(filepath.Join(helperDir, "config.php"))
	return err == nil
}
