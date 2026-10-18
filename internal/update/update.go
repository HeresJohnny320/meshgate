// Package update installs new meshgate releases from GitHub: find the latest
// tag, download this platform's file, verify it against the release's
// SHA256SUMS, and swap it in for the running binary. The service manager
// (systemd Restart=always, FreeBSD daemon -r, Windows recovery actions)
// starts the new version once the old process exits.
package update

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// BaseURL is the GitHub repository; MESHGATE_UPDATE_URL overrides it (tests).
var BaseURL = "https://github.com/heresjohnny320/meshgate"

func init() {
	if u := os.Getenv("MESHGATE_UPDATE_URL"); u != "" {
		BaseURL = strings.TrimRight(u, "/")
	}
}

var client = &http.Client{Timeout: 5 * time.Minute}

// Latest returns the newest release tag (e.g. "v0.2.9"). It reads the
// redirect of /releases/latest, which has no API rate limit.
func Latest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, BaseURL+"/releases/latest", nil)
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("no release found (%s)", res.Status)
	}
	tag := loc[i+len("/tag/"):]
	if _, ok := parse(tag); !ok {
		return "", fmt.Errorf("unexpected release tag %q", tag)
	}
	return tag, nil
}

// Newer reports whether latest is a newer release than current. Development
// builds ("dev", git hashes) never count as older, so they are not replaced.
func Newer(current, latest string) bool {
	c, ok1 := parse(current)
	l, ok2 := parse(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Asset is the release file for this platform.
func Asset() string {
	if runtime.GOOS == "windows" {
		return "meshgate-windows-" + runtime.GOARCH + ".zip"
	}
	return "meshgate-" + runtime.GOOS + "-" + runtime.GOARCH
}

// Fetch downloads a release file and checks it against SHA256SUMS.
func Fetch(ctx context.Context, tag, name string) ([]byte, error) {
	base := BaseURL + "/releases/download/" + tag + "/"
	body, err := get(ctx, base+name, 512<<20)
	if err != nil {
		return nil, err
	}
	sums, err := get(ctx, base+"SHA256SUMS", 1<<20)
	if err != nil {
		return nil, fmt.Errorf("checksums: %w", err)
	}
	want := ""
	for _, l := range strings.Split(string(sums), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			want = f[0]
		}
	}
	got := sha256.Sum256(body)
	if want == "" || want != hex.EncodeToString(got[:]) {
		return nil, fmt.Errorf("checksum mismatch for %s: refusing to install", name)
	}
	return body, nil
}

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, limit))
}

// Install replaces the running binary (exe, normally os.Executable()) with
// release tag. The caller then restarts meshgate.
func Install(ctx context.Context, tag, exe string) error {
	data, err := Fetch(ctx, tag, Asset())
	if err != nil {
		return err
	}
	files := map[string][]byte{filepath.Base(exe): data}
	if runtime.GOOS == "windows" {
		if files, err = unzip(data); err != nil {
			return err
		}
	}
	dir := filepath.Dir(exe)
	for name, b := range files {
		if err := replace(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}
	return nil
}

// replace writes path atomically. A running file cannot be overwritten on
// Windows, but it can be renamed away first.
func replace(path string, b []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		os.Remove(path + ".old")
		if err := os.Rename(path, path+".old"); err != nil && !errors.Is(err, os.ErrNotExist) {
			os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func unzip(data []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if name != "meshgate.exe" && name != "wintun.dll" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 256<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		out[name] = b
	}
	if out["meshgate.exe"] == nil {
		return nil, errors.New("release zip has no meshgate.exe")
	}
	return out, nil
}
