package pfsense

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/webui"
)

func TestDashIndex(t *testing.T) {
	b, err := fs.ReadFile(webui.Static(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	s := dashIndex(string(b), "v1.2.3")
	for _, want := range []string{`<html data-api="/meshgate_api.php?p="`, `href="app.css?v=v1.2.3"`, `src="app.js?v=v1.2.3"`} {
		if !strings.Contains(s, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
}

func TestEmbeddedFiles(t *testing.T) {
	for _, f := range []string{"vpn_meshgate.php", "meshgate_api.php", "meshgate_config.php"} {
		if _, err := files.ReadFile("files/" + f); err != nil {
			t.Error(err)
		}
	}
	proxy, _ := files.ReadFile("files/meshgate_api.php")
	if !strings.Contains(string(proxy), "@@SOCKET@@") {
		t.Error("proxy lost its socket placeholder")
	}
}
