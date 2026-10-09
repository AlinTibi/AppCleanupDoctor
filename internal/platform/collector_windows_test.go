//go:build windows

package platform

import (
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestCommandTarget(t *testing.T) {
	for _, tc := range []struct{ in, want string }{{`"C:\Program Files\Acme\app.exe" -quiet`, `c:\program files\acme\app.exe`}, {`C:\Apps\app.exe /a`, `c:\apps\app.exe`}, {`C:\Program Files\Acme\app.exe /a`, ""}, {`rundll32.exe thing.dll`, ""}, {`cmd.exe /c C:\Gone\app.exe`, ""}, {`"C:\Apps\app.exe" "C:\Other\app.exe"`, `c:\apps\app.exe`}} {
		if got := commandTarget(tc.in); got != tc.want {
			t.Fatalf("%q -> %q want %q", tc.in, got, tc.want)
		}
	}
}
func TestStructuredTarget(t *testing.T) {
	if structuredTarget("app.exe", `C:\Acme`) != `c:\acme\app.exe` {
		t.Fatal("working directory")
	}
	if structuredTarget("app.exe", "") != "" {
		t.Fatal("guessed PATH")
	}
	if structuredTarget(`\\server\app.exe`, "") != "" {
		t.Fatal("network path accepted")
	}
}
func TestProbeDoesNotModifyInput(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "hello.exe")
	b := []byte("synthetic input")
	os.WriteFile(p, b, 0600)
	probe := DiskProbe{}
	if probe.Check(p) != core.Exists {
		t.Fatal("existing")
	}
	if probe.Check(filepath.Join(d, "gone.exe")) != core.Missing {
		t.Fatal("missing")
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(b) {
		t.Fatal("changed input")
	}
}
func TestProbeRejectsSymlinkAncestor(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	os.Mkdir(target, 0700)
	link := filepath.Join(d, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("Windows symlink privilege unavailable; reparse model test still covers withholding")
	}
	if (DiskProbe{}).Check(filepath.Join(link, "gone.exe")) != core.Unknown {
		t.Fatal("followed reparse point")
	}
}
