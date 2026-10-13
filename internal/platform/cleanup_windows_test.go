//go:build windows

package platform

import (
	"encoding/json"
	"github.com/AlinTibi/AppCleanupDoctor/internal/cleanup"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (NativeCleanup, core.Finding) {
	t.Helper()
	// Some Windows runners resolve GetTempPath2 under Windows/SystemTemp.
	// Product policy must keep rejecting that location; use a dedicated synthetic
	// directory under the public profile instead of weakening protected-path checks.
	public, e := windows.KnownFolderPath(windows.FOLDERID_Public, 0)
	if e != nil {
		t.Fatal(e)
	}
	base, e := os.MkdirTemp(public, "ACD-Synthetic-Test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		rel, e := filepath.Rel(public, base)
		if e != nil || strings.Contains(rel, `\`) || !strings.HasPrefix(rel, "ACD-Synthetic-Test-") {
			t.Fatal("synthetic cleanup escaped its root")
		}
		if e = os.RemoveAll(base); e != nil {
			t.Error(e)
		}
	})
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("APPDATA", base)
	source := filepath.Join(base, "Synthetic App Ș Emoji 😀")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(source, "data.txt"), []byte("exact bytes\x00\xff"), 0600); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(base, "ALMARFELD", "AppCleanupDoctor", "Quarantine")
	return NativeCleanup{root}, core.Finding{ID: "synthetic", Kind: "Files", Location: strings.ToLower(source), Target: strings.ToLower(filepath.Join(base, "absent.exe")), Evidence: []string{"synthetic controlled correlation"}}
}
func nativeItem(t *testing.T, n NativeCleanup, f core.Finding) cleanup.Item {
	t.Helper()
	a, b := n.Inspect(f)
	if a.Eligibility != cleanup.Eligible {
		t.Fatalf("inspect: %s", a.Reason)
	}
	path := filepath.Join(n.Root, "01234567890123456789012345678901", "files", "0")
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	return cleanup.Item{Finding: f, Assessment: a, Backup: b, Payload: path, State: "Preparing"}
}
func TestNativeDirectoryRoundTrip(t *testing.T) {
	n, f := fixture(t)
	nested := filepath.Join(f.Location, "nested spaces", strings.Repeat("long", 20))
	if e := os.MkdirAll(nested, 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(nested, "ș.txt"), []byte("preserve"), 0600)
	item := nativeItem(t, n, f)
	if e := n.Quarantine(item); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(f.Location); !os.IsNotExist(e) {
		t.Fatal("source not moved")
	}
	state, e := n.Recover(item)
	if e != nil || state != "Quarantined" {
		t.Fatalf("recovery: %s %v", state, e)
	}
	if e = n.Restore(item); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(filepath.Dir(f.Location))
	if e != nil {
		t.Fatal(e)
	}
	exactName := false
	for _, entry := range entries {
		if entry.Name() == "Synthetic App Ș Emoji 😀" {
			exactName = true
		}
	}
	if !exactName {
		t.Fatal("original directory name casing not restored")
	}
	b, _ := os.ReadFile(filepath.Join(f.Location, "data.txt"))
	if string(b) != "exact bytes\x00\xff" {
		t.Fatal("content changed")
	}
	b, _ = os.ReadFile(filepath.Join(nested, "ș.txt"))
	if string(b) != "preserve" {
		t.Fatal("nested bytes changed")
	}
	item.State = "RestorePending"
	if state, e = n.Recover(item); e != nil || state != "Restored" {
		t.Fatalf("restore recovery %s %v", state, e)
	}
}
func TestNativeStaleAndRestoreConflict(t *testing.T) {
	n, f := fixture(t)
	item := nativeItem(t, n, f)
	os.WriteFile(filepath.Join(f.Location, "new.txt"), []byte("changed"), 0600)
	if n.Quarantine(item) == nil {
		t.Fatal("stale tree moved")
	}
	item = nativeItem(t, n, f)
	if e := n.Quarantine(item); e != nil {
		t.Fatal(e)
	}
	os.Mkdir(f.Location, 0700)
	os.WriteFile(filepath.Join(f.Location, "replacement.txt"), []byte("do not overwrite"), 0600)
	if n.Restore(item) == nil {
		t.Fatal("overwrote replacement")
	}
	if _, e := os.Stat(item.Payload); e != nil {
		t.Fatal("lost payload")
	}
}
func TestNativeStartupFileRoundTrip(t *testing.T) {
	n, f := fixture(t)
	f.Kind = "Startup"
	f.Location = filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`, "Synthetic.lnk")
	os.MkdirAll(filepath.Dir(f.Location), 0700)
	os.WriteFile(f.Location, []byte("controlled shortcut bytes; never execute"), 0600)
	item := nativeItem(t, n, f)
	if e := n.Quarantine(item); e != nil {
		t.Fatal(e)
	}
	if e := n.Restore(item); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(f.Location)
	if !strings.HasPrefix(string(b), "controlled shortcut") {
		t.Fatal("shortcut bytes changed")
	}
}

func TestNativeMissingPayloadAndVanishedSource(t *testing.T) {
	n, f := fixture(t)
	item := nativeItem(t, n, f)
	if e := os.Rename(f.Location, f.Location+"-outside"); e != nil {
		t.Fatal(e)
	}
	if n.Quarantine(item) == nil {
		t.Fatal("vanished source accepted")
	}
	if n.Restore(item) == nil {
		t.Fatal("missing payload accepted")
	}
	state, err := n.Recover(item)
	if state != "RecoveryRequired" || err == nil {
		t.Fatal("missing source/payload falsely resolved")
	}
}
func TestNativeProtectedAndCrossVolume(t *testing.T) {
	n, f := fixture(t)
	for _, path := range []string{`C:\`, os.Getenv("USERPROFILE"), os.Getenv("LOCALAPPDATA"), `C:\Windows\leftover`, `C:\Program Files\Common Files\Acme`, n.Root} {
		f.Location = path
		a, _ := n.Inspect(f)
		if a.Eligibility == cleanup.Eligible {
			t.Fatalf("protected %s", path)
		}
	}
	f.Location = `Z:\Apps\Synthetic`
	if n.safeLocation(f) == nil {
		t.Fatal("cross volume accepted")
	}
}
func TestNativeReparseAndHardlinkRefused(t *testing.T) {
	n, f := fixture(t)
	target := t.TempDir()
	link := filepath.Join(f.Location, "link")
	if e := os.Symlink(target, link); e == nil {
		a, _ := n.Inspect(f)
		if a.Eligibility == cleanup.Eligible {
			t.Fatal("symlink followed")
		}
		os.Remove(link)
	} else {
		if output, e := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); e != nil {
			t.Fatalf("Cannot create synthetic junction: %s %v", output, e)
		}
		a, _ := n.Inspect(f)
		if a.Eligibility == cleanup.Eligible {
			t.Fatal("junction accepted")
		}
		if e := os.Remove(link); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Link(filepath.Join(f.Location, "data.txt"), filepath.Join(f.Location, "hardlink")); e != nil {
		t.Fatal(e)
	}
	a, _ := n.Inspect(f)
	if a.Eligibility == cleanup.Eligible {
		t.Fatal("hardlink accepted")
	}
}
func TestNativeRegistryRunOnceExpandBytes(t *testing.T) {
	if os.Getenv("ACD_ISOLATED_NATIVE") != "1" {
		t.Skip("Registry mutation runs only in disposable Sandbox")
	}
	n, f := fixture(t)
	id, e := cleanup.ID()
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("ACD_SYNTHETIC_BASE", filepath.Dir(f.Target))
	ref := &core.RunValue{Hive: "HKCU", View: "32-bit", Key: `Software\Microsoft\Windows\CurrentVersion\RunOnce`, Name: "ACD-Synthetic-" + id}
	key, _, e := registry.CreateKey(registry.CURRENT_USER, ref.Key, registry.ALL_ACCESS|registry.WOW64_32KEY)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Close()
	defer key.DeleteValue(ref.Name)
	cmd := `"%ACD_SYNTHETIC_BASE%\absent.exe"`
	if e = key.SetExpandStringValue(ref.Name, cmd); e != nil {
		t.Fatal(e)
	}
	typ, raw, e := readRaw(key, ref.Name)
	if e != nil {
		t.Fatal(e)
	}
	f.Kind = "Startup"
	f.Run = ref
	item := nativeItem(t, n, f)
	if e = n.Quarantine(item); e != nil {
		t.Fatal(e)
	}
	if e = n.Restore(item); e != nil {
		t.Fatal(e)
	}
	newType, newRaw, e := readRaw(key, ref.Name)
	if e != nil || typ != newType || !sameRaw(raw, newRaw) {
		t.Fatal("raw EXPAND_SZ bytes changed")
	}
	key.SetExpandStringValue(ref.Name, cmd+" --changed")
	if n.Quarantine(item) == nil {
		t.Fatal("changed value removed")
	}
}
func TestNativeRegistryArgumentsRemainReportOnly(t *testing.T) {
	if _, e := runCommand(registry.SZ, []byte{1}); e == nil {
		t.Fatal("malformed string")
	}
	for _, kind := range []uint32{registry.BINARY, registry.DWORD, registry.MULTI_SZ} {
		if _, e := runCommand(kind, []byte{0, 0}); e == nil {
			t.Fatal("unsupported registry type")
		}
	}
}
func TestNativePermissionFailureNoMutation(t *testing.T) {
	if os.Getenv("ACD_ISOLATED_NATIVE") != "1" {
		t.Skip("ACL fixture runs only in disposable Sandbox")
	}
	n, f := fixture(t)
	item := nativeItem(t, n, f)
	p := filepath.Join(f.Location, "data.txt")
	original, e := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	old, _, e := original.DACL()
	if e != nil {
		t.Fatal(e)
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sd, e := windows.SecurityDescriptorFromString("D:(D;;0x00010001;;;WD)(A;;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		t.Fatal(e)
	}
	deny, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, deny, nil); e != nil {
		t.Fatal(e)
	}
	defer windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, old, nil)
	if n.Quarantine(item) == nil {
		t.Fatal("permission-denied source moved")
	}
	if _, e = os.Stat(f.Location); e != nil {
		t.Fatal("source disappeared")
	}
	if _, e = os.Stat(item.Payload); !os.IsNotExist(e) {
		t.Fatal("payload created on permission failure")
	}
}
func TestNativeInUseAndIdentityChange(t *testing.T) {
	n, f := fixture(t)
	item := nativeItem(t, n, f)
	path := filepath.Join(f.Location, "data.txt")
	h, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	if n.Quarantine(item) == nil {
		t.Fatal("in-use source moved")
	}
	h.Close()
	os.Remove(path)
	os.WriteFile(path, []byte("replacement"), 0600)
	if n.Quarantine(item) == nil {
		t.Fatal("replacement moved")
	}
}
func TestNativeReportOnlyTypes(t *testing.T) {
	n, f := fixture(t)
	for _, kind := range []string{"Registry", "Service", "Tasks"} {
		f.Kind = kind
		a, _ := n.Inspect(f)
		if a.Eligibility != cleanup.ReportOnly {
			t.Fatal(kind)
		}
	}
}
func TestNativeRegistryTransactionRoundTrip(t *testing.T) {
	if os.Getenv("ACD_ISOLATED_NATIVE") != "1" {
		t.Skip("Registry mutation runs only in disposable Sandbox")
	}
	n, f := fixture(t)
	id, e := cleanup.ID()
	if e != nil {
		t.Fatal(e)
	}
	ref := &core.RunValue{Hive: "HKCU", View: "64-bit", Key: `Software\Microsoft\Windows\CurrentVersion\Run`, Name: "ACD-Synthetic-" + id}
	key, _, e := registry.CreateKey(registry.CURRENT_USER, ref.Key, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Close()
	defer key.DeleteValue(ref.Name)
	cmd := `"` + f.Target + `"`
	if e = key.SetStringValue(ref.Name, cmd); e != nil {
		t.Fatal(e)
	}
	f.Kind = "Startup"
	f.Run = ref
	item := nativeItem(t, n, f)
	if e = n.Quarantine(item); e != nil {
		t.Fatal(e)
	}
	if _, _, e = key.GetStringValue(ref.Name); e != registry.ErrNotExist {
		t.Fatal("value remains")
	}
	if e = n.Restore(item); e != nil {
		t.Fatal(e)
	}
	s, typ, e := key.GetStringValue(ref.Name)
	if e != nil || s != cmd || typ != registry.SZ {
		t.Fatal("not restored exactly")
	}
	if e = n.Quarantine(item); e != nil {
		t.Fatal(e)
	}
	key.SetStringValue(ref.Name, "replacement")
	if n.Restore(item) == nil {
		t.Fatal("registry overwrite")
	}
	var b runBackup
	if e = json.Unmarshal(item.Backup.Data, &b); e != nil || b.Type != registry.SZ {
		t.Fatal("backup")
	}
}
