package core

import (
	"strings"
	"testing"
)

type fakeProbe map[string]State

func (p fakeProbe) Check(s string) State {
	n, e := Normalize(s)
	if e != nil {
		return Unknown
	}
	return p[n]
}
func probe(paths map[string]State) fakeProbe {
	p := fakeProbe{}
	for path, s := range paths {
		n, _ := Normalize(path)
		p[n] = s
	}
	return p
}
func TestInventoryViewsDeduplicated(t *testing.T) {
	a := App{ID: "Acme", Name: "Acme", InstallPath: `C:\Apps\Acme`, Source: "HKLM 64"}
	b := a
	b.Source = "HKLM 32"
	r := Detect(Snapshot{Apps: []App{a, b, {ID: "Other", Name: "Other", Source: "HKCU 32"}}}, probe(nil))
	if len(r.Apps) != 2 {
		t.Fatalf("inventory: %d", len(r.Apps))
	}
}
func TestBrokenInventoryRequiresBothMissing(t *testing.T) {
	a := App{ID: "Acme", Name: "Acme", InstallPath: `C:\Apps\Acme`, UninstallTarget: `C:\Apps\Acme\uninstall.exe`, Source: `HKCU\Uninstall\Acme`}
	for _, tc := range []struct {
		name        string
		folder, exe State
		want        int
	}{{"both missing", Missing, Missing, 1}, {"active", Exists, Missing, 0}, {"denied", Unknown, Missing, 0}, {"uninstaller exists", Missing, Exists, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			r := Detect(Snapshot{Apps: []App{a}}, probe(map[string]State{a.InstallPath: tc.folder, a.UninstallTarget: tc.exe}))
			if len(r.Findings) != tc.want {
				t.Fatalf("findings=%d", len(r.Findings))
			}
		})
	}
}
func TestMSIAndSharedRuntimeWithheld(t *testing.T) {
	for _, a := range []App{{Name: "Microsoft Edge WebView2", Publisher: "Microsoft", InstallPath: `C:\Apps\Runtime`, UninstallTarget: `C:\Apps\Runtime\u.exe`}, {Name: "MSI App", MSI: true, InstallPath: `C:\Apps\Acme`, UninstallTarget: `C:\Apps\Acme\u.exe`}} {
		r := Detect(Snapshot{Apps: []App{a}}, probe(map[string]State{a.InstallPath: Missing, a.UninstallTarget: Missing}))
		if len(r.Findings) != 0 {
			t.Fatal("runtime or MSI flagged")
		}
	}
}
func TestReferences(t *testing.T) {
	for _, kind := range []string{"Startup", "Tasks", "Service", "Registry"} {
		for _, state := range []State{Exists, Missing, Unknown} {
			t.Run(kind+string(rune('0'+state)), func(t *testing.T) {
				ref := Reference{Kind: kind, Name: "Acme", Location: kind + " item", Target: `C:\Apps\Acme\app.exe`}
				r := Detect(Snapshot{References: []Reference{ref}}, probe(map[string]State{ref.Target: state}))
				want := 0
				if state == Missing {
					want = 1
				}
				if len(r.Findings) != want {
					t.Fatalf("findings=%d", len(r.Findings))
				}
				if want == 1 && (len(r.Findings[0].Evidence) < 2 || r.Findings[0].Risk == "") {
					t.Fatal("missing evidence/risk")
				}
				if kind == "Service" && want == 1 && !strings.Contains(r.Findings[0].Risk, "Report only") {
					t.Fatal("service removal implied")
				}
			})
		}
	}
}
func TestActiveInstallReferencesWithheld(t *testing.T) {
	root := `C:\Apps\Acme`
	ref := Reference{Kind: "Tasks", Name: "Acme", Location: "Task", Target: root + `\helper.exe`}
	r := Detect(Snapshot{Apps: []App{{Name: "Acme", InstallPath: root}}, References: []Reference{ref}}, probe(map[string]State{root: Exists, ref.Target: Missing}))
	if len(r.Findings) != 0 {
		t.Fatal("active application flagged")
	}
}
func TestStaleAppDataNeedsCorroboration(t *testing.T) {
	folder := Folder{Name: "Acme", Path: `C:\Users\Test\AppData\Roaming\Acme`}
	ref := Reference{Kind: "Registry", Name: "Acme", Location: `HKCU\Software\Acme :: Executable`, Target: `C:\Apps\Acme\app.exe`}
	p := probe(map[string]State{folder.Path: Exists, ref.Target: Missing})
	r := Detect(Snapshot{Folders: []Folder{folder}, References: []Reference{ref}}, p)
	if len(r.Findings) != 2 {
		t.Fatalf("findings %d", len(r.Findings))
	}
	r = Detect(Snapshot{Folders: []Folder{folder}}, p)
	if len(r.Findings) != 0 {
		t.Fatal("name-only flagged")
	}
}
func TestActiveAndSharedVendorFoldersWithheld(t *testing.T) {
	folder := Folder{Name: "Acme", Path: `C:\Users\Test\AppData\Roaming\Acme`}
	ref := Reference{Kind: "Registry", Name: "Acme", Location: "Key", Target: `C:\Old\app.exe`}
	for _, apps := range [][]App{{{Name: "Acme", InstallPath: `C:\Apps\New`}}, {{Name: "Tool A", Publisher: "Acme"}, {Name: "Tool B", Publisher: "Acme"}}} {
		r := Detect(Snapshot{Apps: apps, Folders: []Folder{folder}, References: []Reference{ref}}, probe(map[string]State{folder.Path: Exists, ref.Target: Missing}))
		for _, f := range r.Findings {
			if f.Kind == "Files" {
				t.Fatal("active/shared vendor folder flagged")
			}
		}
	}
}
func TestAmbiguousNamesNotMatched(t *testing.T) {
	folder := Folder{Name: "Acme Pro", Path: `C:\Data\Acme Pro`}
	ref := Reference{Kind: "Registry", Name: "Acme", Location: "Key", Target: `C:\Gone\app.exe`}
	r := Detect(Snapshot{Folders: []Folder{folder}, References: []Reference{ref}}, probe(map[string]State{folder.Path: Exists, ref.Target: Missing}))
	if len(r.Findings) != 1 {
		t.Fatal("substring match used")
	}
}
func TestReparseFoldersWithheld(t *testing.T) {
	folder := Folder{Name: "Acme", Path: `C:\Data\Acme`, Reparse: true}
	ref := Reference{Kind: "Registry", Name: "Acme", Location: "Key", Target: `C:\Gone\app.exe`}
	r := Detect(Snapshot{Folders: []Folder{folder}, References: []Reference{ref}}, probe(map[string]State{folder.Path: Exists, ref.Target: Missing}))
	if len(r.Findings) != 1 {
		t.Fatal("reparse folder flagged")
	}
}
func TestDuplicateFindings(t *testing.T) {
	a := Reference{Kind: "Startup", Name: "Acme", Location: "Run Acme", Target: `C:\Gone\app.exe`}
	b := a
	b.Location = "run acme"
	r := Detect(Snapshot{References: []Reference{a, b}}, probe(map[string]State{a.Target: Missing}))
	if len(r.Findings) != 1 {
		t.Fatal("duplicate")
	}
}

func TestReflectedRegistryViewsDeduplicated(t *testing.T) {
	a := Reference{Kind: "Registry", Name: "Acme", Location: `HKCU\Software\Acme [32-bit] :: ExePath`, Target: `C:\Gone\app.exe`}
	b := a
	b.Location = `HKCU\Software\Acme [64-bit] :: ExePath`
	r := Detect(Snapshot{References: []Reference{a, b}}, probe(map[string]State{a.Target: Missing}))
	if len(r.Findings) != 1 {
		t.Fatal("reflected view duplicate")
	}
	b.Target = `C:\Other\app.exe`
	r = Detect(Snapshot{References: []Reference{a, b}}, probe(map[string]State{a.Target: Missing, b.Target: Missing}))
	if len(r.Findings) != 2 {
		t.Fatal("distinct targets collapsed")
	}
}
func TestCustomWindowsRootProtected(t *testing.T) {
	target := `D:\OS\Acme\app.exe`
	r := Detect(Snapshot{ProtectedRoots: []string{`D:\OS`}, References: []Reference{{Kind: "Tasks", Name: "Acme", Location: "Task", Target: target}}}, probe(map[string]State{target: Missing}))
	if len(r.Findings) != 0 {
		t.Fatal("custom Windows root not protected")
	}
}

func TestSystemVolumeInformationWithheld(t *testing.T) {
	for _, path := range []string{`C:\System Volume Information\app.exe`, `D:\SYSTEM VOLUME INFORMATION\app.exe`} {
		if !Protected(path) {
			t.Fatal("Windows volume metadata directory is not protected")
		}
		r := Detect(Snapshot{References: []Reference{{Kind: "Registry", Name: "Acme", Location: "Synthetic reference", Target: path}}}, probe(map[string]State{path: Missing}))
		if len(r.Findings) != 0 {
			t.Fatal("protected volume metadata was reported as an application leftover")
		}
	}
}

type countingProbe struct{ calls int }

func (p *countingProbe) Check(string) State { p.calls++; return Missing }
func TestProbeCachingIsPerScan(t *testing.T) {
	p := &countingProbe{}
	refs := []Reference{}
	for i := 0; i < 100; i++ {
		refs = append(refs, Reference{Kind: "Tasks", Name: "Acme", Location: "Task", Target: `C:\Gone\app.exe`})
	}
	Detect(Snapshot{References: refs}, p)
	if p.calls != 1 {
		t.Fatalf("repeated disk reads %d", p.calls)
	}
	Detect(Snapshot{References: refs}, p)
	if p.calls != 2 {
		t.Fatal("cache leaked between scans")
	}
}
func TestPartialReadFailurePreserved(t *testing.T) {
	s := Snapshot{Warnings: []string{"Registry access denied"}, Truncated: true}
	r := Detect(s, probe(nil))
	if !r.Truncated || len(r.Warnings) != 1 || !r.ScanOnly {
		t.Fatal("failure hidden")
	}
}
func TestUnicodeAndLongPaths(t *testing.T) {
	for _, path := range []string{`C:\Aplicații\Știință\app.exe`, `C:\Data\` + strings.Repeat("segment\\", 40) + "app.exe"} {
		r := Detect(Snapshot{References: []Reference{{Kind: "Tasks", Name: "Știință", Location: path, Target: path}}}, probe(map[string]State{path: Missing}))
		if len(r.Findings) != 1 {
			t.Fatal("valid path lost")
		}
	}
}
