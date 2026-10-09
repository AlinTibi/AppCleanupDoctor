package core

import "testing"

func TestProtectedPaths(t *testing.T) {
	for _, p := range []string{`C:\Windows\a.exe`, `D:\Windows\System32\a.exe`, `C:\Other\SysWOW64\a.exe`, `C:\Other\WinSxS\a.exe`, `C:\Program Files\WindowsApps\a.exe`, `C:\Other\DriverStore\a.exe`, `C:\Program Files\Common Files\app.exe`, `C:\Program Files\dotnet\app.exe`, `C:\Users\Test\AppData\Local\Packages\a.exe`, `C:\ProgramData\chocolatey\a.exe`, `C:\Data\WebView2\a.exe`, `C:\`} {
		if !Protected(p) {
			t.Errorf("not protected %q", p)
		}
	}
}
func TestInvalidPaths(t *testing.T) {
	for _, p := range []string{`C:app.exe`, `\\server\app.exe`, `\\.\C:\app.exe`, `%APPDATA%\app.exe`, `C:\Data\a.exe:stream`, `C:\Data\*.exe`, `C:\..\a.exe`, `C:\Data.\a.exe`, `C:\Data\CON.exe`, `C:\PROGRA~1\a.exe`} {
		if _, e := Normalize(p); e == nil {
			t.Errorf("accepted %q", p)
		}
	}
}
func TestNormalizeBoundaries(t *testing.T) {
	p, e := Normalize(`\\?\C:\Data\A\..\App.exe`)
	if e != nil || p != `c:\data\app.exe` {
		t.Fatalf("%q %v", p, e)
	}
	if Within(`c:\data-other\app.exe`, `c:\data`) {
		t.Fatal("prefix boundary")
	}
	if Protected(`C:\WindowsTools\app.exe`) {
		t.Fatal("overbroad prefix")
	}
}
