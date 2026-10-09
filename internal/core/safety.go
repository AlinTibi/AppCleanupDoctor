package core

import (
	"errors"
	"strings"
)

// Normalize accepts local, absolute Windows paths only. It never resolves links.
func Normalize(raw string) (string, error) {
	p := strings.ReplaceAll(strings.TrimSpace(raw), "/", `\`)
	if strings.HasPrefix(p, `\\?\`) {
		p = strings.TrimPrefix(p, `\\?\`)
	}
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) {
		return "", errors.New("not an absolute local drive path")
	}
	if strings.ContainsAny(p[2:], `:*?"<>|%`) {
		return "", errors.New("unsafe or unresolved path")
	}
	for _, r := range p {
		if r < 32 {
			return "", errors.New("control character in path")
		}
	}
	parts := []string{}
	for _, s := range strings.Split(p[3:], `\`) {
		if s == "" || s == "." {
			continue
		}
		if s == ".." {
			if len(parts) == 0 {
				return "", errors.New("path escapes drive")
			}
			parts = parts[:len(parts)-1]
			continue
		}
		if strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
			return "", errors.New("ambiguous Windows component")
		}
		base := strings.ToUpper(strings.SplitN(s, ".", 2)[0])
		if strings.Contains(s, "~") || base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return "", errors.New("ambiguous or reserved Windows component")
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "", errors.New("drive root")
	}
	return strings.ToLower(p[:2] + `\` + strings.Join(parts, `\`)), nil
}
func Within(path, root string) bool { return path == root || strings.HasPrefix(path, root+`\`) }
func Protected(path string) bool {
	p, err := Normalize(path)
	if err != nil {
		return true
	}
	parts := strings.Split(p[3:], `\`)
	for _, s := range parts {
		switch s {
		case "windows", "system32", "syswow64", "winsxs", "windowsapps", "driverstore", "drivers", "system volume information", "common files", "dotnet", "microsoft.net", "webview2", "edgewebview", "microsoft", "packages", "package cache", "windows kits", "chocolatey", "scoop", "winget", "vcredist", "shared":
			return true
		}
		if strings.Contains(s, "visual c++") || strings.Contains(s, "redistributable") {
			return true
		}
	}
	return len(parts) == 1 && (parts[0] == "program files" || parts[0] == "program files (x86)" || parts[0] == "programdata" || parts[0] == "users")
}
func SharedIdentity(s string) bool {
	s = strings.ToLower(s)
	for _, term := range []string{"microsoft", "runtime", "redistributable", "framework", "driver", "webview2", ".net", "windows", "package manager"} {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}
