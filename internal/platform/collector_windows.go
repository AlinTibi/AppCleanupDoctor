//go:build windows

package platform

import (
	"context"
	"fmt"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const limit = 5000

type WindowsCollector struct{ Progress func(string) }
type reader struct {
	ctx               context.Context
	s                 core.Snapshot
	softwareRemaining int
}
type hive struct {
	key  registry.Key
	name string
}

var hives = []hive{{registry.CURRENT_USER, "HKCU"}, {registry.LOCAL_MACHINE, "HKLM"}}
var views = []struct {
	flag uint32
	name string
}{{registry.WOW64_64KEY, "64-bit"}, {registry.WOW64_32KEY, "32-bit"}}

func (c WindowsCollector) Collect(ctx context.Context) (core.Snapshot, error) {
	r := reader{ctx: ctx, softwareRemaining: limit, s: core.Snapshot{Apps: []core.App{}, Warnings: []string{}}}
	if root, err := windows.GetSystemWindowsDirectory(); err == nil {
		r.s.ProtectedRoots = append(r.s.ProtectedRoots, root)
	} else {
		return r.s, fmt.Errorf("Cannot determine protected Windows directory; scan refused")
	}
	for _, stage := range []struct {
		name string
		run  func()
	}{{"Reading application inventory", r.inventory}, {"Reading explicit registry references", r.software}, {"Reading startup entries", r.startup}, {"Reading top-level app folders", r.folders}, {"Reading service configurations", r.services}, {"Reading tasks and shortcuts", r.automation}} {
		if ctx.Err() != nil {
			return r.s, ctx.Err()
		}
		if c.Progress != nil {
			c.Progress(stage.name)
		}
		stage.run()
	}
	if ctx.Err() != nil {
		return r.s, ctx.Err()
	}
	return r.s, nil
}
func (r *reader) warn(area string) {
	w := area + ": not fully readable; missing data was not treated as absence."
	for _, existing := range r.s.Warnings {
		if existing == w {
			return
		}
	}
	r.s.Warnings = append(r.s.Warnings, w)
}
func (r *reader) names(k registry.Key) []string {
	n, e := k.ReadSubKeyNames(limit)
	if e != nil && e != io.EOF {
		r.warn("Registry enumeration")
	}
	if len(n) >= limit {
		r.s.Truncated = true
	}
	return n
}
func str(k registry.Key, name string) string {
	s, _, e := k.GetStringValue(name)
	if e != nil {
		return ""
	}
	if x, e := registry.ExpandString(s); e == nil {
		s = x
	}
	return s
}
func (r *reader) inventory() {
	const base = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	for _, h := range hives {
		for _, v := range views {
			k, e := registry.OpenKey(h.key, base, registry.READ|v.flag)
			if e != nil {
				if e != registry.ErrNotExist {
					r.warn("Uninstall inventory " + h.name + " " + v.name)
				}
				continue
			}
			for _, name := range r.names(k) {
				if r.ctx.Err() != nil {
					break
				}
				item, e := registry.OpenKey(k, name, registry.READ|v.flag)
				if e != nil {
					r.warn("Uninstall item")
					continue
				}
				display := str(item, "DisplayName")
				if display != "" {
					command := str(item, "UninstallString")
					msi, _, _ := item.GetIntegerValue("WindowsInstaller")
					r.s.Apps = append(r.s.Apps, core.App{ID: name, Name: display, Publisher: str(item, "Publisher"), Version: str(item, "DisplayVersion"), InstallPath: str(item, "InstallLocation"), UninstallCommand: command, UninstallTarget: commandTarget(command), Source: h.name + `\` + base + `\` + name + " [" + v.name + "]", MSI: msi == 1})
				}
				item.Close()
			}
			k.Close()
		}
	}
}
func (r *reader) software() {
	// Only two bounded levels and explicit executable-path values. No generic
	// registry string search, binary value reads or recursive contents scanning.
	for _, h := range hives {
		for _, v := range views {
			k, e := registry.OpenKey(h.key, `Software`, registry.READ|v.flag)
			if e != nil {
				r.warn("Software keys " + h.name)
				continue
			}
			for _, vendor := range r.names(k) {
				if r.softwareRemaining <= 0 {
					r.s.Truncated = true
					break
				}
				r.softwareRemaining--
				if r.ctx.Err() != nil {
					break
				}
				if core.SharedIdentity(vendor) || registryInfrastructure(vendor) {
					continue
				}
				vk, e := registry.OpenKey(k, vendor, registry.READ|v.flag)
				if e != nil {
					r.warn("Vendor key")
					continue
				}
				base := h.name + `\Software\` + vendor
				r.keyReferences(vk, vendor, vendor, base+" ["+v.name+"]")
				for _, name := range r.names(vk) {
					if r.softwareRemaining <= 0 {
						r.s.Truncated = true
						break
					}
					r.softwareRemaining--
					if r.ctx.Err() != nil {
						break
					}
					ak, e := registry.OpenKey(vk, name, registry.READ|v.flag)
					if e != nil {
						r.warn("Application key")
						continue
					}
					r.keyReferences(ak, name, vendor, base+`\`+name+" ["+v.name+"]")
					ak.Close()
				}
				vk.Close()
			}
			k.Close()
		}
	}
}
func (r *reader) keyReferences(k registry.Key, name, vendor, location string) {
	for _, value := range []string{"Executable", "ApplicationPath", "ExePath"} {
		target := str(k, value)
		if strings.HasSuffix(strings.ToLower(target), ".exe") {
			r.s.References = append(r.s.References, core.Reference{Kind: "Registry", Name: name, Vendor: vendor, Location: location + " :: " + value, Target: target})
		}
	}
}

// Unquoted paths with spaces and relative commands cannot be resolved safely.
// Argument contents are never searched for additional targets or executed.
func commandTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if x, e := registry.ExpandString(s); e == nil {
		s = x
	}
	args, e := windows.DecomposeCommandLine(s)
	if e != nil || len(args) == 0 {
		return ""
	}
	first := args[0]
	if !strings.HasPrefix(s, `"`) && !strings.HasSuffix(strings.ToLower(first), ".exe") {
		return ""
	}
	if !strings.HasSuffix(strings.ToLower(first), ".exe") {
		return ""
	}
	p, e := core.Normalize(first)
	if e != nil {
		return ""
	}
	return p
}
func (r *reader) startup() {
	for _, h := range hives {
		for _, v := range views {
			for _, leaf := range []string{"Run", "RunOnce"} {
				base := `Software\Microsoft\Windows\CurrentVersion\` + leaf
				k, e := registry.OpenKey(h.key, base, registry.READ|v.flag)
				if e != nil {
					if e != registry.ErrNotExist {
						r.warn("Startup registry")
					}
					continue
				}
				names, e := k.ReadValueNames(limit)
				if e != nil && e != io.EOF {
					r.warn("Startup values")
				}
				if len(names) >= limit {
					r.s.Truncated = true
				}
				for _, name := range names {
					target := commandTarget(str(k, name))
					if target != "" {
						r.s.References = append(r.s.References, core.Reference{Kind: "Startup", Name: name, Location: h.name + `\` + base + " :: " + name + " [" + v.name + "]", Target: target})
					}
				}
				k.Close()
			}
		}
	}
}
func (r *reader) folders() {
	for _, env := range []string{"LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "ProgramFiles", "ProgramFiles(x86)"} {
		root := os.Getenv(env)
		if root == "" {
			continue
		}
		if normalized, e := core.Normalize(root); e != nil || !localFixed(normalized) {
			r.warn("Non-local folder root " + env)
			continue
		}
		entries, e := os.ReadDir(root)
		if e != nil {
			r.warn("Folder root " + env)
			continue
		}
		if len(entries) > limit {
			entries = entries[:limit]
			r.s.Truncated = true
		}
		for _, entry := range entries {
			if r.ctx.Err() != nil {
				return
			}
			path := filepath.Join(root, entry.Name())
			info, e := os.Lstat(path)
			if e != nil {
				r.warn("Folder entry")
				continue
			}
			if !info.IsDir() {
				continue
			}
			r.s.Folders = append(r.s.Folders, core.Folder{Name: entry.Name(), Path: path, Reparse: isReparse(path, info)})
		}
	}
}
func isReparse(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return true
	}
	attrs, e := windows.GetFileAttributes(p)
	return e != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func localFixed(path string) bool {
	n, e := core.Normalize(path)
	if e != nil {
		return false
	}
	p, e := windows.UTF16PtrFromString(n[:3])
	return e == nil && windows.GetDriveType(p) == windows.DRIVE_FIXED
}
func registryInfrastructure(name string) bool {
	switch strings.ToLower(name) {
	case "classes", "policies", "clients", "registeredapplications", "wow6432node":
		return true
	}
	return false
}
func (r *reader) services() {
	handle, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if e != nil {
		r.warn("Services")
		return
	}
	m := &mgr.Mgr{Handle: handle}
	defer m.Disconnect()
	names, e := m.ListServices()
	if e != nil {
		r.warn("Service list")
		return
	}
	if len(names) > limit {
		names = names[:limit]
		r.s.Truncated = true
	}
	for _, name := range names {
		if r.ctx.Err() != nil {
			return
		}
		namePtr, e := windows.UTF16PtrFromString(name)
		if e != nil {
			r.warn("Service name")
			continue
		}
		serviceHandle, e := windows.OpenService(m.Handle, namePtr, windows.SERVICE_QUERY_CONFIG)
		if e != nil {
			r.warn("Service configuration")
			continue
		}
		s := &mgr.Service{Name: name, Handle: serviceHandle}
		c, e := s.Config()
		s.Close()
		if e != nil {
			r.warn("Service configuration")
			continue
		}
		if c.ServiceType&(windows.SERVICE_KERNEL_DRIVER|windows.SERVICE_FILE_SYSTEM_DRIVER) != 0 {
			continue
		}
		target := commandTarget(c.BinaryPathName)
		if target != "" {
			r.s.References = append(r.s.References, core.Reference{Kind: "Service", Name: c.DisplayName, Location: "Service: " + name, Target: target})
		}
	}
}
func structuredTarget(path, working string) string {
	if x, e := registry.ExpandString(path); e == nil {
		path = x
	}
	path = strings.Trim(strings.TrimSpace(path), `"`)
	if !strings.HasSuffix(strings.ToLower(path), ".exe") {
		return ""
	}
	if _, e := core.Normalize(path); e != nil {
		if filepath.IsAbs(path) || working == "" {
			return ""
		}
		// A bare executable name can use Windows executable-search semantics.
		// WorkingDirectory is not proof of its resolved location. Only explicit
		// relative paths can be anchored there; never guess PATH/search results.
		if !strings.ContainsAny(path, `\/`) {
			return ""
		}
		path = filepath.Join(working, path)
	}
	if p, e := core.Normalize(path); e == nil {
		return p
	}
	return ""
}
func (r *reader) limited(label string, n int) int {
	if n > limit {
		r.s.Truncated = true
		r.warn(fmt.Sprintf("%s limit reached", label))
		return limit
	}
	return n
}
