//go:build windows

package platform

import (
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// All automation calls here read existing task definitions or shortcut
// properties. There is no Run, RegisterTask, DeleteTask or shortcut Save call.
func dispatch(v *ole.VARIANT, e error) *ole.IDispatch {
	if e != nil || v == nil {
		return nil
	}
	d := v.ToIDispatch()
	if d != nil {
		d.AddRef()
	}
	v.Clear()
	return d
}
func prop(d *ole.IDispatch, n string) string {
	v, e := oleutil.GetProperty(d, n)
	if e != nil {
		return ""
	}
	defer v.Clear()
	return v.ToString()
}
func number(d *ole.IDispatch, n string) int {
	v, e := oleutil.GetProperty(d, n)
	if e != nil {
		return 0
	}
	defer v.Clear()
	return int(v.Val)
}
func create(prog string) *ole.IDispatch {
	u, e := oleutil.CreateObject(prog)
	if e != nil {
		return nil
	}
	defer u.Release()
	d, e := u.QueryInterface(ole.IID_IDispatch)
	if e != nil {
		return nil
	}
	return d
}
func (r *reader) automation() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); e != nil {
		r.warn("Task and shortcut COM initialization")
		return
	}
	defer ole.CoUninitialize()
	service := create("Schedule.Service")
	if service == nil {
		r.warn("Scheduled tasks")
	} else {
		defer service.Release()
		v, e := oleutil.CallMethod(service, "Connect")
		if e != nil {
			r.warn("Task service connection")
		} else {
			v.Clear()
			root := dispatch(oleutil.CallMethod(service, "GetFolder", `\`))
			if root != nil {
				remaining := limit
				r.taskFolder(root, 0, &remaining)
				root.Release()
			} else {
				r.warn("Task root")
			}
		}
	}
	shell := create("WScript.Shell")
	if shell == nil {
		r.warn("Startup shortcuts")
		return
	}
	defer shell.Release()
	for _, root := range []string{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`), filepath.Join(os.Getenv("PROGRAMDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)} {
		if n, e := core.Normalize(root); e != nil || !localFixed(n) {
			r.warn("Non-local startup folder")
			continue
		}
		entries, e := os.ReadDir(root)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			r.warn("Startup folder")
			continue
		}
		for i, entry := range entries {
			if i >= limit {
				r.s.Truncated = true
				break
			}
			if r.ctx.Err() != nil {
				return
			}
			path := filepath.Join(root, entry.Name())
			info, e := os.Lstat(path)
			if e != nil || isReparse(path, info) || !strings.EqualFold(filepath.Ext(path), ".lnk") {
				continue
			}
			shortcut := dispatch(oleutil.CallMethod(shell, "CreateShortcut", path))
			if shortcut == nil {
				r.warn("Startup shortcut read")
				continue
			}
			target := structuredTarget(prop(shortcut, "TargetPath"), prop(shortcut, "WorkingDirectory"))
			shortcut.Release()
			if target != "" {
				r.s.References = append(r.s.References, core.Reference{Kind: "Startup", Name: strings.TrimSuffix(entry.Name(), filepath.Ext(path)), Location: path, Target: target})
			}
		}
	}
}
func (r *reader) taskFolder(folder *ole.IDispatch, depth int, remaining *int) {
	if depth > 12 || *remaining <= 0 {
		r.s.Truncated = true
		return
	}
	if r.ctx.Err() != nil {
		return
	}
	tasks := dispatch(oleutil.CallMethod(folder, "GetTasks", 1))
	if tasks == nil {
		r.warn("Task folder enumeration")
	} else {
		for i := 1; i <= r.limited("Tasks", number(tasks, "Count")); i++ {
			if *remaining <= 0 || r.ctx.Err() != nil {
				r.s.Truncated = true
				break
			}
			*remaining--
			task := dispatch(oleutil.GetProperty(tasks, "Item", i))
			if task == nil {
				r.warn("Task definition")
				continue
			}
			name, path := prop(task, "Name"), prop(task, "Path")
			definition := dispatch(oleutil.GetProperty(task, "Definition"))
			if definition != nil {
				actions := dispatch(oleutil.GetProperty(definition, "Actions"))
				if actions != nil {
					for j := 1; j <= r.limited("Task actions", number(actions, "Count")); j++ {
						action := dispatch(oleutil.GetProperty(actions, "Item", j))
						if action != nil {
							if number(action, "Type") == 0 {
								target := structuredTarget(prop(action, "Path"), prop(action, "WorkingDirectory"))
								if target != "" {
									r.s.References = append(r.s.References, core.Reference{Kind: "Tasks", Name: name, Location: "Scheduled task: " + path + " / action " + stringID(j), Target: target})
								}
							}
							action.Release()
						}
					}
					actions.Release()
				}
				definition.Release()
			} else {
				r.warn("Task definition")
			}
			task.Release()
		}
		tasks.Release()
	}
	children := dispatch(oleutil.CallMethod(folder, "GetFolders", 0))
	if children == nil {
		r.warn("Task subfolders")
		return
	}
	defer children.Release()
	for i := 1; i <= r.limited("Task folders", number(children, "Count")); i++ {
		child := dispatch(oleutil.GetProperty(children, "Item", i))
		if child != nil {
			r.taskFolder(child, depth+1, remaining)
			child.Release()
		}
	}
}
