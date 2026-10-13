//go:build windows

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AlinTibi/AppCleanupDoctor/internal/cleanup"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"strings"
	"syscall"
	"unsafe"
)

type runBackup struct {
	Ref   core.RunValue
	Type  uint32
	Bytes []byte
}

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var ktm = windows.NewLazySystemDLL("ktmw32.dll")

func runKey(ref *core.RunValue) (registry.Key, uint32, error) {
	if ref == nil || (ref.Key != `Software\Microsoft\Windows\CurrentVersion\Run` && ref.Key != `Software\Microsoft\Windows\CurrentVersion\RunOnce`) || ref.Name == "" {
		return 0, 0, errors.New("Only structured orphan Run/RunOnce values are supported")
	}
	var h registry.Key
	switch ref.Hive {
	case "HKCU":
		h = registry.CURRENT_USER
	case "HKLM":
		h = registry.LOCAL_MACHINE
	default:
		return 0, 0, errors.New("Invalid hive")
	}
	var view uint32
	switch ref.View {
	case "64-bit":
		view = registry.WOW64_64KEY
	case "32-bit":
		view = registry.WOW64_32KEY
	default:
		return 0, 0, errors.New("Invalid registry view")
	}
	return h, view, nil
}
func readRaw(key registry.Key, name string) (uint32, []byte, error) {
	size, typ, err := key.GetValue(name, nil)
	if err != nil {
		return 0, nil, err
	}
	if size > 32768 {
		return 0, nil, errors.New("Registry command is too large")
	}
	b := make([]byte, size)
	_, typ, err = key.GetValue(name, b)
	return typ, b, err
}
func runCommand(typ uint32, b []byte) (string, error) {
	if (typ != registry.SZ && typ != registry.EXPAND_SZ) || len(b)%2 != 0 || len(b) < 2 {
		return "", errors.New("Unsupported registry data type")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	if u[len(u)-1] != 0 {
		return "", errors.New("Unterminated registry command")
	}
	for _, c := range u[:len(u)-1] {
		if c == 0 {
			return "", errors.New("Ambiguous embedded NUL")
		}
	}
	s := windows.UTF16ToString(u)
	if typ == registry.EXPAND_SZ {
		var e error
		s, e = registry.ExpandString(s)
		if e != nil {
			return "", e
		}
	}
	args, e := windows.DecomposeCommandLine(s)
	if e != nil || len(args) != 1 {
		return "", errors.New("Commands with arguments remain report-only to avoid backing up secrets or unsupported semantics")
	}
	target := commandTarget(s)
	if target == "" {
		return "", errors.New("Ambiguous executable command")
	}
	return target, nil
}
func inspectRun(f core.Finding) (cleanup.Assessment, cleanup.Backup) {
	refuse := func(e error) (cleanup.Assessment, cleanup.Backup) {
		return cleanup.Assessment{Eligibility: cleanup.ReportOnly, Reason: e.Error()}, cleanup.Backup{}
	}
	h, v, e := runKey(f.Run)
	if e != nil {
		return refuse(e)
	}
	key, e := registry.OpenKey(h, f.Run.Key, registry.QUERY_VALUE|v)
	if e != nil {
		return refuse(e)
	}
	defer key.Close()
	typ, b, e := readRaw(key, f.Run.Name)
	if e != nil {
		return refuse(e)
	}
	target, e := runCommand(typ, b)
	if e != nil {
		return refuse(e)
	}
	if target != f.Target {
		return refuse(errors.New("Run command changed"))
	}
	data, _ := json.Marshal(runBackup{*f.Run, typ, b})
	return cleanup.Assessment{Eligibility: cleanup.Eligible, Reason: "Exact orphan Run/RunOnce value; native transaction required", Action: "Back up exact registry type/bytes, then remove only this value"}, cleanup.Backup{Data: data, Identity: fmt.Sprintf("%x", data)}
}
func nativeCall(proc *windows.LazyProc, args ...uintptr) error {
	r, _, e := proc.Call(args...)
	if r == 0 {
		return nil
	}
	if r == uintptr(^uint32(0)) || r == ^uintptr(0) {
		return e
	}
	return syscall.Errno(r)
}
func mutateRun(item cleanup.Item, restore bool) error {
	var b runBackup
	if e := json.Unmarshal(item.Backup.Data, &b); e != nil {
		return e
	}
	h, view, e := runKey(&b.Ref)
	if e != nil {
		return e
	}
	if item.Finding.Run == nil || b.Ref != *item.Finding.Run {
		return errors.New("Registry backup provenance mismatch")
	}
	target, e := runCommand(b.Type, b.Bytes)
	if e != nil || target != item.Finding.Target {
		return errors.New("Invalid registry backup command")
	}
	// KTM registry transactions provide conflict detection at commit, unlike read-then-delete.
	transaction, _, err := ktm.NewProc("CreateTransaction").Call(0, 0, 0, 0, 0, 0, 0)
	if transaction == ^uintptr(0) || transaction == 0 {
		return fmt.Errorf("Registry transaction unavailable; no changes: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(transaction))
	defer ktm.NewProc("RollbackTransaction").Call(transaction)
	path, _ := windows.UTF16PtrFromString(b.Ref.Key)
	var key registry.Key
	if e = nativeCall(advapi.NewProc("RegOpenKeyTransactedW"), uintptr(h), uintptr(unsafe.Pointer(path)), 0, uintptr(registry.QUERY_VALUE|registry.SET_VALUE|view), uintptr(unsafe.Pointer(&key)), transaction, 0); e != nil {
		return fmt.Errorf("Registry permission/transaction failure; no changes: %w", e)
	}
	defer key.Close()
	typ, data, e := readRaw(key, b.Ref.Name)
	name, _ := windows.UTF16PtrFromString(b.Ref.Name)
	if restore {
		if e == nil {
			if typ == b.Type && sameRaw(data, b.Bytes) {
				return nil
			}
			return errors.New("Registry restore conflict: current value differs; never overwrite")
		}
		if e != registry.ErrNotExist {
			return e
		}
		if e = nativeCall(advapi.NewProc("RegSetValueExW"), uintptr(key), uintptr(unsafe.Pointer(name)), 0, uintptr(b.Type), uintptr(unsafe.Pointer(&b.Bytes[0])), uintptr(len(b.Bytes))); e != nil {
			return e
		}
	} else {
		if e != nil {
			return e
		}
		if typ != b.Type || !sameRaw(data, b.Bytes) {
			return errors.New("Run value changed; cleanup refused")
		}
		if core.Protected(target) || (DiskProbe{}).Check(target) != core.Missing {
			return errors.New("Executable no longer positively absent")
		}
		if e = key.DeleteValue(b.Ref.Name); e != nil {
			return e
		}
	}
	success, _, err := ktm.NewProc("CommitTransaction").Call(transaction)
	if success == 0 {
		return cleanup.UncertainMutation{Err: fmt.Errorf("Registry commit failed/conflicted; inspect state before restoring: %w", err)}
	}
	return nil
}
func recoverRun(item cleanup.Item) (string, error) {
	var b runBackup
	if e := json.Unmarshal(item.Backup.Data, &b); e != nil {
		return "RecoveryRequired", e
	}
	h, v, e := runKey(&b.Ref)
	if e != nil {
		return "RecoveryRequired", e
	}
	k, e := registry.OpenKey(h, b.Ref.Key, registry.QUERY_VALUE|v)
	if e != nil {
		return "RecoveryRequired", e
	}
	defer k.Close()
	typ, data, e := readRaw(k, b.Ref.Name)
	if e == registry.ErrNotExist {
		return "Quarantined", nil
	}
	if e != nil {
		return "RecoveryRequired", e
	}
	if typ == b.Type && sameRaw(data, b.Bytes) {
		if strings.EqualFold(item.State, "RestorePending") {
			return "Restored", nil
		}
		return "Failed", nil
	}
	return "RecoveryRequired", errors.New("Registry value changed during interrupted operation")
}
