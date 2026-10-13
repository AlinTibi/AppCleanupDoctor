//go:build windows

package platform

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AlinTibi/AppCleanupDoctor/internal/cleanup"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"
)

// NativeCleanup never accepts paths from the UI. It receives backend-owned findings.
type NativeCleanup struct{ Root string }

func (n NativeCleanup) ValidateStore() error {
	p, e := core.Normalize(n.Root)
	if e != nil {
		return e
	}
	current := p[:3]
	for _, part := range strings.Split(p[3:], `\`) {
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if isReparse(current, info) {
			return errors.New("Quarantine store traverses a reparse point")
		}
		if !info.IsDir() {
			return errors.New("Quarantine parent is not a directory")
		}
	}
	entries, e := os.ReadDir(p)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		path := filepath.Join(p, entry.Name())
		info, e := os.Lstat(path)
		if e != nil || isReparse(path, info) {
			return errors.New("Reparse point in quarantine store")
		}
		if entry.IsDir() {
			nested, e := os.ReadDir(path)
			if e != nil {
				return e
			}
			for _, child := range nested {
				ci, e := os.Lstat(filepath.Join(path, child.Name()))
				if e != nil || isReparse(filepath.Join(path, child.Name()), ci) {
					return errors.New("Reparse point in operation directory")
				}
			}
		}
	}
	return nil
}

type fileStamp struct {
	Relative   string
	Volume     uint32
	Index      uint64
	Size       uint64
	Modified   uint64
	Attributes uint32
}
type fileBackup struct{ Stamps []fileStamp }
type lockedTree struct {
	handles []windows.Handle
	source  windows.Handle
	stamps  []fileStamp
}

func (l *lockedTree) close() {
	for i := len(l.handles) - 1; i >= 0; i-- {
		windows.CloseHandle(l.handles[i])
	}
}
func openLocked(path string, rename bool) (windows.Handle, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	access := uint32(windows.FILE_READ_ATTRIBUTES)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if rename {
		access |= windows.DELETE
		share = windows.FILE_SHARE_READ
	}
	return windows.CreateFile(p, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}
func stamp(h windows.Handle, rel string) (fileStamp, error) {
	var s windows.ByHandleFileInformation
	e := windows.GetFileInformationByHandle(h, &s)
	if e != nil {
		return fileStamp{}, e
	}
	if s.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fileStamp{}, errors.New("Reparse points, junctions and symlinks are refused")
	}
	if s.NumberOfLinks > 1 && s.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fileStamp{}, errors.New("Hard-linked files are report-only")
	}
	return fileStamp{rel, s.VolumeSerialNumber, uint64(s.FileIndexHigh)<<32 | uint64(s.FileIndexLow), uint64(s.FileSizeHigh)<<32 | uint64(s.FileSizeLow), uint64(s.LastWriteTime.HighDateTime)<<32 | uint64(s.LastWriteTime.LowDateTime), s.FileAttributes}, nil
}
func lockAncestors(path string, l *lockedTree) error {
	n, e := core.Normalize(path)
	if e != nil {
		return e
	}
	current := n[:3]
	for _, part := range strings.Split(n[3:], `\`) {
		current = filepath.Join(current, part)
		h, e := openLocked(current, false)
		if e != nil {
			return e
		}
		l.handles = append(l.handles, h)
		if _, e = stamp(h, ""); e != nil {
			return e
		}
	}
	return nil
}
func lockTree(path string, rename bool) (*lockedTree, error) {
	l := &lockedTree{}
	fail := func(e error) (*lockedTree, error) { l.close(); return nil, e }
	if e := lockAncestors(filepath.Dir(path), l); e != nil {
		return fail(e)
	}
	var visit func(string) error
	visit = func(p string) error {
		if len(l.stamps) >= 10000 {
			return errors.New("Tree exceeds 10,000 entries; report-only")
		}
		ptr, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return e
		}
		access := uint32(windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_DATA)
		if p == path && rename {
			access |= windows.DELETE
		}
		h, e := windows.CreateFile(ptr, access, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return fmt.Errorf("Cannot lock item (permission or in-use conflict): %w", e)
		}
		l.handles = append(l.handles, h)
		if p == path {
			l.source = h
		}
		rel, e := filepath.Rel(path, p)
		if e != nil {
			return e
		}
		st, e := stamp(h, rel)
		if e != nil {
			return e
		}
		l.stamps = append(l.stamps, st)
		if st.Attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			var duplicate windows.Handle
			if e = windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); e != nil {
				return e
			}
			dir := os.NewFile(uintptr(duplicate), p)
			entries, e := dir.ReadDir(-1)
			dir.Close()
			if e != nil {
				return e
			}
			for _, entry := range entries {
				if e = visit(filepath.Join(p, entry.Name())); e != nil {
					return e
				}
			}
		}
		return nil
	}
	e := visit(path)
	if e != nil {
		return fail(e)
	}
	sort.Slice(l.stamps, func(i, j int) bool { return l.stamps[i].Relative < l.stamps[j].Relative })
	return l, nil
}
func fingerprint(stamps []fileStamp) string {
	b, _ := json.Marshal(stamps)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (n NativeCleanup) safeLocation(f core.Finding) error {
	p, e := core.Normalize(f.Location)
	if e != nil {
		return e
	}
	root, e := core.Normalize(n.Root)
	if e != nil {
		return e
	}
	if core.Within(p, root) || core.Within(root, p) {
		return errors.New("Quarantine store and its ancestors are protected")
	}
	if !localFixed(p) {
		return errors.New("Only local fixed volumes are supported")
	}
	if strings.ToLower(filepath.VolumeName(p)) != strings.ToLower(filepath.VolumeName(root)) {
		return errors.New("Cross-volume quarantine is refused; no copy/delete fallback")
	}
	if f.Kind == "Startup" && f.Run == nil {
		for _, env := range []string{"APPDATA", "PROGRAMDATA"} {
			base, err := core.Normalize(filepath.Join(os.Getenv(env), `Microsoft\Windows\Start Menu\Programs\Startup`))
			if err == nil && filepath.Dir(p) == base && strings.EqualFold(filepath.Ext(p), ".lnk") {
				return nil
			}
		}
		return errors.New("Only actual shortcuts directly in the Windows Startup folder are supported")
	}
	if f.Kind != "Files" || core.Protected(p) {
		return errors.New("Protected/system/shared/runtime location")
	}
	if system, e := windows.GetSystemWindowsDirectory(); e != nil {
		return errors.New("Cannot establish protected Windows directory")
	} else if r, e := core.Normalize(system); e != nil || core.Within(p, r) {
		return errors.New("Actual Windows directory is protected")
	}
	for _, env := range []string{"USERPROFILE", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "ProgramFiles", "ProgramFiles(x86)"} {
		r, err := core.Normalize(os.Getenv(env))
		if err == nil && p == r {
			return errors.New("Profile/application-data roots are protected")
		}
	}
	allowed := false
	for _, env := range []string{"LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "ProgramFiles", "ProgramFiles(x86)"} {
		r, err := core.Normalize(os.Getenv(env))
		if err == nil && filepath.Dir(p) == r {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("Only scanner-correlated top-level application folders are supported")
	}
	return nil
}
func (n NativeCleanup) Inspect(f core.Finding) (cleanup.Assessment, cleanup.Backup) {
	reject := func(reason string) (cleanup.Assessment, cleanup.Backup) {
		return cleanup.Assessment{Eligibility: cleanup.ReportOnly, Reason: reason}, cleanup.Backup{}
	}
	if f.Kind == "Service" {
		return reject("Services remain report-only; no service changes")
	}
	if f.Kind == "Tasks" {
		return reject("Task definition/state restoration is not implemented; report-only")
	}
	if f.Kind == "Registry" {
		return reject("Uninstall inventory and general registry keys remain report-only")
	}
	if f.Kind != "Files" && f.Kind != "Startup" {
		return reject("Unsupported finding type")
	}
	if (DiskProbe{}).Check(f.Target) != core.Missing || core.Protected(f.Target) {
		return reject("Referenced executable is not positively absent or is protected")
	}
	if f.Run != nil {
		return inspectRun(f)
	}
	if e := n.safeLocation(f); e != nil {
		return cleanup.Assessment{Eligibility: cleanup.Blocked, Reason: e.Error()}, cleanup.Backup{}
	}
	l, e := lockTree(f.Location, false)
	if e != nil {
		return reject(e.Error())
	}
	defer l.close()
	b, _ := json.Marshal(fileBackup{l.stamps})
	return cleanup.Assessment{Eligibility: cleanup.Eligible, Reason: "Explicit scanner evidence; same-volume reversible move; revalidated before execution", Action: "Move to quarantine without overwriting"}, cleanup.Backup{Data: b, Identity: fingerprint(l.stamps)}
}
func renameHandle(h windows.Handle, to string) error {
	type renameInfo struct {
		Replace uint32
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	chars, e := windows.UTF16FromString(to)
	if e != nil {
		return e
	}
	chars = chars[:len(chars)-1]
	off := int(unsafe.Offsetof(renameInfo{}.Name))
	buf := make([]byte, off+len(chars)*2)
	info := (*renameInfo)(unsafe.Pointer(&buf[0]))
	info.Length = uint32(len(chars) * 2)
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off])), len(chars))
	copy(dst, chars)
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &buf[0], uint32(len(buf)))
}
func (n NativeCleanup) payload(item cleanup.Item) error {
	root, e := core.Normalize(n.Root)
	if e != nil {
		return e
	}
	p, e := core.Normalize(item.Payload)
	if e != nil || !core.Within(p, root) {
		return errors.New("Invalid quarantine payload path")
	}
	rel, e := filepath.Rel(n.Root, item.Payload)
	if e != nil {
		return e
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	if len(parts) != 3 || parts[1] != "files" {
		return errors.New("Invalid payload layout")
	}
	return nil
}
func (n NativeCleanup) move(item cleanup.Item, restore bool) error {
	if e := n.payload(item); e != nil {
		return e
	}
	if e := n.safeLocation(item.Finding); e != nil {
		return e
	}
	from, to := item.Finding.Location, item.Payload
	if restore {
		from, to = to, from
	}
	l, e := lockTree(from, true)
	if e != nil {
		return e
	}
	defer l.close()
	if fingerprint(l.stamps) != item.Backup.Identity {
		return errors.New("Source identity/tree changed; no move performed")
	}
	parents := &lockedTree{}
	defer parents.close()
	if e = lockAncestors(filepath.Dir(to), parents); e != nil {
		return e
	}
	if _, e = os.Lstat(to); e == nil {
		return errors.New("Destination already exists; never overwrite")
	} else if !os.IsNotExist(e) {
		return e
	}
	if !restore && (DiskProbe{}).Check(item.Finding.Target) != core.Missing {
		return errors.New("Referenced executable changed; cleanup refused")
	}
	// Windows refuses a directory rename while descendant handles are open.
	// Release descendants only after the complete locked-tree identity check;
	// retain the root/ancestor handles so the actual source cannot be replaced.
	if len(l.stamps) > 0 && l.stamps[0].Attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		kept := []windows.Handle{}
		for _, h := range l.handles {
			if h == l.source {
				kept = append(kept, h)
			} else {
				windows.CloseHandle(h)
			}
		}
		l.handles = kept
	}
	// Handle-based rename and Replace=false keep both identity and no-overwrite guarantees.
	if e = renameHandle(l.source, to); e != nil {
		return e
	}
	l.close()
	l.handles = nil
	check, e := lockTree(to, false)
	if e != nil {
		return cleanup.UncertainMutation{Err: fmt.Errorf("Item moved but final tree cannot be verified: %w", e)}
	}
	defer check.close()
	if fingerprint(check.stamps) != item.Backup.Identity {
		return cleanup.UncertainMutation{Err: errors.New("Item moved but descendants changed concurrently; recovery review required")}
	}
	return nil
}
func (n NativeCleanup) Quarantine(item cleanup.Item) error {
	if item.Finding.Run != nil {
		return mutateRun(item, false)
	}
	return n.move(item, false)
}
func (n NativeCleanup) Restore(item cleanup.Item) error {
	if item.Finding.Run != nil {
		return mutateRun(item, true)
	}
	return n.move(item, true)
}
func (n NativeCleanup) Recover(item cleanup.Item) (string, error) {
	if item.Finding.Run != nil {
		return recoverRun(item)
	}
	if e := n.payload(item); e != nil {
		return "RecoveryRequired", e
	}
	if e := n.safeLocation(item.Finding); e != nil {
		return "RecoveryRequired", e
	}
	match := func(path string) bool {
		l, e := lockTree(path, false)
		if e != nil {
			return false
		}
		defer l.close()
		return fingerprint(l.stamps) == item.Backup.Identity
	}
	_, s := os.Lstat(item.Finding.Location)
	_, q := os.Lstat(item.Payload)
	if os.IsNotExist(s) && match(item.Payload) {
		return "Quarantined", nil
	}
	if os.IsNotExist(q) && match(item.Finding.Location) {
		if item.State == "RestorePending" {
			return "Restored", nil
		}
		return "Failed", nil
	}
	return "RecoveryRequired", errors.New("Cannot determine interrupted item state safely; no automatic mutation")
}
func sameRaw(a, b []byte) bool { return bytes.Equal(a, b) }
