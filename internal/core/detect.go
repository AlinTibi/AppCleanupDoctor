package core

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Detect produces review candidates, never deletion instructions. Missing means
// positively absent; access-denied and ambiguous command lines remain Unknown.
func Detect(s Snapshot, p Probe) Report {
	p = &cachedProbe{inner: p, states: map[string]State{}}
	r := Report{Created: time.Now().UTC().Format(time.RFC3339), Apps: []App{}, Findings: []Finding{}, Warnings: s.Warnings, Truncated: s.Truncated, ScanOnly: true}
	protected := func(path string) bool {
		if Protected(path) {
			return true
		}
		n, err := Normalize(path)
		if err != nil {
			return true
		}
		for _, root := range s.ProtectedRoots {
			r, err := Normalize(root)
			if err == nil && Within(n, r) {
				return true
			}
		}
		return false
	}
	appSeen := map[string]bool{}
	for _, a := range s.Apps {
		key := strings.ToLower(a.ID + "|" + a.Name + "|" + a.InstallPath + "|" + a.Version + "|" + a.Publisher)
		if !appSeen[key] {
			appSeen[key] = true
			r.Apps = append(r.Apps, a)
		}
	}
	seen := map[string]int{}
	add := func(f Finding) {
		logical := strings.NewReplacer(" [32-bit]", "", " [64-bit]", "").Replace(f.Location)
		key := strings.ToLower(f.Kind + "|" + logical + "|" + f.Target)
		if i, ok := seen[key]; ok {
			for _, e := range f.Evidence {
				if !contains(r.Findings[i].Evidence, e) {
					r.Findings[i].Evidence = append(r.Findings[i].Evidence, e)
				}
			}
			return
		}
		f.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(key)))[:16]
		seen[key] = len(r.Findings)
		r.Findings = append(r.Findings, f)
	}
	active := func(path string) bool {
		n, e := Normalize(path)
		if e != nil {
			return true
		}
		for _, a := range r.Apps {
			root, e := Normalize(a.InstallPath)
			if e == nil && p.Check(root) == Exists && (Within(n, root) || Within(root, n)) {
				return true
			}
		}
		return false
	}
	for _, a := range r.Apps {
		if a.MSI || SharedIdentity(a.Name+" "+a.Publisher) || protected(a.InstallPath) || protected(a.UninstallTarget) {
			continue
		}
		root, e1 := Normalize(a.InstallPath)
		target, e2 := Normalize(a.UninstallTarget)
		if e1 == nil && e2 == nil && p.Check(root) == Missing && p.Check(target) == Missing {
			add(Finding{Group: a.Name, Kind: "Registry", Location: a.Source, Target: target, Confidence: "Medium", Evidence: []string{"Uninstall entry names this application.", "Recorded install directory is absent: " + root, "Recorded uninstaller executable is absent: " + target}, Recommendation: "Review a potentially broken uninstall entry; do not assume all app data is obsolete.", Risk: "Portable, disconnected-drive or moved installations may still be in use."})
		}
	}
	for _, ref := range s.References {
		target, err := Normalize(ref.Target)
		if err != nil || protected(target) || SharedIdentity(ref.Name+" "+ref.Vendor) || active(target) || p.Check(target) != Missing {
			continue
		}
		group := ref.Name
		if group == "" {
			group = "Unassociated reference"
		}
		confidence := "Medium"
		risk := "A missing target may be temporary, moved or on a disconnected drive. Review the exact reference."
		if ref.Kind == "Service" {
			risk = "Report only. Never remove a service based on a missing binary alone."
		}
		add(Finding{Group: group, Kind: ref.Kind, Location: ref.Location, Target: target, Confidence: confidence, Evidence: []string{"This specific Windows entry references the executable path shown below.", "The referenced local executable is positively absent: " + target}, Recommendation: "Manual investigation; cleanup is disabled.", Risk: risk})
		// A present app-data folder needs BOTH a missing executable reference and
		// an exact bounded vendor/application name match. Name alone is withheld.
		for _, folder := range s.Folders {
			fn, err := Normalize(folder.Path)
			if err != nil || folder.Reparse || protected(fn) || active(fn) || p.Check(fn) != Exists {
				continue
			}
			if !equalName(folder.Name, ref.Name) || ref.Kind != "Registry" {
				continue
			}
			installed := false
			for _, a := range r.Apps {
				if equalName(folder.Name, a.Name) || equalName(folder.Name, a.Publisher) {
					installed = true
					break
				}
			}
			if installed {
				continue
			}
			add(Finding{Group: group, Kind: "Files", Location: fn, Target: target, Confidence: "Low", Evidence: []string{"Folder name matches the application/vendor registry key exactly.", "That key references an absent executable: " + target}, Recommendation: "Review ownership and contents; no automatic removal recommendation.", Risk: "Shared vendor folders, saved settings and user-created data may still be valuable."})
		}
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		return r.Findings[i].Group+r.Findings[i].Location < r.Findings[j].Group+r.Findings[j].Location
	})
	return r
}

// Cache only within one snapshot analysis, never across scans. Repeated active
// ownership checks must not repeatedly traverse hundreds of install paths.
type cachedProbe struct {
	inner  Probe
	states map[string]State
}

func (p *cachedProbe) Check(path string) State {
	key, err := Normalize(path)
	if err != nil {
		return Unknown
	}
	if state, ok := p.states[key]; ok {
		return state
	}
	state := p.inner.Check(key)
	p.states[key] = state
	return state
}
func equalName(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
