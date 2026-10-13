// Package cleanup owns immutable plans and the durable reversible-operation journal.
package cleanup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
)

type Eligibility string

// UncertainMutation means the native mutation happened but its final state needs review.
type UncertainMutation struct{ Err error }

func (e UncertainMutation) Error() string { return e.Err.Error() }

const (
	Eligible   Eligibility = "ReversibleEligible"
	ReportOnly Eligibility = "ReportOnly"
	Blocked    Eligibility = "Blocked"
)

type Assessment struct {
	Eligibility Eligibility `json:"eligibility"`
	Reason      string      `json:"reason"`
	Action      string      `json:"action"`
}
type Backup struct {
	Data     json.RawMessage `json:"data"`
	Identity string          `json:"identity"`
}
type Item struct {
	Finding    core.Finding `json:"finding"`
	Assessment Assessment   `json:"assessment"`
	Backup     Backup       `json:"backup"`
	State      string       `json:"state"`
	Error      string       `json:"error"`
	Payload    string       `json:"payload"`
}
type Operation struct {
	Schema   int       `json:"schema"`
	Version  string    `json:"version"`
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	Items    []Item    `json:"items"`
	Recovery bool      `json:"recovery"`
}
type Plan struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
	Items   []Item    `json:"items"`
	Scan    string    `json:"scan"`
}

// Adapter must compare a frozen backup under native locks before changing anything.
// Recover only observes state; it must never finish interrupted cleanup automatically.
type Adapter interface {
	Inspect(core.Finding) (Assessment, Backup)
	Quarantine(Item) error
	Restore(Item) error
	Recover(Item) (string, error)
}
type storeValidator interface{ ValidateStore() error }
type Engine struct {
	mu         sync.Mutex
	root       string
	adapter    Adapter
	plans      map[string]Plan
	operations map[string]Operation
	hook       func(string) error
}

func ID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && len(s) == 32
}
func New(root string, adapter Adapter) (*Engine, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("Quarantine path must be absolute")
	}
	e := &Engine{root: root, adapter: adapter, plans: map[string]Plan{}, operations: map[string]Operation{}}
	if v, ok := adapter.(storeValidator); ok {
		if err := v.ValidateStore(); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	if v, ok := adapter.(storeValidator); ok {
		if err := v.ValidateStore(); err != nil {
			return nil, err
		}
	}
	unlock, err := lockStore(root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validID(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name(), "manifest.json"))
		if os.IsNotExist(err) {
			e.operations[entry.Name()] = Operation{Schema: 1, Version: "0.1.0", ID: entry.Name(), Items: []Item{}, Recovery: true}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("Cannot read operation %s: %w", entry.Name(), err)
		}
		var op Operation
		if err = json.Unmarshal(data, &op); err != nil || op.Schema != 1 || op.ID != entry.Name() {
			return nil, errors.New("Invalid quarantine journal; no mutations allowed")
		}
		for i := range op.Items {
			item := &op.Items[i]
			switch item.State {
			case "Planned", "Preparing", "Quarantined", "RestorePending", "Restored", "Failed", "RecoveryRequired":
			default:
				return nil, errors.New("Unknown journal item state")
			}
			if item.Payload != filepath.Join(root, op.ID, "files", fmt.Sprint(i)) {
				return nil, errors.New("Invalid payload location in journal")
			}
			if item.State == "Preparing" || item.State == "RestorePending" {
				state, err := adapter.Recover(*item)
				item.State = state
				item.Error = "Interrupted operation: inspect before restoring"
				if err != nil {
					item.State = "RecoveryRequired"
					item.Error = err.Error()
				}
				op.Recovery = true
			}
		}
		e.operations[op.ID] = op
		if op.Recovery {
			if err = e.persist(op); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}
func clone[T any](v T) T                           { b, _ := json.Marshal(v); var out T; _ = json.Unmarshal(b, &out); return out }
func (e *Engine) Assess(f core.Finding) Assessment { a, _ := e.adapter.Inspect(f); return a }
func (e *Engine) Prepare(scan string, findings []core.Finding, ids []string) (Plan, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// The UI has one active confirmation screen. Re-preparing invalidates older previews.
	e.plans = map[string]Plan{}
	if len(ids) == 0 || len(ids) > 100 {
		return Plan{}, errors.New("Select between 1 and 100 findings manually")
	}
	id, err := ID()
	if err != nil {
		return Plan{}, err
	}
	p := Plan{ID: id, Scan: scan, Expires: time.Now().Add(5 * time.Minute), Items: []Item{}}
	index := map[string]core.Finding{}
	for _, f := range findings {
		index[f.ID] = f
	}
	seen := map[string]bool{}
	for _, id := range ids {
		f, ok := index[id]
		if !ok || seen[id] {
			return Plan{}, errors.New("Unknown or repeated finding")
		}
		seen[id] = true
		a, b := e.adapter.Inspect(f)
		p.Items = append(p.Items, Item{Finding: f, Assessment: a, Backup: b, State: "Planned"})
	}
	// Overlapping source folders would make either plan item stale after the first move.
	for i := range p.Items {
		for j := 0; j < i; j++ {
			a, b := p.Items[i].Finding, p.Items[j].Finding
			if a.Kind == "Files" && b.Kind == "Files" && (core.Within(a.Location, b.Location) || core.Within(b.Location, a.Location)) {
				return Plan{}, errors.New("Overlapping targets cannot share a plan")
			}
		}
	}
	e.plans[p.ID] = clone(p)
	return clone(p), nil
}

// Execute consumes a plan even when validation fails. Reconfirmation requires a new plan.
func (e *Engine) Execute(id, scan string, revalidate func(core.Finding) error) (Operation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	unlock, err := lockStore(e.root)
	if err != nil {
		return Operation{}, err
	}
	defer unlock()
	p, ok := e.plans[id]
	if !ok {
		return Operation{}, errors.New("Plan is unknown or already consumed")
	}
	delete(e.plans, id)
	if p.Scan != scan || time.Now().After(p.Expires) {
		return Operation{}, errors.New("Plan expired or scan changed; prepare again")
	}
	for _, item := range p.Items {
		if item.Assessment.Eligibility != Eligible {
			return Operation{}, errors.New("Plan contains blocked/report-only items")
		}
		if err := revalidate(item.Finding); err != nil {
			return Operation{}, err
		}
	}
	op := Operation{Schema: 1, Version: "0.1.0", ID: p.ID, Created: time.Now().UTC(), Items: p.Items}
	dir := filepath.Join(e.root, op.ID)
	if err := os.Mkdir(dir, 0700); err != nil {
		return Operation{}, err
	}
	if err := os.Mkdir(filepath.Join(dir, "files"), 0700); err != nil {
		return Operation{}, err
	}
	for i := range op.Items {
		op.Items[i].Payload = filepath.Join(dir, "files", fmt.Sprint(i))
	}
	if err := e.persist(op); err != nil {
		return Operation{}, err
	}
	for i := range op.Items {
		item := &op.Items[i]
		if err := revalidate(item.Finding); err != nil {
			item.State = "Failed"
			item.Error = err.Error()
		} else {
			item.State = "Preparing"
			if err := e.persist(op); err != nil {
				return clone(op), err
			}
			if err := e.checkpoint("before-quarantine"); err != nil {
				return clone(op), err
			}
			err := e.adapter.Quarantine(*item)
			if err != nil {
				item.State = "Failed"
				var uncertain UncertainMutation
				if errors.As(err, &uncertain) {
					item.State = "RecoveryRequired"
				}
				item.Error = err.Error()
			} else {
				if err := e.checkpoint("after-quarantine"); err != nil {
					return clone(op), err
				}
				item.State = "Quarantined"
			}
		}
		if err := e.persist(op); err != nil {
			return clone(op), err
		}
	}
	return clone(op), nil
}
func (e *Engine) Restore(id string, ids []string) (Operation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	unlock, err := lockStore(e.root)
	if err != nil {
		return Operation{}, err
	}
	defer unlock()
	op, ok := e.operations[id]
	if !ok {
		return Operation{}, errors.New("Unknown operation")
	}
	chosen := map[string]bool{}
	for _, id := range ids {
		chosen[id] = true
	}
	if len(chosen) == 0 {
		return Operation{}, errors.New("Select items to restore")
	}
	for id := range chosen {
		found := false
		for _, it := range op.Items {
			if it.Finding.ID == id {
				found = true
			}
		}
		if !found {
			return Operation{}, errors.New("Unknown restore item")
		}
	}
	for i := range op.Items {
		item := &op.Items[i]
		if !chosen[item.Finding.ID] || item.State == "Restored" {
			continue
		}
		if item.State != "Quarantined" && item.State != "RecoveryRequired" {
			continue
		}
		item.State = "RestorePending"
		item.Error = ""
		if err := e.persist(op); err != nil {
			return clone(op), err
		}
		if err := e.checkpoint("before-restore"); err != nil {
			return clone(op), err
		}
		if err := e.adapter.Restore(*item); err != nil {
			item.State = "RecoveryRequired"
			item.Error = err.Error()
		} else {
			if err := e.checkpoint("after-restore"); err != nil {
				return clone(op), err
			}
			item.State = "Restored"
		}
		if err := e.persist(op); err != nil {
			return clone(op), err
		}
	}
	return clone(op), nil
}
func (e *Engine) History() []Operation {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []Operation{}
	for _, o := range e.operations {
		out = append(out, clone(o))
	}
	return out
}
func (e *Engine) checkpoint(phase string) error {
	if e.hook != nil {
		return e.hook(phase)
	}
	return nil
}
func (e *Engine) persist(op Operation) error {
	if v, ok := e.adapter.(storeValidator); ok {
		if err := v.ValidateStore(); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(op, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(e.root, op.ID)
	f, err := os.CreateTemp(dir, "manifest-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = replaceJournal(name, filepath.Join(dir, "manifest.json")); err != nil {
		return err
	}
	e.operations[op.ID] = clone(op)
	return nil
}
