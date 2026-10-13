package cleanup

import (
	"encoding/json"
	"errors"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeAdapter struct {
	state       map[string]string
	fail        string
	eligibility Eligibility
	storeErr    error
	uncertain   bool
}

func (a *fakeAdapter) ValidateStore() error { return a.storeErr }

func (a *fakeAdapter) Inspect(f core.Finding) (Assessment, Backup) {
	e := a.eligibility
	if e == "" {
		e = Eligible
	}
	return Assessment{Eligibility: e, Action: "synthetic"}, Backup{Data: json.RawMessage(`{}`), Identity: f.ID}
}
func (a *fakeAdapter) Quarantine(i Item) error {
	if a.fail == i.Finding.ID {
		return errors.New("synthetic permission denied")
	}
	if a.state[i.Finding.ID] == "Quarantined" {
		return errors.New("already moved")
	}
	a.state[i.Finding.ID] = "Quarantined"
	if a.uncertain {
		return UncertainMutation{Err: errors.New("moved but changed")}
	}
	return nil
}
func (a *fakeAdapter) Restore(i Item) error {
	if a.fail == i.Finding.ID {
		return errors.New("synthetic conflict")
	}
	a.state[i.Finding.ID] = "Restored"
	return nil
}
func (a *fakeAdapter) Recover(i Item) (string, error) {
	if s := a.state[i.Finding.ID]; s != "" {
		return s, nil
	}
	return "Failed", nil
}
func engineFixture(t *testing.T) (*Engine, *fakeAdapter, []core.Finding) {
	t.Helper()
	a := &fakeAdapter{state: map[string]string{}}
	e, err := New(t.TempDir(), a)
	if err != nil {
		t.Fatal(err)
	}
	return e, a, []core.Finding{{ID: "one", Kind: "Files", Location: `C:\Synthetic\One`}, {ID: "two", Kind: "Files", Location: `C:\Synthetic\Two`}}
}
func TestPlanOwnershipExpiryAndEligibility(t *testing.T) {
	e, a, f := engineFixture(t)
	for _, ids := range [][]string{nil, {"unknown"}, {"one", "one"}} {
		if _, err := e.Prepare("scan", f, ids); err == nil {
			t.Fatal("invalid selection")
		}
	}
	p, _ := e.Prepare("scan", f, []string{"one"})
	p.Items[0].Finding.Location = `C:\Windows`
	op, err := e.Execute(p.ID, "scan", func(f core.Finding) error {
		if f.Location == `C:\Windows` {
			t.Fatal("frontend mutated plan")
		}
		return nil
	})
	if err != nil || op.Items[0].State != "Quarantined" {
		t.Fatal(err)
	}
	if _, err = e.Execute(p.ID, "scan", func(core.Finding) error { return nil }); err == nil {
		t.Fatal("double execution")
	}
	p, _ = e.Prepare("scan", f, []string{"two"})
	internal := e.plans[p.ID]
	internal.Expires = time.Now().Add(-time.Second)
	e.plans[p.ID] = internal
	if _, err = e.Execute(p.ID, "scan", nil); err == nil {
		t.Fatal("expired plan")
	}
	a.eligibility = ReportOnly
	p, _ = e.Prepare("scan", f, []string{"one"})
	if _, err = e.Execute(p.ID, "scan", nil); err == nil {
		t.Fatal("report only executed")
	}
}
func TestRevalidationAndPartialFailures(t *testing.T) {
	e, a, f := engineFixture(t)
	p, _ := e.Prepare("scan", f, []string{"one"})
	if _, err := e.Execute(p.ID, "scan", func(core.Finding) error { return errors.New("changed") }); err == nil {
		t.Fatal("stale accepted")
	}
	if len(e.History()) != 0 {
		t.Fatal("journal falsely succeeded")
	}
	a.fail = "two"
	p, _ = e.Prepare("scan", f, []string{"one", "two"})
	op, err := e.Execute(p.ID, "scan", func(core.Finding) error { return nil })
	if err != nil || op.Items[0].State != "Quarantined" || op.Items[1].State != "Failed" {
		t.Fatal("partial result", err)
	}
	a.fail = "one"
	op, err = e.Restore(op.ID, []string{"one"})
	if err != nil || op.Items[0].State != "RecoveryRequired" {
		t.Fatal("restore conflict")
	}
	a.fail = ""
	op, err = e.Restore(op.ID, []string{"one"})
	if err != nil || op.Items[0].State != "Restored" {
		t.Fatal(err)
	}
}
func TestCrashRecoveryAtMutationBoundaries(t *testing.T) {
	for _, phase := range []string{"before-quarantine", "after-quarantine", "before-restore", "after-restore"} {
		t.Run(phase, func(t *testing.T) {
			e, a, f := engineFixture(t)
			p, _ := e.Prepare("scan", f, []string{"one"})
			hook := func(s string) error {
				if s == phase {
					return errors.New("simulated process stop")
				}
				return nil
			}
			if phase == "before-quarantine" || phase == "after-quarantine" {
				e.hook = hook
			}
			op, err := e.Execute(p.ID, "scan", func(core.Finding) error { return nil })
			if phase == "before-restore" || phase == "after-restore" {
				e.hook = hook
				_, err = e.Restore(op.ID, []string{"one"})
			}
			if err == nil {
				t.Fatal("failure not injected")
			}
			reopened, err := New(e.root, a)
			if err != nil {
				t.Fatal(err)
			}
			history := reopened.History()
			if len(history) != 1 || !history[0].Recovery {
				t.Fatal("no recovery")
			}
			want := map[string]string{"before-quarantine": "Failed", "after-quarantine": "Quarantined", "before-restore": "Quarantined", "after-restore": "Restored"}[phase]
			if history[0].Items[0].State != want {
				t.Fatalf("%s want %s", history[0].Items[0].State, want)
			}
			if len(a.state) > 1 {
				t.Fatal("recovery performed mutation")
			}
		})
	}
}
func TestScanGenerationAndRestoreIdempotency(t *testing.T) {
	e, _, f := engineFixture(t)
	p, _ := e.Prepare("old", f, []string{"one"})
	if _, err := e.Execute(p.ID, "new", nil); err == nil {
		t.Fatal("old scan")
	}
	p, _ = e.Prepare("new", f, []string{"one"})
	op, _ := e.Execute(p.ID, "new", func(core.Finding) error { return nil })
	op, err := e.Restore(op.ID, []string{"one"})
	if err != nil {
		t.Fatal(err)
	}
	op, err = e.Restore(op.ID, []string{"one"})
	if err != nil || op.Items[0].State != "Restored" {
		t.Fatal("restore not idempotent")
	}
}
func TestInvalidJournalFailsClosed(t *testing.T) {
	root := t.TempDir()
	id, _ := ID()
	os.Mkdir(filepath.Join(root, id), 0700)
	os.WriteFile(filepath.Join(root, id, "manifest.json"), []byte(`{"schema":99}`), 0600)
	if _, err := New(root, &fakeAdapter{}); err == nil {
		t.Fatal("invalid journal accepted")
	}
}
func TestConcurrentDoubleExecuteSerialized(t *testing.T) {
	e, _, f := engineFixture(t)
	p, _ := e.Prepare("scan", f, []string{"one"})
	entered := make(chan struct{})
	release := make(chan struct{})
	e.hook = func(phase string) error {
		if phase == "before-quarantine" {
			close(entered)
			<-release
		}
		return nil
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, err := e.Execute(p.ID, "scan", func(core.Finding) error { return nil }); first <- err }()
	<-entered
	go func() { _, err := e.Execute(p.ID, "scan", func(core.Finding) error { return nil }); second <- err }()
	select {
	case <-second:
		t.Fatal("second call bypassed serialization")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err == nil {
		t.Fatal("executed twice")
	}
}
func TestJournalFailureStopsAndRecovers(t *testing.T) {
	e, a, f := engineFixture(t)
	p, _ := e.Prepare("scan", f, []string{"one", "two"})
	e.hook = func(phase string) error {
		if phase == "after-quarantine" {
			a.storeErr = errors.New("simulated journal write failure")
		}
		return nil
	}
	if _, err := e.Execute(p.ID, "scan", func(core.Finding) error { return nil }); err == nil {
		t.Fatal("journal failure hidden")
	}
	if a.state["two"] != "" {
		t.Fatal("continued after failed persistence")
	}
	a.storeErr = nil
	recovered, err := New(e.root, a)
	if err != nil {
		t.Fatal(err)
	}
	op := recovered.History()[0]
	if op.Items[0].State != "Quarantined" || op.Items[1].State != "Planned" {
		t.Fatal("incorrect interrupted states")
	}
}
func TestUncertainMutationNotReportedAsUntouched(t *testing.T) {
	e, a, f := engineFixture(t)
	p, _ := e.Prepare("scan", f, []string{"one"})
	a.uncertain = true
	op, err := e.Execute(p.ID, "scan", func(core.Finding) error { return nil })
	if err != nil || op.Items[0].State != "RecoveryRequired" || a.state["one"] != "Quarantined" {
		t.Fatal("uncertain native mutation falsely classified", err)
	}
}
