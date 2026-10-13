package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AlinTibi/AppCleanupDoctor/internal/cleanup"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"github.com/AlinTibi/AppCleanupDoctor/internal/platform"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
	"path/filepath"
	"sync"
)

type App struct {
	ctx       context.Context
	mu        sync.Mutex
	busy      bool
	cancel    context.CancelFunc
	report    *core.Report
	collector core.Collector
	probe     core.Probe
	progress  func(string)
	engine    *cleanup.Engine
	engineErr error
	scanID    string
}

func NewApp() *App {
	a := &App{probe: platform.DiskProbe{}}
	a.collector = platform.WindowsCollector{Progress: func(stage string) {
		if a.progress != nil {
			a.progress(stage)
		}
	}}
	return a
}
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.progress = func(stage string) { runtime.EventsEmit(ctx, "scan:progress", stage) }
	root := filepath.Join(os.Getenv("LOCALAPPDATA"), "ALMARFELD", "AppCleanupDoctor", "Quarantine")
	a.engine, a.engineErr = cleanup.New(root, platform.NativeCleanup{Root: root})
}
func (a *App) Scan() (core.Report, error) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return core.Report{}, errors.New("A scan is already running")
	}
	base := a.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	a.cancel = cancel
	a.busy = true
	a.report = nil
	a.scanID = ""
	a.mu.Unlock()
	defer func() { cancel(); a.mu.Lock(); a.busy = false; a.cancel = nil; a.mu.Unlock() }()
	s, err := a.collector.Collect(ctx)
	if err != nil {
		return core.Report{}, err
	}
	if a.progress != nil {
		a.progress("Analyzing evidence and protected paths")
	}
	r := core.Detect(s, cancelProbe{ctx: ctx, inner: a.probe})
	if a.engine != nil {
		for i := range r.Findings {
			as := a.engine.Assess(r.Findings[i])
			r.Findings[i].Eligibility = string(as.Eligibility)
			r.Findings[i].CleanupReason = as.Reason
		}
		r.ScanOnly = false
	}
	if ctx.Err() != nil {
		return core.Report{}, ctx.Err()
	}
	id, err := cleanup.ID()
	if err != nil {
		return core.Report{}, err
	}
	a.mu.Lock()
	a.report = &r
	a.scanID = id
	a.mu.Unlock()
	return r, nil
}
func (a *App) CancelScan() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

type cancelProbe struct {
	ctx   context.Context
	inner core.Probe
}

func (p cancelProbe) Check(path string) core.State {
	if p.ctx.Err() != nil {
		return core.Unknown
	}
	return p.inner.Check(path)
}
func (a *App) ExportReport() error {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return errors.New("Wait for the scan to finish before exporting")
	}
	if a.report == nil {
		a.mu.Unlock()
		return errors.New("Run a scan first")
	}
	data, e := json.MarshalIndent(a.report, "", "  ")
	a.mu.Unlock()
	if e != nil {
		return e
	}
	path, e := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "Save scan report (contains local paths and application inventory)", DefaultFilename: "AppCleanupDoctor-scan.json", Filters: []runtime.FileFilter{{DisplayName: "JSON scan report", Pattern: "*.json"}}})
	if e != nil || path == "" {
		return e
	}
	return saveNewReport(path, data)
}
func saveNewReport(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return fmt.Errorf("Report was not saved; choose a new filename: %w", e)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

// Legacy single-call mutation entry points deliberately remain disabled.
func (a *App) Cleanup() error {
	return errors.New("One-step cleanup is unavailable. Prepare and confirm a reviewed quarantine plan; no changes were made")
}
func (a *App) Restore() error {
	return errors.New("Choose an operation in Quarantine / Restore; this legacy entry point makes no changes")
}

func (a *App) mutationStart() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return errors.New("Wait for the current scan/cleanup/restore to finish")
	}
	if a.engineErr != nil {
		return a.engineErr
	}
	if a.engine == nil {
		return errors.New("Quarantine storage is unavailable")
	}
	a.busy = true
	return nil
}
func (a *App) mutationEnd() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }
func (a *App) fresh(f core.Finding) error {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	s, e := a.collector.Collect(ctx)
	if e != nil {
		return e
	}
	if s.Truncated {
		return errors.New("Fresh scan was truncated; cleanup refused")
	}
	r := core.Detect(s, a.probe)
	for _, current := range r.Findings {
		if current.ID == f.ID {
			f.Eligibility = ""
			f.CleanupReason = ""
			current.Eligibility = ""
			current.CleanupReason = ""
			old, _ := json.Marshal(f)
			now, _ := json.Marshal(current)
			if string(old) == string(now) {
				return nil
			}
		}
	}
	return errors.New("Finding/evidence changed since scan; rescan and prepare again")
}
func (a *App) PrepareCleanupPlan(ids []string) (cleanup.Plan, error) {
	if e := a.mutationStart(); e != nil {
		return cleanup.Plan{}, e
	}
	defer a.mutationEnd()
	if a.report == nil || a.report.Truncated {
		return cleanup.Plan{}, errors.New("Complete a non-truncated scan first")
	}
	for _, id := range ids {
		for _, f := range a.report.Findings {
			if f.ID == id {
				if e := a.fresh(f); e != nil {
					return cleanup.Plan{}, e
				}
			}
		}
	}
	return a.engine.Prepare(a.scanID, a.report.Findings, ids)
}
func (a *App) ExecuteCleanupPlan(id string) (cleanup.Operation, error) {
	if e := a.mutationStart(); e != nil {
		return cleanup.Operation{}, e
	}
	defer a.mutationEnd()
	if a.report == nil {
		return cleanup.Operation{}, errors.New("Scan is unavailable")
	}
	op, e := a.engine.Execute(id, a.scanID, a.fresh)
	// A mutation invalidates the visible scan; retained findings can never be reused for cleanup.
	a.mu.Lock()
	a.report = nil
	a.mu.Unlock()
	return op, e
}
func (a *App) QuarantineHistory() ([]cleanup.Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return nil, errors.New("Operation is running")
	}
	if a.engineErr != nil {
		return nil, a.engineErr
	}
	if a.engine == nil {
		return nil, errors.New("Quarantine storage unavailable")
	}
	return a.engine.History(), nil
}
func (a *App) RestoreQuarantine(id string, items []string) (cleanup.Operation, error) {
	if e := a.mutationStart(); e != nil {
		return cleanup.Operation{}, e
	}
	defer a.mutationEnd()
	op, e := a.engine.Restore(id, items)
	a.mu.Lock()
	a.report = nil
	a.mu.Unlock()
	return op, e
}
