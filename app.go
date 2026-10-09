package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"github.com/AlinTibi/AppCleanupDoctor/internal/platform"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
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
	if ctx.Err() != nil {
		return core.Report{}, ctx.Err()
	}
	a.mu.Lock()
	a.report = &r
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

// Disabled methods also enforce the milestone boundary if called directly.
func (a *App) Cleanup() error {
	return errors.New("Cleanup is disabled in this scan-only milestone; no changes were made")
}
func (a *App) Restore() error {
	return errors.New("Restore is unavailable: this milestone creates no cleanup sessions or quarantine")
}
