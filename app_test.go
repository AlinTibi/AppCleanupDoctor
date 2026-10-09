package main

import (
	"context"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"os"
	"path/filepath"
	"testing"
)

type fixtureCollector struct{}

func (fixtureCollector) Collect(context.Context) (core.Snapshot, error) {
	return core.Snapshot{Apps: []core.App{{Name: "Synthetic"}}}, nil
}

type fixtureProbe struct{}

func (fixtureProbe) Check(string) core.State { return core.Unknown }
func TestScanOnlyBoundary(t *testing.T) {
	a := NewApp()
	a.collector = fixtureCollector{}
	a.probe = fixtureProbe{}
	a.ctx = context.Background()
	r, e := a.Scan()
	if e != nil || !r.ScanOnly || len(r.Apps) != 1 {
		t.Fatal("scan")
	}
	if a.Cleanup() == nil || a.Restore() == nil {
		t.Fatal("destructive operation enabled")
	}
}
func TestReportCannotOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	if e := saveNewReport(p, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := saveNewReport(p, []byte("second")); e == nil {
		t.Fatal("overwrote")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "first" {
		t.Fatal("modified existing report")
	}
}

type blockingCollector struct{ started chan struct{} }

func (c blockingCollector) Collect(ctx context.Context) (core.Snapshot, error) {
	close(c.started)
	<-ctx.Done()
	return core.Snapshot{}, ctx.Err()
}
func TestConcurrentScanAndCancellation(t *testing.T) {
	started := make(chan struct{})
	a := &App{collector: blockingCollector{started: started}, probe: fixtureProbe{}}
	a.report = &core.Report{ScanOnly: true}
	done := make(chan error, 1)
	go func() { _, err := a.Scan(); done <- err }()
	<-started
	if a.ExportReport() == nil {
		t.Fatal("report export allowed during scan")
	}
	if _, err := a.Scan(); err == nil {
		t.Fatal("concurrent scan allowed")
	}
	a.CancelScan()
	if err := <-done; err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	if a.report != nil {
		t.Fatal("partial scan reported as successful")
	}
}
