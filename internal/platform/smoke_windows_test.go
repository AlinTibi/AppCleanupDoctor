//go:build windows

package platform

import (
	"context"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"os"
	"testing"
	"time"
)

// Opt-in read-only integration smoke. Logs aggregate counts only, never paths.
func TestWindowsReadOnlyIntegration(t *testing.T) {
	if os.Getenv("APP_CLEANUP_READ_ONLY_SMOKE") != "1" {
		t.Skip("Opt-in host inventory scan; default tests use synthetic data")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r := reader{ctx: ctx, softwareRemaining: limit}
	for _, stage := range []struct {
		name string
		run  func()
	}{{"Inventory", r.inventory}, {"Registry references", r.software}, {"Startup", r.startup}, {"Folders", r.folders}, {"Services", r.services}, {"Tasks and shortcuts", r.automation}} {
		start := time.Now()
		t.Log("Starting", stage.name)
		stage.run()
		t.Log(stage.name, "completed in", time.Since(start))
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
	}
	start := time.Now()
	report := core.Detect(r.s, DiskProbe{})
	t.Log("Detection", time.Since(start), "inventory", len(report.Apps), "findings", len(report.Findings), "warnings", len(report.Warnings))
	if !report.ScanOnly {
		t.Fatal("scan boundary")
	}
}
