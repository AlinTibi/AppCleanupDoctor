//go:build !windows

package platform

import (
	"errors"
	"github.com/AlinTibi/AppCleanupDoctor/internal/cleanup"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
)

type NativeCleanup struct{ Root string }

func (NativeCleanup) Inspect(core.Finding) (cleanup.Assessment, cleanup.Backup) {
	return cleanup.Assessment{Eligibility: cleanup.Blocked, Reason: "Windows is required"}, cleanup.Backup{}
}
func (NativeCleanup) Quarantine(cleanup.Item) error { return errors.New("Windows required") }
func (NativeCleanup) Restore(cleanup.Item) error    { return errors.New("Windows required") }
func (NativeCleanup) Recover(cleanup.Item) (string, error) {
	return "RecoveryRequired", errors.New("Windows required")
}
