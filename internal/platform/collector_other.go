//go:build !windows

package platform

import (
	"context"
	"errors"
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"os"
)

type WindowsCollector struct{ Progress func(string) }

func (WindowsCollector) Collect(context.Context) (core.Snapshot, error) {
	return core.Snapshot{}, errors.New("Windows 10/11 is required")
}
func isReparse(_ string, i os.FileInfo) bool { return i.Mode()&os.ModeSymlink != 0 }
func localFixed(string) bool                 { return false }
