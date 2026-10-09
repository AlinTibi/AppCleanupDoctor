package platform

import (
	"github.com/AlinTibi/AppCleanupDoctor/internal/core"
	"os"
	"path/filepath"
	"strings"
)

type DiskProbe struct{}

func (DiskProbe) Check(raw string) core.State {
	p, e := core.Normalize(raw)
	if e != nil {
		return core.Unknown
	}
	if !localFixed(p) {
		return core.Unknown
	}
	// Inspect each ancestor with Lstat; never follow a reparse point to make a
	// missing-target decision. Unknown is deliberately different from Missing.
	parts := strings.Split(p[3:], `\`)
	current := p[:3]
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return core.Missing
		}
		if err != nil {
			return core.Unknown
		}
		if isReparse(current, info) {
			return core.Unknown
		}
	}
	return core.Exists
}
