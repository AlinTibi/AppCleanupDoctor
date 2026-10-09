package core

import "context"

type App struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Publisher        string `json:"publisher"`
	Version          string `json:"version"`
	InstallPath      string `json:"installPath"`
	UninstallCommand string `json:"uninstallCommand"`
	UninstallTarget  string `json:"uninstallTarget"`
	Source           string `json:"source"`
	MSI              bool   `json:"msi"`
}
type Reference struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Target   string `json:"target"`
	Vendor   string `json:"vendor"`
}
type Folder struct {
	Path, Name string
	Reparse    bool
}
type Snapshot struct {
	ProtectedRoots []string    `json:"-"`
	Apps           []App       `json:"apps"`
	References     []Reference `json:"-"`
	Folders        []Folder    `json:"-"`
	Warnings       []string    `json:"warnings"`
	Truncated      bool        `json:"truncated"`
}
type Finding struct {
	ID             string   `json:"id"`
	Group          string   `json:"group"`
	Kind           string   `json:"kind"`
	Location       string   `json:"location"`
	Target         string   `json:"target"`
	Confidence     string   `json:"confidence"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	Risk           string   `json:"risk"`
	Size           *int64   `json:"size"`
}
type Report struct {
	Created   string    `json:"created"`
	Apps      []App     `json:"apps"`
	Findings  []Finding `json:"findings"`
	Warnings  []string  `json:"warnings"`
	Truncated bool      `json:"truncated"`
	ScanOnly  bool      `json:"scanOnly"`
}
type State int

const (
	Unknown State = iota
	Exists
	Missing
)

type Probe interface{ Check(string) State }
type Collector interface {
	Collect(context.Context) (Snapshot, error)
}
