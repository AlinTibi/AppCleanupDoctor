# Contributing

Keep the product focused on evidence-based application leftovers. Before proposing cleanup, read [the safety model](docs/safety-model.md).

Use synthetic fixtures only. Never add machine scan reports, personal paths, registry exports, credentials or user file contents to this repository.

Run frontend tests/build, `go vet ./...`, `go test ./...` and the Windows Wails build. Changes to a collector must keep missing, inaccessible and ambiguous states distinct. No detection command may execute a discovered application or uninstall command.

Cleanup, backup and restoration require a separate design and regression suite; they cannot be enabled by a UI-only change.
