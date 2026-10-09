# App Cleanup Doctor

**Understand possible application leftovers before changing anything.**

An offline Windows utility by ALMARFELD. This repository contains the **0.1.0 scan-only development milestone**, not a published release. Windows 10/11 x64 and the separate [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) are required. Nothing is downloaded automatically.

## Current workflow

Scan Windows → inspect evidence → select items for review → optionally export a JSON scan report.

- Reads user/machine uninstall inventory in both 32-bit and 64-bit registry views, including readable Windows Installer flags and product metadata.
- Checks explicit application/vendor executable references, Run/RunOnce entries, Startup shortcuts, scheduled task executable actions and service binary paths.
- Correlates top-level AppData, ProgramData and Program Files folders with explicit missing-executable registry evidence. A folder name alone does not produce a finding.
- Displays exact locations, confidence, evidence and risk. Confidence describes the evidence, **not removal safety**.
- Shows installed application metadata and read-only uninstall commands. It never executes those commands or discovered executables.
- Supports filters, finding details and review selections. Nothing is selected automatically.
- Exports a scan report only when requested, to a new filename. Reports contain local paths and installed software details; share them carefully.

## Safety boundary

**Cleanup, quarantine, registry backup, task/startup modification, Undo and permanent deletion are disabled, including at the backend boundary.** There is no destructive cleanup implementation in this milestone. Selecting findings does not authorize or perform changes.

This is not a generic registry cleaner, antivirus, performance booster or proof that every leftover is safe to remove. Detection is conservative and heuristic. Missing files can represent moved applications or disconnected drives. Unknown paths, access-denied probes and reparse points are not treated as missing files. Active installation paths and known shared/system/runtime/package-manager locations are excluded.

Future cleanup must require explicit approval and tested rollback. Restoration can have limits (permissions, locked files, conflicts, interrupted writes); no rollback guarantee is offered by this scan-only build.

## Limitations

- No historical inventory: arbitrary unnamed orphan folders cannot be reliably attributed and are withheld.
- Registry reference detection is bounded to two Software levels and the explicit `Executable`, `ApplicationPath` and `ExePath` values. It is not a recursive string search.
- Unquoted command paths with spaces, short 8.3 aliases, relative commands, hosted scripts, DLL actions, COM task actions, non-fixed drives and network targets are withheld rather than guessed.
- Collection is bounded to 5,000 entries per source/collection and task recursion to 12 levels. Warnings and truncation are reported. No directory-size traversal is performed.
- Scans run with the current user's permissions; unreadable sources produce warnings. Administrator access is not requested automatically.
- Service findings are report-only. Drivers, Windows components and shared runtimes are excluded.
- Native collection can block briefly inside a Windows API call; cancellation is cooperative between items.
- Windows executable is not Authenticode signed. Windows may show a reputation warning. Do not disable Windows security.

## Build and tests

Use Go matching `go.mod`, Node 22 and the exact Wails version declared in `go.mod`.

```powershell
cd frontend
npm ci
npm test
npm run build
cd ..
go vet ./...
go test ./...
go install github.com/wailsapp/wails/v2/cmd/wails@v2.16.0
wails build -clean -s -webview2 browser
```

Tests use synthetic snapshots and temporary files. They do not edit registry, tasks or services. Quarantine/restore/registry backup tests are intentionally deferred with those disabled features; a refusal test enforces the boundary.

See [architecture](docs/architecture.md), [safety model](docs/safety-model.md) and [validation](docs/VALIDATION.md). MIT licensed. Support: support@almarfeld.com; security reports: security@almarfeld.com.
