# App Cleanup Doctor

**Understand possible application leftovers before changing anything.**

An offline Windows utility by ALMARFELD. This repository contains the **0.1.0 reversible-cleanup development milestone**, not a published release. Windows 10/11 x64 and the separate [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) are required. Nothing is downloaded automatically.

## Current workflow

Scan Windows → inspect evidence and eligibility → manually select eligible items → prepare and confirm a frozen cleanup plan → quarantine → inspect results → restore if needed. JSON scan report export remains available.

- Reads user/machine uninstall inventory in both 32-bit and 64-bit registry views, including readable Windows Installer flags and product metadata.
- Checks explicit application/vendor executable references, Run/RunOnce entries, Startup shortcuts, scheduled task executable actions and service binary paths.
- Correlates top-level AppData, ProgramData and Program Files folders with explicit missing-executable registry evidence. A folder name alone does not produce a finding.
- Displays exact locations, confidence, evidence and risk. Confidence describes the evidence, **not removal safety**.
- Shows installed application metadata and read-only uninstall commands. It never executes those commands or discovered executables.
- Supports filters, finding details and review selections. Nothing is selected automatically.
- Exports a scan report only when requested, to a new filename. Reports contain local paths and installed software details; share them carefully.

## Safety boundary

**Permanent deletion is unavailable.** Supported cleanup moves correlated files/folders and actual orphan Startup shortcuts into local quarantine, or backs up and removes specifically identified orphan Run/RunOnce values. Services, scheduled tasks, uninstall inventory and general registry keys remain report-only. Selection alone performs no mutation.

This is not a generic registry cleaner, antivirus, performance booster or proof that every leftover is safe to remove. Detection is conservative and heuristic. Missing files can represent moved applications or disconnected drives. Unknown paths, access-denied probes and reparse points are not treated as missing files. Active installation paths and known shared/system/runtime/package-manager locations are excluded.

Quarantine is stored under `%LOCALAPPDATA%\ALMARFELD\AppCleanupDoctor\Quarantine\<operation-id>`. Each operation has a durable journal and separate payloads. Restore never overwrites replacements and can fail because of permissions, locks, conflicts or system changes. There is no purge, expiry or automatic cleanup continuation after a crash.

## Reversible cleanup scope

- Only same-volume native moves: cross-volume copy/delete fallback is refused. No overwrite, reparse traversal, hard-linked files or protected roots.
- Run/RunOnce backups preserve hive, view, key, name, type and exact bytes. Only unambiguous single-executable REG_SZ/REG_EXPAND_SZ commands are eligible; commands with arguments stay report-only to avoid storing secrets and unsupported semantics. Windows registry transactions are required.
- Plans expire after five minutes and are consumed once. Scanning, cleanup and restore are serialized.
- Windows requires descendant handles to close before a folder rename. Root identity stays locked; a post-move tree change produces RecoveryRequired. This is not an adversarial filesystem transaction or a promise of unconditional rollback.

## Limitations

- No historical inventory: arbitrary unnamed orphan folders cannot be reliably attributed and are withheld.
- Registry reference detection is bounded to two Software levels and the explicit `Executable`, `ApplicationPath` and `ExePath` values. It is not a recursive string search.
- Unquoted command paths with spaces, short 8.3 aliases, relative commands, hosted scripts, DLL actions, COM task actions, non-fixed drives and network targets are withheld rather than guessed.
- Collection is bounded to 5,000 entries per source/collection and task recursion to 12 levels. Warnings and truncation are reported. Scans do not traverse folder contents. Cleanup preparation inspects at most 10,000 tree entries for identity/reparse checks without hashing every file.
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

Tests use synthetic snapshots and temporary files. Registry mutation tests are opt-in with `ACD_ISOLATED_NATIVE=1` and must run only in a disposable Windows Sandbox. They create unique controlled Run/RunOnce fixtures and restore exact type/bytes; no task or service mutations are implemented. Legacy single-call cleanup methods still refuse calls.

See [architecture](docs/architecture.md), [safety model](docs/safety-model.md) and [validation](docs/VALIDATION.md). MIT licensed. Support: support@almarfeld.com; security reports: security@almarfeld.com.
