# v1.0.0 release-readiness validation

Validation completed on 2026-10-13 against the Windows/amd64 production candidate. v1.0.0 is not publicly released. Only disposable synthetic Sandbox fixtures were mutated.

## Automated regression

50 top-level Go tests, 77 including subtests: the host passed 73 test/subtest cases and skipped four explicit native opt-ins. All four also passed in the network-disabled Windows Sandbox. The isolated platform and cleanup suites passed with no skips. Six frontend tests passed. Go vet, TypeScript/Vite production build, Wails v2.16.0 production build and actionlint passed.

Coverage includes plan ownership/expiry/generation, immutable copies, report-only eligibility, stale identities, protected/custom system roots, cross-volume refusal, reparse/hard-link refusal, in-use files, exact byte preservation, Unicode/spaced paths, no-overwrite restore, partial failures, consumed plans, serialization, journal-write failure and interrupted cleanup/restore boundaries. Added cases cover vanished sources, missing payloads, newest-first history and seven malformed-journal variants (malformed JSON, future schema, payload traversal, unknown state, report-only assessment, missing backup and duplicate finding ID).

Go race instrumentation was not run: this workstation has CGO disabled and no C compiler. Explicit concurrent/double-execution tests passed; this is not a race-detector claim. Persistence failure is injected at journal boundaries; a physically full disk and hardware power loss were not reproduced.

## Production GUI and Sandbox end-to-end

The real packaged executable scanned a synthetic absent application with an app-data file, an actual WScript.Shell-created Startup shortcut, a vendor Software reference and an orphan HKCU Run value. No item was preselected. Finding details separated evidence confidence from eligibility. Manual selection, frozen preview, confirmation, quarantine and per-item results worked. Sources were independently checked absent and payloads present.

Both views of the shared HKCU Run value were selected deliberately: one succeeded and the duplicate view was recorded as a stale-value failure. The app did not claim complete success. This remains a documented conservative limitation, not a registry replacement/removal workaround.

History survived restart. A controlled interrupted journal produced RecoveryRequired. A replacement folder blocked restore without overwrite; after removal of only that synthetic replacement, Undo restored the file, shortcut and exact Run data. Independent SHA-256 checks matched the original file and shortcut, and the Run value matched exactly. Native tests additionally covered REG_EXPAND_SZ RunOnce and raw type/bytes, both views, changed-value conflicts and access-denied sources. Services, tasks and uninstall inventory were never mutated.

The GUI empty state, scan progress, filters, eligible/report-only details, manual review, partial results, history, restore conflicts and recovery states were inspected. A bounded large synthetic inventory allowed real Cancel scan interaction; cancellation retained no partial results. Scan cancellation remains cooperative and native API calls are not interrupted mid-call. Cleanup/restore do not offer cancellation.

## Runtimes, portability and offline behavior

The executable ran in Sandbox without a separate .NET installation. WebView2 is required separately. In the disposable Sandbox only, the runtime registration was temporarily hidden from the pinned loader, then restored with its exact values/types. The packaged executable displayed a controlled Microsoft Edge WebView2 Runtime-required message with the official Microsoft URL. No download, installation or host runtime modification occurred. This tested unavailable runtime discovery, not physical runtime uninstallation.

Networking was disabled and there were zero enabled Sandbox network adapters throughout representative scan/quarantine/restart/restore workflows. Source inspection found no application telemetry, analytics, upload, update check or runtime downloader. The Microsoft runtime URL is explanatory text. This does not prove zero background network attempts by Windows/WebView2 internals.

Fresh ZIP extraction and launch from a non-project working directory passed in Downloads-like, Desktop-like, spaced, Unicode (including Japanese), and approximately 190-character practical paths. An application directory denying file/directory creation and attribute writes still launched and responded; no state was written beside the executable. Journals remained under the current user's LocalAppData quarantine directory.

The real window, taskbar and Alt+Tab icons were inspected automatically. Dark theme is the only implemented theme; light-theme testing is not applicable. The standard Sandbox display and the compact application width were inspected. Higher native Windows DPI scaling is unavailable in this remote Sandbox display and is not claimed as tested.

## Package, build and workflow

The versioned portable package uses a whitelist: executable, MIT license, README, security/release notes, third-party notices and architecture/safety/validation documentation. It contains no source, tests, caches, scan reports or quarantine payloads. The executable metadata is App Cleanup Doctor / ALMARFELD / 1.0.0 and the binary is not Authenticode signed.

The release workflow is tag-triggered only, verifies an annotated SSH-signed tag and its main ancestry, selects the peeled tag commit, checks the configured version, runs tests, installs the matching Wails CLI, and packages before publication. Workflow syntax and PowerShell parsing are checked locally. No release trigger, tag or publication was executed. Release notes deliberately retain candidate status until the later publication task.

A fresh local clone at the readiness commit passed dependency installation, all host tests, frontend build, vet, Windows production build and packaging. The nine-file archive structure matched the working-tree package, and packaged document text matched after newline normalization. The executable hashes differed, including after normalizing generated HTML/SVG newlines; byte-for-byte reproducibility is not established. This is a successful clean-source build, not a deterministic-binary claim.

The notices inventory includes the pinned Go build/transitive modules and installed frontend packages. Original upstream license and notice text is retained, including MPL-2.0 notices for build dependencies; the project itself remains MIT. No incompatible production dependency was identified.

## Limits

Windows directory rename requires closing descendant handles; concurrent descendant changes are detected after the move and become RecoveryRequired. Mismatched payloads are not silently restored. Journals are structurally validated, not cryptographically authenticated against malicious same-user edits. No cross-volume pseudo-move, automatic recovery mutation, elevation, task/service cleanup, purge or permanent deletion exists. This is not a formal security proof or guaranteed rollback.

Four real, consistently framed screenshots under docs/screenshots show findings, details, preview and history using synthetic data. Runtime evidence and reports remain in ignored artifacts. Hosted CI/CodeQL results belong to the readiness PR; local checks do not substitute for those results.
