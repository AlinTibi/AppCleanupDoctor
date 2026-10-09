# Scan-only milestone validation

This is development validation for 0.1.0, not an approval for destructive cleanup or a public release.

## Automated

- Go: 27 top-level unit tests covering inventory/view deduplication, broken entries, active/shared application exclusions, explicit startup/task/service targets, corroborated folders, protected/custom Windows paths, reparse points, ambiguous names, Unicode/long paths, unknown/access-denied states, collection warnings, duplicate references, per-scan probe caching, cancellation and backend cleanup/restore refusal. With the opt-in native integration test enabled, the final local regression passed 44 tests including subtests, with no failures or skips.
- An additional opt-in read-only Windows integration test scans native sources and logs aggregate counts only. Enable with `APP_CLEANUP_READ_ONLY_SMOKE=1`. It is intentionally skipped in ordinary CI to avoid relying on the runner's application inventory. It passed locally; local final regression had no skipped tests.
- Frontend: 3 tests for escaping untrusted metadata, combined filters and honest unmeasured-size review summaries.
- Go vet, frontend production build and Wails Windows production build passed locally.
- Production renderer with synthetic bridge fixtures: scan, empty initial selection, filters, details, review/history refusal, metadata escaping and 900/1024/1380/1920px layouts passed. No console errors or external requests were observed. This checks UI behavior, not native Windows collection.

## Actual Windows application

Fresh-directory launch (including spaces and a non-project working directory) passed. The rebuilt production executable completed a real read-only scan. Native UI automation verified group/type/confidence filters, finding details, explicit review selection, empty filtered results, inventory and history. Cleanup and restore remained disabled. The native save dialog successfully exported a JSON report; its inventory, findings and warnings exactly matched an independent invocation of the collector/detector. Cancelling a second save dialog created no new JSON file and left the exported report unchanged. Exclusive JSON-file creation and overwrite refusal are also covered by backend tests.

The distinct folder/magnifier icon is embedded in the multi-resolution ICO and visible in the application window. Automated captures of the real Windows taskbar button and Alt+Tab tile confirmed the same icon. The executable also launched from a read-only mapped folder in Windows Sandbox with networking disabled. That Sandbox already had a usable WebView2 Runtime: actual runtime absence was not independently reproduced. The startup code checks the separately required runtime and contains factual Microsoft download guidance without an automatic installation path; source inspection is not a missing-runtime execution test.

The final local development ZIP was freshly extracted and launched successfully; its real scan completed with no automatic selection. The public repository contains no machine report or private scan data.

An early scan exposed repeated disk-probe overhead and unnecessary SCM access permissions. Per-scan caching and query-only SCM access corrected those issues; subsequent native integration scans completed in approximately two seconds on the validation machine. This is not a general performance guarantee.

## Real Windows evidence review

The validation machine yielded 776 raw uninstall records across HKCU and both HKLM views, deduplicated to 749 inventory entries. All raw records were compared against an independent registry reader; a representative 23-application sample was reviewed field by field. No real inventory mismatch remained. Registry string values were compared using the Windows terminating-NUL convention.

All seven reported findings were reviewed against independent filesystem and registry/task data: four registry findings and three scheduled-task findings, all Medium confidence. Three were assessed as likely true positives and four as ambiguous because related installations or shared vendor components still existed. There were no High or Low findings, no confirmed true positives asserting safe removal, and no false positives in the final reported set. Missing referenced targets do not establish that deleting a record or related data is safe. Machine-specific evidence stays in ignored local validation artifacts and is not published.

Independent read-only task, startup and service inspection found no real resolved-target mismatches. COM task actions were not treated as executable paths, and protected/shared service targets were withheld. Partial collection warnings remained visible; unreadable sources were not converted into missing-file evidence.

Two verified safety gaps were corrected and covered by synthetic regression tests:

- `System Volume Information` was absent from the protected-path components. A controlled in-memory reference to a missing target beneath the real protected directory demonstrated a potential false positive; the directory is now withheld on any drive, case-insensitively.
- A real task using a bare executable name and a working directory exposed an unjustified path assumption. Bare executable names can use Windows search semantics; a working directory alone does not establish their resolved location. Such targets are now withheld, while explicitly relative paths retain their documented handling.

The corrections did not hide or change the seven real reported findings. Real junction/symlink paths returned Unknown, and protected Windows/runtime directories were excluded. Unicode and long-path edge cases were covered by synthetic probes and production-renderer fixtures rather than fabricated native system entries.

## Deferred safety validation

Quarantine, restore, registry backup/restore and fault-injected partial cleanup tests are not implemented because those operations are disabled and have no implementation. The corrected scan-only detector is sufficiently conservative to proceed with a separate rollback/cleanup implementation milestone; this does not authorize cleanup, automatic selection, or deletion of any reviewed finding. Destructive operations will require their own recovery, ownership, failure and clean-machine validation before they can be enabled.
