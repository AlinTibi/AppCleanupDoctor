# Scan-only milestone validation

This is development validation for 0.1.0, not an approval for destructive cleanup or a public release.

## Automated

- Go: 25 top-level unit tests covering inventory/view deduplication, broken entries, active/shared application exclusions, explicit startup/task/service targets, corroborated folders, protected/custom Windows paths, reparse points, ambiguous names, Unicode/long paths, unknown/access-denied states, collection warnings, duplicate references, per-scan probe caching, cancellation and backend cleanup/restore refusal.
- An additional opt-in read-only Windows integration test scans native sources and logs aggregate counts only. Enable with `APP_CLEANUP_READ_ONLY_SMOKE=1`. It is intentionally skipped in ordinary CI to avoid relying on the runner's application inventory. It passed locally; local final regression had no skipped tests.
- Frontend: 3 tests for escaping untrusted metadata, combined filters and honest unmeasured-size review summaries.
- Go vet, frontend production build and Wails Windows production build passed locally.
- Production renderer with synthetic bridge fixtures: scan, empty initial selection, filters, details, review/history refusal, metadata escaping and 900/1024/1380/1920px layouts passed. No console errors or external requests were observed. This checks UI behavior, not native Windows collection.

## Actual Windows application

Fresh-directory launch (including spaces and a non-project working directory) passed. The packaged application completed a real read-only scan, displayed inventory/findings/warnings and opened the native report-save dialog. Cancelling the dialog created no report. Exclusive JSON-file creation and overwrite refusal are covered by backend tests; a complete native-dialog save has not been independently confirmed.

The distinct folder/magnifier icon is embedded in the multi-resolution ICO and visible in the application window. Taskbar/Alt+Tab checks and missing-WebView2 testing in an isolated environment have not been independently completed for this product.

An early scan exposed repeated disk-probe overhead and unnecessary SCM access permissions. Per-scan caching and query-only SCM access corrected those issues; subsequent native integration scans completed in approximately two seconds on the validation machine. This is not a general performance guarantee.

## Deferred safety validation

Quarantine, restore, registry backup/restore and fault-injected partial cleanup tests are not implemented because those operations are disabled and have no implementation. Detection quality still needs wider synthetic scenarios and clean-machine review before any destructive workflow is designed or enabled.
