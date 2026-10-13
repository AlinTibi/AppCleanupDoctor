# Reversible-cleanup milestone validation

Development validation completed on 2026-10-13. No public release or real-machine cleanup was performed.

## Automated regression

47 top-level Go tests (67 including subtests) are covered across the host and isolated Windows runs. The host run passed 63 test/subtest cases and skipped four explicit opt-in native cases. Those four passed in Windows Sandbox: Run/RunOnce transactions, permission-denied ACL fixture and the existing read-only collector integration. Sandbox platform and journal suites had no failures or skipped cases. The 5 frontend tests passed. Go vet, TypeScript/Vite production build and Wails v2.16.0 Windows/amd64 production build passed.

Coverage includes backend plan ownership, expiry, generation changes, immutable copies, blocked/report-only eligibility, stale tree identity, protected/custom system roots, cross-volume refusal, symlink/junction/hard-link refusal, in-use files, exact byte preservation, Unicode/spaced/nested paths, no-overwrite restore, partial failures, duplicate execution, serialization, journal-write failure, and interrupted cleanup/restore boundaries. The engine fault tests simulate before/after native mutation and persistence failure; native recovery independently inspects source/payload identity. No permanent-deletion implementation exists.

Go race instrumentation was not run: this workstation has CGO disabled and no C compiler. Explicit concurrent/double-execution unit tests passed; this is not a race-detector claim.

## Actual Windows Sandbox (network disabled)

Only disposable synthetic fixtures were mutated. Native tests passed for correlated files/folders, unchanged bytes after restore, a Startup shortcut file, REG_SZ Run and REG_EXPAND_SZ RunOnce (32/64-bit provenance and exact raw bytes), registry restore conflicts/stale commands, real reparse/hard-link refusal and an ACL-denied source that remained untouched. Services/tasks were not modified. Scheduled tasks remain report-only because exact rollback is not implemented.

A real .lnk was created for a harmless absent executable through WScript.Shell in Sandbox. The production executable scanned the synthetic Software reference, correlated app-data folder and orphan shortcut. Nothing was selected automatically. GUI automation selected the two eligible items, prepared the detailed plan, confirmed quarantine, inspected the two Quarantined results and restored both through Undo. Independent native checks confirmed source absence/payload presence during quarantine, then source presence/payload absence after restore. The restored synthetic file content was identical. The application ran with zero enabled network adapters; no runtime download was needed.

The journal survived process restart and history was reloaded. All native mutation files, reports and evidence remain in ignored artifacts, not in Git. Tests do not remove real user documents or touch unrelated registry entries, tasks, services or startup items.

## Limits of this validation

This is not an adversarial filesystem proof. Windows requires closing descendant handles before directory rename; concurrent descendant namespace changes are detected after the move and become RecoveryRequired. A mismatched payload is not silently restored. Power-loss hardware durability was not physically tested; flushed/write-through journal transitions and simulated interruption were tested. Journals are not cryptographically authenticated against malicious same-user edits. No cross-volume pseudo-move, task rollback, permanent deletion, automatic expiry or elevation is supported. Cancellation applies to scanning only; cleanup/restore finish one serialized operation with per-item results.

Current CI and CodeQL results are attached to the PR; local checks do not substitute for those hosted results.
