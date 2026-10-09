# Safety model

## Current scan-only guarantees

No scan code deletes, moves, edits, executes or installs detected items. Reads are bounded. No cleanup is selected automatically. Review checkboxes are review aids; the cleanup button and backend methods are disabled. Nothing is persisted unless the user exports a report to a new filename.

Every finding contains explicit evidence and a risk explanation. High/Medium/Low confidence is not equivalent to safe/unsafe deletion. The initial engine uses Medium for explicit missing references and Low for correlated folders; it does not manufacture High-confidence removal approvals.

Only positively absent local executable targets count. Access denied, unknown commands, network paths, unresolved variables and reparse points produce unknown or are withheld. An installed application's existing install tree is not flagged from a missing helper alone.

Folder correlation requires an exact folder/application-key name plus that key's absent executable reference. Installed application and shared-vendor names suppress folder candidates. A name-only folder match is not reported.

## Protection policy

Local drive paths must normalize without drive-relative, network/device, wildcard, alternate-stream, control-character or ambiguous trailing components. Matching respects directory boundaries.

Windows/System32/SysWOW64/WinSxS/DriverStore/WindowsApps, drivers, Microsoft/shared runtime paths, .NET/WebView2, common files and known package-manager data are excluded. Protected identities are withheld. Folder and probe reparse points are never followed. This policy is conservative and is not a substitute for a future pre-mutation safety check.

## Deliberately unimplemented

Quarantine, cleanup sessions, registry backup/restore, startup/task rollback, permanent deletion and disk-space reclamation. There are no successful-cleanup or successful-Undo claims. Tests cover disabled-action refusal; operational rollback tests will accompany an actual implementation.

Partial collection failure is visible through warnings and truncation. Partial cleanup failure cannot occur because cleanup is disabled.

## Future cleanup acceptance criteria

Explicit review and confirmation; exact immutable targets; fresh state checks; no wildcard operation; durable backup before mutation; per-item outcome; restore conflict refusal; fault-injected interruption/cross-volume/permissions/locked-file tests; service changes excluded. Backup data must stay local and never be committed or automatically shared.
