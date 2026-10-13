# Safety model

Scanning remains read-only. Nothing is selected automatically. Confidence means evidence confidence; eligibility is a separate ReversibleEligible / ReportOnly / Blocked assessment with a reason.

Only backend findings can enter a frozen plan. Exact actions/evidence and restoration limitations are shown before confirmation. Current evidence is recollected during preparation and execution; stale targets, changed identities, unsafe/protected paths, non-fixed volumes, cross-volume moves, reparse points and hard links are refused. Locked/access-denied sources fail without elevation. A failed item does not stop unrelated eligible items, except a journal persistence failure, which stops the operation for recovery.

Supported mutations: same-volume moves of correlated application folders and actual orphan Startup shortcut files; transactionally backed-up orphan Run/RunOnce values containing one supported executable command. Services, tasks, uninstall records and arbitrary registry keys remain report-only. Tasks cannot yet be restored with exact definition/state guarantees.

Restore requires a free original filesystem destination and unchanged quarantined identity/tree. Existing replacements are never overwritten. Registry restore inserts only if absent; a differing current value blocks it; an already identical value is an idempotent success. Registry backups retain hive/view/key/name/type/raw bytes. Shortcuts are moved, never run or rewritten.

Prepared plans expire and are single-use. No automatic crash continuation, purge, expiry or permanent-delete API exists. Native mutation precedes final success journal state; interrupted state is inspected conservatively. Directory rename has a Windows-specific race window for descendant namespace changes after their handles close: the root identity remains locked, post-move changes are flagged RecoveryRequired, and mismatching payloads are not silently restored. No claim of unconditional safety or adversarial filesystem atomicity is made.

Quarantine requires the current user's permissions and stays local. Report exports and journals contain local paths/application evidence; share carefully. Runtime WebView2 remains separate and nothing is downloaded automatically.
