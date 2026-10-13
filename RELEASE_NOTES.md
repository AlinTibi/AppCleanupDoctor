# App Cleanup Doctor v1.0.0

This release introduces explicit cleanup eligibility, frozen preview plans, same-volume filesystem and Startup shortcut quarantine, exact transactional Run/RunOnce backup and restore, durable item journals, conservative interrupted-operation recovery and conflict-aware Undo.

Services, scheduled tasks, uninstall inventory and arbitrary registry keys remain report-only. Permanent deletion, expiry and purge are unavailable. Restore can fail because of locks, permissions, conflicts or system changes. Windows folder moves are checked again after mutation and concurrent descendant changes require recovery review.

Microsoft Edge WebView2 Runtime is required separately. No telemetry, accounts, runtime downloads or application update mechanism are included.
