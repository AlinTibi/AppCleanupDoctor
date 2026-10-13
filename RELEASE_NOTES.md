# Development notes

No public release has been published. Version remains 0.1.0.

This milestone adds explicit cleanup eligibility, frozen preview plans, same-volume filesystem/Startup shortcut quarantine, exact transactional Run/RunOnce backup/restore, durable item journals, conservative interrupted-operation recovery and conflict-aware Undo.

Services, scheduled tasks, uninstall inventory and arbitrary registry keys remain report-only. Permanent deletion, expiry and purge are unavailable. Restore can fail because of locks, permissions, conflicts or system changes. Windows folder moves are checked again after mutation and concurrent descendant changes require recovery review.

WebView2 remains a separate requirement. No telemetry, accounts, downloads or application update mechanism is added.
