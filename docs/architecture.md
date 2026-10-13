# Architecture

`internal/platform` retains read-only Windows collection. Structured Run/RunOnce provenance is collected independently of display strings. `internal/core` retains evidence-based detection and protected-path policy; registry views remain distinct for mutable startup values.

`internal/cleanup` owns immutable five-minute plans, operation IDs, durable schema-1 journals and item states. App methods accept finding IDs or plan/operation IDs, never arbitrary frontend paths. App serializes scanning/preparation/execution/restore. Preparation and execution recollect evidence; execution rechecks each item before mutation. A plan is consumed even on validation failure.

Native filesystem operations inspect locked handles, canonical paths, protected roots, reparse attributes, file IDs, timestamps and bounded descendant metadata. Same-volume handle-based rename refuses replacement. Windows requires descendant handles to close before directory renames; the root handle remains pinned and a post-move tree mismatch is recorded as recovery-required. It does not recursively follow links or copy/delete across volumes.

Native Run/RunOnce operations use KTM registry transactions with exact raw type/data comparison and conflict detection at commit. Unsupported types/commands, task definitions, services and general keys remain report-only. No elevation or executable invocation is used.

## Journal and recovery

`%LOCALAPPDATA%\ALMARFELD\AppCleanupDoctor\Quarantine\<id>\manifest.json` stores version/schema, timestamp, finding/evidence, original location, payload path, native identity/backup, assessment, state and per-item error. `files/<index>` preserves actual payloads. Temporary journal writes are flushed and closed, then atomically replaced with write-through. Success is recorded after the native operation. A store lock serializes mutations across processes as well as the engine mutex.

States: Planned, Preparing, Quarantined, RestorePending, Restored, Failed, RecoveryRequired. Startup observes interrupted Preparing/RestorePending items and never resumes cleanup automatically. Uncertain state remains RecoveryRequired. An operation directory without a manifest is shown as interrupted; no payload is guessed or removed.

The journal is local to the current user, not an authenticated archive against malicious same-user tampering. Invalid schema/state/payload locations fail closed. No passwords or commands with arguments are backed up. No networking, telemetry, downloads or update mechanism is added.

The v1.0.0 journal loader also bounds item count, rejects duplicate or missing finding IDs, unsupported cleanup kinds, non-eligible assessments and missing/invalid backup data before native recovery. History is ordered newest first with a stable operation-ID tie break. Findings use human-readable eligibility labels; the detail dialog is modal and keyboard-dismissible. Scan cancellation is not offered during cleanup or restore.
