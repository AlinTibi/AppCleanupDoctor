# Security

Report suspected security issues privately to security@almarfeld.com. Do not include unredacted machine reports, credentials or personal paths in public issues.

The current development milestone is scan-only. It cannot delete, quarantine or restore files or modify registry/startup/task/service state. Its optional JSON export creates a user-selected new file and does not overwrite an existing file.

Paths and Windows metadata are untrusted input. Detection does not execute discovered binaries, uninstall strings or task commands. Reparse targets and uncertain probes are withheld. The renderer escapes metadata and loads no external scripts or resources. No telemetry, uploads or runtime downloads are implemented.

Findings are heuristic; they are not malware diagnoses or removal approvals. Shared components and protected paths are excluded, but no heuristic proves ownership or future deletion safety. Windows binaries are not Authenticode signed.
