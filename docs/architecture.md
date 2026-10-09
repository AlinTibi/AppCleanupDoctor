# Architecture

## Layers

`internal/platform` collects a read-only snapshot using Windows registry APIs, Service Control Manager, Task Scheduler COM and existing shortcut properties. The Wails process runs without automatic elevation. Task and shortcut COM work is pinned to one initialized OS thread.

`internal/core` contains data models, a path policy and the pure detection engine. A `Collector` supplies a snapshot; a `Probe` distinguishes exists, positively missing and unknown. Synthetic providers exercise detections without touching the machine. The disk probe checks every ancestor with `Lstat` and reparse attributes before deciding absence.

`App` serializes scans, supports cooperative cancellation and keeps the latest report in memory. Explicit JSON export uses exclusive file creation. It provides no deletion/move/registry-write API. Disabled cleanup/restore methods return an error even if invoked outside the UI.

The TypeScript UI uses the local Wails bridge, safely escapes Windows metadata, provides inventory/results/details/review/history screens and fetches no remote resources. No scan report is saved automatically.

## Collection scope

- HKCU/HKLM uninstall keys, 32/64-bit views: names, publishers, versions, paths, uninstall strings and WindowsInstaller flag.
- Two Software levels, explicit executable values only. No registry traversal looking for arbitrary strings.
- Run/RunOnce values and existing Startup `.lnk` target properties. Shortcut objects are read and never saved or run.
- Task Scheduler ExecAction `Path`/`WorkingDirectory`; arguments are never executed. No task registration or removal.
- SCM service configurations, excluding drivers. No start, stop or delete calls.
- Top-level directories under known app-data/install roots. No recursive content or size scans.

Structured task/shortcut paths are used directly. Command-line text in Run/service/uninstall records is parsed with Windows' argument parser only to identify the first executable. Relative or ambiguous targets are withheld; hosted command arguments are not investigated.

## Platform references

[Windows uninstall metadata](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key), [TaskService](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskservice), [ExecAction](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction).

## Next boundary

A future transactional cleanup layer must independently revalidate identity, path protection, reparse ancestry and current ownership immediately before changes, create exact rollback data first, handle cross-volume/locked items and interrupted sessions, and refuse unsafe restoration conflicts. Scan confidence alone is insufficient authorization.
