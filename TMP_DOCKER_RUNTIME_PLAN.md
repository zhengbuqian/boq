# Temporary Plan: Docker Runtime Support for boq

## Goals
- Add `--docker` option to create boq containers with Docker.
- Keep backward compatibility with existing Podman boqs (rootful/rootless).
- Preserve global name uniqueness across runtimes (single `~/.boq/<name>` namespace).
- Show container type in `list` and `status` (`podman-rootful`, `podman-rootless`, `docker`).
- Allow explicit runtime migration for stopped boqs.

## Runtime Metadata
- Add `~/.boq/<name>/.runtime` file.
- Values:
  - `podman`
  - `docker`
- New boqs always persist runtime at creation.
- Legacy boqs without `.runtime`:
  - treated as podman-compatible by default.
  - when runtime is inferred confidently, metadata can be persisted.

## CLI Changes
- `boq create <name> [--no-enter] [--docker]`
  - `--docker` creates boq using Docker backend.
- `boq enter [name] [--docker]`
  - If boq is stopped and `--docker` is provided, runtime migration is allowed.
  - If boq is running with another runtime, return clear error.
- `list` and `status`
  - append runtime type label in output.

## Runtime Selection Rules
- If `.runtime` exists, use it as source of truth.
- If missing:
  - prefer detecting currently running backend (`docker` / `podman-rootful` / `podman-rootless`).
  - fallback to podman for backward compatibility.
- Migration only happens when explicitly requested and container is not running.

## Backend Behavior
- Podman backend:
  - keep existing rootful/rootless compatibility behavior.
- Docker backend:
  - use `docker run/exec/stop/rm/inspect`.
  - static IP is only used on bridge/default bridge mode.
  - update/remove `/etc/hosts` alias like podman.

## Name Uniqueness
- Keep existing create path guard:
  - under global lock, fail if `~/.boq/<name>` already exists.
- This guarantees podman/docker boqs cannot share a name.

## Compatibility
- Existing podman boqs continue to work without any manual migration.
- Old rootless running boqs still enter/run via rootless podman exec.
- `--force-stop` remains hidden no-op for compatibility.

## Open Decision Applied
- Can a stopped podman boq be reopened with docker?
  - Yes, but only with explicit `boq enter <name> --docker`.
  - No implicit runtime switching.
