"""
Core boq operations: overlay mounting, container management.
"""

import fcntl
import ipaddress
import json
import logging
import os
import re
import shlex
import socket
import subprocess
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import Config


def detect_inside_boq() -> tuple[bool, str]:
    """Detect if currently running inside a boq container.

    Uses multiple detection methods for reliability:
    1. BOQ_NAME environment variable (set by boq)
    2. Hostname prefix "boq-" (set by boq)
    3. Podman container marker file /run/.containerenv

    Returns:
        Tuple of (is_inside_boq, detection_method).
        detection_method is empty string if not inside boq.
    """
    # Method 1: BOQ_NAME environment variable (most reliable, boq-specific)
    if os.environ.get("BOQ_NAME"):
        return True, "BOQ_NAME environment variable"

    # Method 2: Hostname prefix (boq-specific)
    try:
        if socket.gethostname().startswith("boq-"):
            return True, "hostname prefix 'boq-'"
    except OSError:
        pass

    # Method 3: Podman container marker file
    if Path("/run/.containerenv").exists():
        return True, "podman container marker /run/.containerenv"

    return False, ""


class BoqError(Exception):
    """Boq operation error."""
    pass


class LockTimeout(BoqError):
    """Lock acquisition timeout."""
    pass


class BoqDestroyed(BoqError):
    """Boq was destroyed while waiting for lock."""
    pass


class BoqLock:
    """File-based lock for serializing boq operations.

    Uses fcntl.flock() for POSIX advisory locking.
    Supports exclusive (write) and shared (read) locks with timeout.
    """

    def __init__(self, lock_file: Path, timeout: float = 30.0, check_destroyed: bool = False):
        """
        Args:
            lock_file: Path to the lock file.
            timeout: Lock acquisition timeout in seconds.
            check_destroyed: If True, check st_nlink after acquiring lock to detect
                if the boq was destroyed while waiting.
        """
        self.lock_file = lock_file
        self.timeout = timeout
        self.check_destroyed = check_destroyed
        self._fd = None
        self._lock_type = None

    def _ensure_lock_dir(self):
        """Ensure parent directory exists for lock file."""
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)

    def _acquire(self, lock_type: int, lock_name: str):
        """Acquire lock with timeout."""
        self._ensure_lock_dir()
        self._fd = open(self.lock_file, "w")

        start = time.monotonic()
        while True:
            try:
                fcntl.flock(self._fd, lock_type | fcntl.LOCK_NB)
                self._lock_type = lock_type

                # Check if lock file was deleted while we were waiting
                # (indicates boq was destroyed)
                if self.check_destroyed:
                    stat = os.fstat(self._fd.fileno())
                    if stat.st_nlink == 0:
                        self._fd.close()
                        self._fd = None
                        self._lock_type = None
                        raise BoqDestroyed(
                            "Boq was destroyed while waiting for lock"
                        )
                return
            except BlockingIOError:
                elapsed = time.monotonic() - start
                if elapsed > self.timeout:
                    self._fd.close()
                    self._fd = None
                    raise LockTimeout(
                        f"Timeout acquiring {lock_name} lock after {self.timeout:.0f}s: "
                        f"another boq operation is in progress"
                    )
                time.sleep(0.1)

    def _release(self):
        """Release lock."""
        if self._fd:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None
            self._lock_type = None

    def downgrade_to_shared(self):
        """Atomically downgrade from exclusive to shared lock."""
        if self._fd and self._lock_type == fcntl.LOCK_EX:
            fcntl.flock(self._fd, fcntl.LOCK_SH)
            self._lock_type = fcntl.LOCK_SH

    @contextmanager
    def exclusive(self):
        """Context manager for exclusive lock."""
        self._acquire(fcntl.LOCK_EX, "exclusive")
        try:
            yield self
        finally:
            self._release()

    @contextmanager
    def shared(self):
        """Context manager for shared lock."""
        self._acquire(fcntl.LOCK_SH, "shared")
        try:
            yield self
        finally:
            self._release()


def get_global_lock(boq_root: Path, timeout: float = 30.0) -> BoqLock:
    """Get global lock for cross-instance operations (e.g., create)."""
    return BoqLock(boq_root / ".lock", timeout=timeout)


def run_cmd(cmd: list[str], check: bool = True, capture: bool = False, **kwargs) -> subprocess.CompletedProcess:
    """Run a command."""
    if capture:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
        kwargs.setdefault("text", True)
    return subprocess.run(cmd, check=check, **kwargs)


def run_sudo(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command with sudo."""
    return run_cmd(["sudo"] + cmd, **kwargs)


def validate_name(name: str) -> None:
    """Validate boq name to prevent path traversal."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise BoqError(f"Invalid boq name '{name}': must contain only alphanumeric characters, dashes, and underscores.")


# Paths that must never be deleted
_DANGEROUS_PATHS = frozenset({
    "/", "/home", "/root", "/usr", "/var", "/etc", "/bin", "/sbin",
    "/lib", "/lib64", "/lib32", "/opt", "/boot", "/dev", "/proc", "/sys", "/tmp"
})


def safe_rmtree(path: Path) -> None:
    """Safely remove a boq directory with multiple safeguards.

    Safeguards:
    1. Path must be resolved (no symlinks or ..)
    2. Path must contain '.boq' component
    3. Path must have sufficient depth (>= 4 components)
    4. Path must not be in dangerous paths blacklist
    """
    resolved = path.resolve()
    resolved_str = str(resolved)

    # 1. Must contain '.boq' in path
    if "/.boq/" not in resolved_str and not resolved_str.endswith("/.boq"):
        raise BoqError(f"Refusing to delete: {resolved} does not contain '.boq'")

    # 2. Path depth check (e.g., /home/user/.boq/name = 5 parts)
    if len(resolved.parts) < 4:
        raise BoqError(f"Refusing to delete: path {resolved} is too shallow")

    # 3. Blacklist check
    if resolved_str in _DANGEROUS_PATHS or resolved_str.rstrip("/") in _DANGEROUS_PATHS:
        raise BoqError(f"Refusing to delete dangerous path: {resolved}")

    # All checks passed, safe to delete
    run_sudo(["rm", "-rf", str(resolved)])


def escape_mount_opt(path: str | Path) -> str:
    """Escape path for use in mount options."""
    return str(path).replace(",", "\\,")


def is_mountpoint(path: Path) -> bool:
    """Check if path is a mountpoint."""
    result = run_cmd(["mountpoint", "-q", str(path)], check=False)
    return result.returncode == 0


RUNTIME_PODMAN = "podman"
RUNTIME_DOCKER = "docker"
CONTAINER_TYPE_PODMAN_ROOTFUL = "podman-rootful"
CONTAINER_TYPE_PODMAN_ROOTLESS = "podman-rootless"
CONTAINER_TYPE_DOCKER = "docker"
CONTAINER_TYPE_DOCKER_SUDO = "docker-sudo"
SUPPORTED_RUNTIMES = frozenset({RUNTIME_PODMAN, RUNTIME_DOCKER})


def _docker_container_exists_with_prefix(name: str, prefix: list[str]) -> bool:
    """Check if docker container exists with command prefix."""
    try:
        result = run_cmd(
            prefix + ["docker", "container", "inspect", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _docker_container_running_with_prefix(name: str, prefix: list[str]) -> bool:
    """Check if docker container is running with command prefix."""
    try:
        result = run_cmd(
            prefix + ["docker", "inspect", "-f", "{{.State.Status}}", name],
            check=False,
            capture=True,
        )
        return result.returncode == 0 and result.stdout.strip() == "running"
    except FileNotFoundError:
        return False


def _podman_container_exists_with_prefix(name: str, prefix: list[str]) -> bool:
    """Check if podman container exists with a specific command prefix."""
    try:
        result = run_cmd(
            prefix + ["podman", "container", "exists", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _podman_container_running_with_prefix(name: str, prefix: list[str]) -> bool:
    """Check if podman container is running with a specific command prefix."""
    try:
        result = run_cmd(
            prefix + ["podman", "inspect", "-f", "{{.State.Status}}", name],
            check=False,
            capture=True,
        )
        return result.returncode == 0 and result.stdout.strip() == "running"
    except FileNotFoundError:
        return False


def get_running_container_type(name: str) -> str | None:
    """Detect running container type for boq container name."""
    if _docker_container_running_with_prefix(name, []):
        return CONTAINER_TYPE_DOCKER
    if _docker_container_running_with_prefix(name, ["sudo"]):
        return CONTAINER_TYPE_DOCKER_SUDO
    if _podman_container_running_with_prefix(name, ["sudo"]):
        return CONTAINER_TYPE_PODMAN_ROOTFUL
    if _podman_container_running_with_prefix(name, []):
        return CONTAINER_TYPE_PODMAN_ROOTLESS
    return None


def container_exists(name: str) -> bool:
    """Check if container exists (docker or podman)."""
    return (
        _docker_container_exists_with_prefix(name, [])
        or _docker_container_exists_with_prefix(name, ["sudo"])
        or _podman_container_exists_with_prefix(name, ["sudo"])
        or _podman_container_exists_with_prefix(name, [])
    )


def container_running(name: str) -> bool:
    """Check if container is running (docker or podman)."""
    return get_running_container_type(name) is not None


class Boq:
    """Boq instance manager."""

    def __init__(self, name: str, lock_timeout: float = 30.0, runtime: str | None = None):
        validate_name(name)
        self.name = name
        self.boq_root = Path.home() / ".boq"
        self.boq_dir = self.boq_root / name
        self.container_name = f"boq-{name}"
        self.config = Config(boq_name=name if self.exists() else None)
        # Per-boq lock with check_destroyed=True to detect if boq was destroyed while waiting
        self._lock = BoqLock(self.boq_dir / ".lock", timeout=lock_timeout, check_destroyed=True)
        self._lock_timeout = lock_timeout
        if runtime is not None and runtime not in SUPPORTED_RUNTIMES:
            raise BoqError(f"Unsupported runtime: {runtime}")
        self._runtime_override = runtime

    # Auto IP on rootful podman bridge (10.88.0.0/16 by default)
    _IP_RANGE_START = 100
    _IP_RANGE_END = 254
    _PODMAN_SUBNET = "10.88.0.0/16"
    _DOCKER_NETWORK_NAME = "boq-docker-net"
    _DOCKER_SUBNET_START = 200
    _DOCKER_SUBNET_END = 254

    def _docker_subnet_file(self) -> Path:
        """Path to persisted docker subnet selection."""
        return self.boq_root / ".docker-subnet"

    def _settings_file(self) -> Path:
        return self.boq_dir / "settings.json"

    def _load_settings(self) -> dict:
        settings_file = self._settings_file()
        if not settings_file.is_file():
            return {}
        try:
            data = json.loads(settings_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_settings(self, settings: dict) -> None:
        self.boq_dir.mkdir(parents=True, exist_ok=True)
        self._settings_file().write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n")

    def _set_setting(self, key: str, value) -> None:
        settings = self._load_settings()
        settings[key] = value
        self._save_settings(settings)

    def _get_setting(self, key: str):
        return self._load_settings().get(key)

    def get_runtime(self) -> str | None:
        """Read persisted runtime ('podman'|'docker') if available."""
        if self._runtime_override is not None:
            return self._runtime_override
        runtime = self._get_setting("runtime")
        if isinstance(runtime, str) and runtime in SUPPORTED_RUNTIMES:
            return runtime
        return None

    def _save_runtime(self, runtime: str) -> None:
        """Persist runtime metadata."""
        if runtime not in SUPPORTED_RUNTIMES:
            raise BoqError(f"Unsupported runtime: {runtime}")
        self._set_setting("runtime", runtime)

    def get_use_sudo(self) -> bool | None:
        """Read persisted sudo mode if available."""
        value = self._get_setting("use_sudo")
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in {"1", "true", "yes", "on"}:
            return True
        if isinstance(value, str) and value.lower() in {"0", "false", "no", "off"}:
            return False
        return None

    def _save_use_sudo(self, use_sudo: bool) -> None:
        """Persist sudo mode metadata."""
        self._set_setting("use_sudo", bool(use_sudo))

    def _default_runtime_preference(self) -> str:
        """Get configured default runtime preference."""
        pref = str(self.config.get("runtime.default", "auto")).strip().lower()
        if pref not in {"auto", RUNTIME_DOCKER, RUNTIME_PODMAN}:
            raise BoqError(
                f"Invalid runtime.default='{pref}'. Use auto, docker, or podman."
            )
        return pref

    def _resolve_create_runtime(self, runtime: str | None) -> str:
        """Resolve runtime for create command."""
        if runtime is not None:
            if runtime not in SUPPORTED_RUNTIMES:
                raise BoqError(f"Unsupported runtime: {runtime}")
            self._ensure_runtime_available(runtime)
            return runtime

        pref = self._default_runtime_preference()
        if pref == RUNTIME_DOCKER:
            self._ensure_runtime_available(RUNTIME_DOCKER)
            return RUNTIME_DOCKER
        if pref == RUNTIME_PODMAN:
            self._ensure_runtime_available(RUNTIME_PODMAN)
            return RUNTIME_PODMAN

        if shutil.which("docker") is not None:
            return RUNTIME_DOCKER
        if shutil.which("podman") is not None:
            return RUNTIME_PODMAN
        raise BoqError("No supported runtime found: install docker or podman.")

    def _default_docker_sudo(self) -> bool:
        """Get configured default for docker sudo mode."""
        return bool(self.config.get("docker.use_sudo", False))

    def _resolve_create_sudo_mode(self, runtime: str, docker_sudo: bool | None) -> bool:
        """Resolve sudo mode for create command."""
        if runtime == RUNTIME_DOCKER:
            if docker_sudo is not None:
                return docker_sudo
            return self._default_docker_sudo()
        if docker_sudo is not None:
            raise BoqError("--docker-sudo/--no-docker-sudo is only valid with docker runtime.")
        # New podman boqs default to rootful mode.
        return True

    def _load_docker_subnet(self) -> str | None:
        """Read persisted docker subnet if valid."""
        f = self._docker_subnet_file()
        if not f.is_file():
            return None
        subnet = f.read_text().strip()
        if not subnet:
            return None
        try:
            net = ipaddress.ip_network(subnet, strict=True)
        except ValueError:
            return None
        if net.version != 4:
            return None
        return subnet

    def _save_docker_subnet(self, subnet: str) -> None:
        """Persist docker subnet selection."""
        self._docker_subnet_file().write_text(subnet + "\n")

    def _collect_occupied_networks(self) -> list[ipaddress.IPv4Network]:
        """Collect occupied IPv4 networks from host routes and docker networks."""
        occupied: list[ipaddress.IPv4Network] = []

        try:
            route = run_cmd(["ip", "route"], capture=True, check=False)
            if route.returncode == 0 and route.stdout:
                for line in route.stdout.splitlines():
                    token = line.split(maxsplit=1)[0] if line.split() else ""
                    if "/" not in token:
                        continue
                    try:
                        net = ipaddress.ip_network(token, strict=False)
                    except ValueError:
                        continue
                    if isinstance(net, ipaddress.IPv4Network):
                        occupied.append(net)
        except FileNotFoundError:
            pass

        for prefix in ([], ["sudo"]):
            try:
                nets = run_cmd(prefix + ["docker", "network", "ls", "-q"], capture=True, check=False)
                if nets.returncode != 0 or not nets.stdout.strip():
                    continue
                ids = nets.stdout.strip().splitlines()
                inspect = run_cmd(
                    prefix + ["docker", "network", "inspect"] + ids + ["--format", "{{range .IPAM.Config}}{{println .Subnet}}{{end}}"],
                    capture=True,
                    check=False,
                )
                if inspect.returncode != 0 or not inspect.stdout:
                    continue
                for line in inspect.stdout.splitlines():
                    subnet = line.strip()
                    if not subnet:
                        continue
                    try:
                        net = ipaddress.ip_network(subnet, strict=False)
                    except ValueError:
                        continue
                    if isinstance(net, ipaddress.IPv4Network):
                        occupied.append(net)
            except FileNotFoundError:
                continue

        return occupied

    def _pick_docker_subnet(self) -> str:
        """Pick an available /16 subnet for boq docker network."""
        occupied = self._collect_occupied_networks()
        for second_octet in range(self._DOCKER_SUBNET_START, self._DOCKER_SUBNET_END + 1):
            candidate = ipaddress.ip_network(f"10.{second_octet}.0.0/16", strict=True)
            if all(not candidate.overlaps(net) for net in occupied):
                return str(candidate)
        raise BoqError("No available subnet found for docker network (tried 10.200.0.0/16-10.254.0.0/16).")

    def _get_or_allocate_docker_subnet_locked(self) -> str:
        """Get persisted docker subnet or allocate one.

        Caller must hold global lock.
        """
        subnet = self._load_docker_subnet()
        if subnet:
            return subnet

        # If network already exists, adopt its subnet for compatibility.
        docker_prefix = self._runtime_prefix(RUNTIME_DOCKER)
        try:
            existing = run_cmd(
                docker_prefix + ["docker", "network", "inspect", self._DOCKER_NETWORK_NAME, "--format", "{{range .IPAM.Config}}{{println .Subnet}}{{end}}"],
                check=False,
                capture=True,
            )
        except FileNotFoundError:
            raise BoqError("Docker runtime selected but 'docker' command is not available.")
        if existing.returncode == 0:
            subnets = []
            for line in existing.stdout.splitlines():
                s = line.strip()
                if not s:
                    continue
                try:
                    net = ipaddress.ip_network(s, strict=True)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network):
                    subnets.append(str(net))
            if len(subnets) == 1:
                self._save_docker_subnet(subnets[0])
                return subnets[0]
            if len(subnets) > 1:
                raise BoqError(
                    f"Docker network '{self._DOCKER_NETWORK_NAME}' has multiple subnets ({', '.join(subnets)}), "
                    f"cannot choose one automatically. Set {self._docker_subnet_file()} manually."
                )

        subnet = self._pick_docker_subnet()
        self._save_docker_subnet(subnet)
        return subnet

    def _get_or_allocate_docker_subnet(self) -> str:
        """Get persisted docker subnet or allocate and persist one."""
        subnet = self._load_docker_subnet()
        if subnet:
            return subnet

        global_lock = get_global_lock(self.boq_root, timeout=self._lock_timeout)
        with global_lock.exclusive():
            return self._get_or_allocate_docker_subnet_locked()

    def _effective_use_sudo(self, runtime: str | None = None) -> bool:
        """Resolve effective sudo mode for runtime backend."""
        runtime = runtime or self._effective_runtime()
        stored = self.get_use_sudo()
        if stored is not None:
            return stored

        if runtime == RUNTIME_DOCKER:
            if _docker_container_exists_with_prefix(self.container_name, []):
                return False
            if _docker_container_exists_with_prefix(self.container_name, ["sudo"]):
                return True
            return self._default_docker_sudo()

        if _podman_container_exists_with_prefix(self.container_name, ["sudo"]):
            return True
        if _podman_container_exists_with_prefix(self.container_name, []):
            return False
        # Backward compatibility: default podman behavior is rootful.
        return True

    def _runtime_prefix(self, runtime: str | None = None) -> list[str]:
        """Get command prefix for runtime backend."""
        if self._effective_use_sudo(runtime):
            return ["sudo"]
        return []

    def _ordered_prefixes_for_runtime(self, runtime: str) -> list[list[str]]:
        """Get preferred and fallback prefixes for runtime backend."""
        primary = self._runtime_prefix(runtime)
        fallback = [] if primary else ["sudo"]
        if fallback == primary:
            return [primary]
        return [primary, fallback]

    def _running_container_type_for_instance(self) -> str | None:
        """Detect running container type using boq's persisted runtime/mode."""
        runtime = self.get_runtime()

        if runtime == RUNTIME_DOCKER:
            prefix = self._runtime_prefix(RUNTIME_DOCKER)
            if _docker_container_running_with_prefix(self.container_name, prefix):
                return CONTAINER_TYPE_DOCKER_SUDO if prefix else CONTAINER_TYPE_DOCKER
            alt = [] if prefix else ["sudo"]
            if _docker_container_running_with_prefix(self.container_name, alt):
                return CONTAINER_TYPE_DOCKER_SUDO if alt else CONTAINER_TYPE_DOCKER
            return None

        if runtime == RUNTIME_PODMAN:
            prefix = self._runtime_prefix(RUNTIME_PODMAN)
            if _podman_container_running_with_prefix(self.container_name, prefix):
                return CONTAINER_TYPE_PODMAN_ROOTFUL if prefix else CONTAINER_TYPE_PODMAN_ROOTLESS
            alt = [] if prefix else ["sudo"]
            if _podman_container_running_with_prefix(self.container_name, alt):
                return CONTAINER_TYPE_PODMAN_ROOTFUL if alt else CONTAINER_TYPE_PODMAN_ROOTLESS
            return None

        # Legacy fallback when runtime metadata is absent.
        return get_running_container_type(self.container_name)

    def _container_exists_for_instance(self) -> bool:
        """Detect container existence using boq's persisted runtime/mode."""
        runtime = self.get_runtime()
        if runtime == RUNTIME_DOCKER:
            prefix = self._runtime_prefix(RUNTIME_DOCKER)
            return (
                _docker_container_exists_with_prefix(self.container_name, prefix)
                or _docker_container_exists_with_prefix(self.container_name, [] if prefix else ["sudo"])
            )
        if runtime == RUNTIME_PODMAN:
            prefix = self._runtime_prefix(RUNTIME_PODMAN)
            return (
                _podman_container_exists_with_prefix(self.container_name, prefix)
                or _podman_container_exists_with_prefix(self.container_name, [] if prefix else ["sudo"])
            )
        return container_exists(self.container_name)

    def _effective_runtime(self) -> str:
        """Resolve effective runtime for this boq."""
        running_type = self._running_container_type_for_instance()
        if running_type in {CONTAINER_TYPE_DOCKER, CONTAINER_TYPE_DOCKER_SUDO}:
            return RUNTIME_DOCKER
        if running_type in {CONTAINER_TYPE_PODMAN_ROOTFUL, CONTAINER_TYPE_PODMAN_ROOTLESS}:
            return RUNTIME_PODMAN

        runtime = self.get_runtime()
        if runtime in SUPPORTED_RUNTIMES:
            return runtime
        # Backward compatibility: legacy boqs default to podman behavior.
        return RUNTIME_PODMAN

    def _runtime_label(self) -> str:
        """Get display label for runtime type."""
        running_type = self._running_container_type_for_instance()
        if running_type:
            return running_type

        runtime = self.get_runtime() or RUNTIME_PODMAN
        if runtime == RUNTIME_DOCKER:
            return CONTAINER_TYPE_DOCKER_SUDO if self._effective_use_sudo(runtime) else CONTAINER_TYPE_DOCKER
        return CONTAINER_TYPE_PODMAN_ROOTFUL if self._effective_use_sudo(runtime) else CONTAINER_TYPE_PODMAN_ROOTLESS

    def _resolve_exec_backend(self) -> tuple[str, list[str]]:
        """Resolve backend for exec operations."""
        running_type = self._running_container_type_for_instance()
        if running_type == CONTAINER_TYPE_DOCKER:
            return RUNTIME_DOCKER, []
        if running_type == CONTAINER_TYPE_DOCKER_SUDO:
            return RUNTIME_DOCKER, ["sudo"]
        if running_type == CONTAINER_TYPE_PODMAN_ROOTLESS:
            return RUNTIME_PODMAN, []
        if running_type == CONTAINER_TYPE_PODMAN_ROOTFUL:
            return RUNTIME_PODMAN, ["sudo"]

        runtime = self._effective_runtime()
        return runtime, self._runtime_prefix(runtime)

    def _should_use_static_ip(self) -> bool:
        """Whether static IP should be configured for this boq."""
        network = self.config.get("container.network")
        # None/empty => podman default bridge network
        return not network or network == "bridge"

    def _docker_network_mode(self) -> str:
        """Resolve docker networking mode.

        Returns:
            "managed": use internal boq-docker-net
            "host": docker host mode
            "none": docker none mode

        Raises:
            BoqError: if container.network is configured to an unsupported value.
        """
        network = self.config.get("container.network")
        if not network:
            return "managed"
        if network in {"host", "none"}:
            return network
        raise BoqError(
            f"Unsupported container.network='{network}' for docker runtime. "
            "Use host/none, or leave it unset."
        )

    def _should_use_static_ip_for_runtime(self, runtime: str) -> bool:
        """Whether static IP should be configured for selected runtime."""
        if runtime == RUNTIME_DOCKER:
            return self._docker_network_mode() == "managed"
        return self._should_use_static_ip()

    def exists(self) -> bool:
        """Check if boq directory exists."""
        return self.boq_dir.is_dir()

    def is_running(self) -> bool:
        """Check if boq container is running."""
        return self._running_container_type_for_instance() is not None

    def _read_legacy_ip_file(self, boq_dir: Path) -> str | None:
        """Read persisted IP from legacy .ip file."""
        ip_file = boq_dir / ".ip"
        if not ip_file.is_file():
            return None
        try:
            ip = ip_file.read_text().strip()
        except OSError:
            return None
        if ip:
            return ip
        return None

    def _load_persisted_ip_from_dir(self, boq_dir: Path) -> str | None:
        """Read persisted IP from settings.json, falling back to legacy .ip."""
        settings_file = boq_dir / "settings.json"
        if settings_file.is_file():
            try:
                settings = json.loads(settings_file.read_text())
            except (OSError, json.JSONDecodeError):
                settings = None
            if isinstance(settings, dict):
                ip_text = settings.get("ip")
                if isinstance(ip_text, str) and ip_text:
                    return ip_text
        return self._read_legacy_ip_file(boq_dir)

    def _migrate_legacy_ip_to_settings(self) -> None:
        """Persist legacy .ip value into settings.json when setting is absent."""
        current_ip = self._get_setting("ip")
        if isinstance(current_ip, str) and current_ip:
            return
        legacy_ip = self._read_legacy_ip_file(self.boq_dir)
        if legacy_ip:
            self._save_ip(legacy_ip)

    def get_ip(self) -> str | None:
        """Read persisted IP from settings.json, with legacy .ip fallback."""
        return self._load_persisted_ip_from_dir(self.boq_dir)

    def _save_ip(self, ip: str) -> None:
        """Persist IP into settings.json."""
        self._set_setting("ip", ip)

    def _subnet_for_runtime(self, runtime: str, assume_global_lock: bool = False) -> str:
        """Return subnet used by runtime for static IP allocation."""
        if runtime == RUNTIME_DOCKER:
            if assume_global_lock:
                return self._get_or_allocate_docker_subnet_locked()
            return self._get_or_allocate_docker_subnet()
        return self._PODMAN_SUBNET

    def _allocate_ip_for_runtime(self, runtime: str, assume_global_lock: bool = False) -> str:
        """Allocate next available IP from runtime subnet.

        Scans ~/.boq/*/settings.json (falling back to legacy ~/.boq/*/.ip) and picks
        lowest available address with host part range 100-254 from selected subnet.
        Must be called under global lock.
        """
        subnet = ipaddress.ip_network(
            self._subnet_for_runtime(runtime, assume_global_lock=assume_global_lock),
            strict=True,
        )
        used: set[ipaddress.IPv4Address] = set()
        for item in self.boq_root.iterdir():
            if not item.is_dir():
                continue
            ip_text = self._load_persisted_ip_from_dir(item)
            if not isinstance(ip_text, str) or not ip_text:
                continue
            try:
                ip = ipaddress.ip_address(ip_text)
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address) and ip in subnet:
                used.add(ip)

        base = int(subnet.network_address)
        for host_part in range(self._IP_RANGE_START, self._IP_RANGE_END + 1):
            candidate = ipaddress.ip_address(base + host_part)
            if candidate in subnet and candidate not in used:
                return str(candidate)

        raise BoqError(
            f"IP range exhausted for {runtime} subnet {subnet} "
            f"(host offsets {self._IP_RANGE_START}-{self._IP_RANGE_END}). "
            "Destroy unused boqs to free addresses."
        )

    def _ip_matches_runtime_subnet(
        self, ip: str, runtime: str, assume_global_lock: bool = False
    ) -> bool:
        """Check whether IP belongs to selected runtime subnet."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not isinstance(addr, ipaddress.IPv4Address):
            return False
        subnet = ipaddress.ip_network(
            self._subnet_for_runtime(runtime, assume_global_lock=assume_global_lock),
            strict=True,
        )
        return addr in subnet

    def _update_hosts(self, ip: str) -> None:
        """Add/update /etc/hosts entry for this boq. Idempotent, warns on failure."""
        marker = f"# boq-managed:{self.name}"
        new_line = f"{ip} {self.container_name}  {marker}"
        try:
            hosts = Path("/etc/hosts").read_text()
            # Remove any existing entry for this boq
            lines = [l for l in hosts.splitlines() if marker not in l]
            lines.append(new_line)
            content = "\n".join(lines) + "\n"
            run_cmd(
                ["sudo", "tee", "/etc/hosts"],
                input=content, text=True,
                stdout=subprocess.DEVNULL, check=True,
            )
        except Exception as e:
            logging.getLogger("boq").warning(
                "Could not update /etc/hosts for %s: %s (IP %s still works by address)",
                self.container_name, e, ip,
            )

    def _remove_hosts(self) -> None:
        """Remove /etc/hosts entry for this boq. Graceful: warns on failure."""
        marker = f"# boq-managed:{self.name}"
        try:
            hosts = Path("/etc/hosts").read_text()
            if marker not in hosts:
                return
            lines = [l for l in hosts.splitlines() if marker not in l]
            content = "\n".join(lines) + "\n"
            run_cmd(
                ["sudo", "tee", "/etc/hosts"],
                input=content, text=True,
                stdout=subprocess.DEVNULL, check=True,
            )
        except Exception as e:
            logging.getLogger("boq").warning(
                "Could not remove /etc/hosts entry for %s: %s",
                self.container_name, e,
            )

    def overlay_dirs(self) -> Iterator[tuple[str, str, Path]]:
        """
        Yield overlay directories.

        Returns: (source_path, overlay_name, merged_path)
        """
        for src_path, overlay_name in self.config.overlays.items():
            merged = self.boq_dir / overlay_name / "merged"
            yield src_path, overlay_name, merged

    def mount_overlay(self, src_path: str, overlay_name: str) -> None:
        """Mount a single overlay."""
        if not Path(src_path).is_dir():
            return

        merged = self.boq_dir / overlay_name / "merged"
        if is_mountpoint(merged):
            return

        upper = self.boq_dir / overlay_name / "upper"
        work = self.boq_dir / overlay_name / "work"

        # Escape paths for mount options
        opts = (
            f"lowerdir={escape_mount_opt(src_path)},"
            f"upperdir={escape_mount_opt(upper)},"
            f"workdir={escape_mount_opt(work)},"
            "userxattr"
        )

        run_sudo([
            "mount", "-t", "overlay", f"overlay-{overlay_name}",
            "-o", opts,
            str(merged)
        ])

    def mount_all_overlays(self) -> None:
        """Mount all overlay directories."""
        for src_path, overlay_name, _ in self.overlay_dirs():
            self.mount_overlay(src_path, overlay_name)

    def unmount_overlay(self, overlay_name: str) -> None:
        """Unmount a single overlay."""
        merged = self.boq_dir / overlay_name / "merged"
        if is_mountpoint(merged):
            run_sudo(["umount", str(merged)], check=False)

    def unmount_all_overlays(self) -> None:
        """Unmount all overlay directories."""
        # First, try to unmount based on config
        for _, overlay_name, _ in self.overlay_dirs():
            self.unmount_overlay(overlay_name)

        # Safety net: check /proc/mounts for any remaining mounts under boq_dir
        # This handles cases where config changed or overlays were renamed
        if self.boq_dir.exists():
            boq_prefix = str(self.boq_dir) + "/"
            try:
                remaining = []
                for line in Path("/proc/mounts").read_text().splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        target = parts[1]
                        if target.startswith(boq_prefix):
                            remaining.append(target)
                # Unmount deepest paths first
                for target in sorted(remaining, key=len, reverse=True):
                    run_sudo(["umount", target], check=False)
            except OSError:
                pass  # /proc/mounts unavailable, first pass should have handled it

    def create_overlay_dirs(self, overlay_name: str) -> None:
        """Create overlay directory structure."""
        base = self.boq_dir / overlay_name
        (base / "upper").mkdir(parents=True, exist_ok=True)
        (base / "work").mkdir(parents=True, exist_ok=True)
        (base / "merged").mkdir(parents=True, exist_ok=True)

    def _find_dns_resolv(self) -> str | None:
        """Find the best DNS resolver config file.

        Auto-detects the best DNS config:
        1. systemd-resolved real config (not stub)
        2. /etc/resolv.conf fallback
        """
        # Try systemd-resolved (use real upstream, not stub resolver)
        systemd_resolv = Path("/run/systemd/resolve/resolv.conf")
        if systemd_resolv.exists():
            return str(systemd_resolv)

        # Fallback to /etc/resolv.conf
        if Path("/etc/resolv.conf").exists():
            return "/etc/resolv.conf"

        return None

    # System directories that may be symlinks to /usr on merged-/usr distros
    _MERGED_USR_CANDIDATES = frozenset({"/bin", "/sbin", "/lib", "/lib64", "/lib32"})

    def _is_merged_usr_symlink(self, path: str) -> bool:
        """Check if path is a system directory symlinked into /usr.

        On merged-/usr distros (Fedora, Arch, etc.), /bin -> /usr/bin, etc.
        We skip mounting these since /usr is already overlayed.

        Only checks known system directories to avoid affecting user-configured paths.
        """
        if path not in self._MERGED_USR_CANDIDATES:
            return False
        p = Path(path)
        if not p.is_symlink():
            return False
        try:
            target = str(p.resolve())
            return target.startswith("/usr/")
        except (OSError, ValueError):
            return False

    def build_volumes(self) -> list[str]:
        """Build volume mount arguments for podman."""
        volumes = []

        # Overlayed directories
        for src_path, overlay_name, merged in self.overlay_dirs():
            volumes.extend(["-v", f"{merged}:{src_path}"])

        # Passthrough paths (bypass overlay)
        for path in self.config.passthrough_paths:
            if Path(path).exists():
                volumes.extend(["-v", f"{path}:{path}"])

        # Direct mounts (read-write, bypass overlay)
        for path in self.config.direct_mounts:
            if Path(path).exists():
                volumes.extend(["-v", f"{path}:{path}"])

        # Read-only mounts (skip symlinks to /usr on merged-usr distros)
        for path in self.config.readonly_mounts:
            if self._is_merged_usr_symlink(path):
                # Skip: this is a symlink to /usr which is already overlayed
                continue
            if Path(path).exists():
                volumes.extend(["-v", f"{path}:{path}:ro"])

        # /etc files
        for f in self.config.etc_files:
            etc_path = Path("/etc") / f
            if etc_path.exists():
                volumes.extend(["-v", f"{etc_path}:{etc_path}:ro"])

        # Custom mounts (src -> dest mapping)
        custom_dests = set()
        for mount in self.config.custom_mounts:
            src = mount.get("src", "")
            dest = mount.get("dest", "")
            mode = mount.get("mode", "ro")
            if src and dest and Path(src).exists():
                mode_suffix = ":ro" if mode == "ro" else ""
                volumes.extend(["-v", f"{src}:{dest}{mode_suffix}"])
                custom_dests.add(dest)

        # DNS resolver (auto-detect if not overridden by custom mount)
        if "/etc/resolv.conf" not in custom_dests:
            dns_resolv = self._find_dns_resolv()
            if dns_resolv:
                volumes.extend(["-v", f"{dns_resolv}:/etc/resolv.conf:ro"])

        # /var/cache (some tools need)
        if Path("/var/cache").is_dir():
            volumes.extend(["-v", "/var/cache:/var/cache:ro"])

        return volumes

    def build_env_args(self) -> list[str]:
        """Build environment variable arguments for podman."""
        env_args = []

        # Determine PS1 format based on shell
        shell = self.config.get("container.shell", "/bin/zsh")
        if "zsh" in shell:
            ps1 = f"[boq:{self.name}] %n@%m:%~%# "
        else:
            # bash/sh format
            ps1 = f"[boq:{self.name}] \\u@\\h:\\w\\$ "

        # Basic environment
        env_vars = {
            "HOME": os.environ.get("HOME", ""),
            "USER": os.environ.get("USER", ""),
            "TERM": os.environ.get("TERM", "xterm-256color"),
            "PATH": os.environ.get("PATH", ""),
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
            "BOQ_NAME": self.name,
            "BOQ_IP": self.get_ip() or "",
            "PS1": ps1,
            # Build tools
            "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", ""),
            "PKG_CONFIG_PATH": os.environ.get("PKG_CONFIG_PATH", ""),
            "CMAKE_PREFIX_PATH": os.environ.get("CMAKE_PREFIX_PATH", ""),
            # Language-specific
            "GOPATH": os.environ.get("GOPATH", str(Path.home() / "go")),
            "GOROOT": os.environ.get("GOROOT", ""),
            "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
            # Shell
            "ZSH_DISABLE_COMPFIX": "true",
        }

        # Add configured environment variables
        for key, value in self.config.container.get("env", {}).items():
            if isinstance(value, str) and "$" in value:
                # Expand $VAR references from env_vars first, then os.environ
                def replace_var(match):
                    var_name = match.group(1)
                    return env_vars.get(var_name, os.environ.get(var_name, ""))
                env_vars[key] = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', replace_var, value)
            else:
                env_vars[key] = value

        for key, value in env_vars.items():
            if value:  # Only add non-empty values
                env_args.extend(["--env", f"{key}={value}"])

        return env_args

    def start_container(self) -> None:
        """Start container with current runtime backend."""
        runtime = self._effective_runtime()
        if runtime == RUNTIME_DOCKER:
            self._start_container_docker()
        else:
            self._start_container_podman()

    def _start_container_podman(self) -> None:
        """Start container with podman."""
        podman_prefix = self._runtime_prefix(RUNTIME_PODMAN)
        volumes = self.build_volumes()
        env_args = self.build_env_args()
        image = self.config.get("container.image", "docker.io/library/ubuntu:22.04")
        capabilities = self.config.get("container.capabilities", ["SYS_PTRACE"])

        cap_add = []
        for cap in capabilities:
            cap_add.extend(["--cap-add", cap])

        optional_args = []
        network = self.config.get("container.network")
        if network:
            optional_args.extend(["--network", network])

        ipc = self.config.get("container.ipc")
        if ipc:
            optional_args.extend(["--ipc", ipc])

        devices = self.config.get("container.devices", [])
        for device in devices:
            optional_args.extend(["--device", device])

        ip = self.get_ip()
        if ip and self._should_use_static_ip():
            optional_args.extend(["--ip", ip])

        extra_args = self.config.get("container.extra_args", [])
        optional_args.extend(extra_args)

        cmd = podman_prefix + [
            "podman", "run", "-d",
            "--name", self.container_name,
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--hostname", self.container_name,
        ] + volumes + [
            "--mount", "type=tmpfs,dst=/tmp,tmpfs-mode=1777",
            "--mount", "type=tmpfs,dst=/run",
            "--mount", "type=tmpfs,dst=/var/tmp,tmpfs-mode=1777",
            "--cap-drop", "ALL",
            "--cap-add", "CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,NET_BIND_SERVICE",
        ] + cap_add + optional_args + [
            "--security-opt", "no-new-privileges",
            "--pids-limit", "4096",
        ] + env_args + [
            image,
            "sleep", "infinity"
        ]

        try:
            run_cmd(cmd, stdout=subprocess.DEVNULL)
        except FileNotFoundError as e:
            raise BoqError(f"Failed to start podman container: {e}")

        if ip and self._should_use_static_ip():
            self._update_hosts(ip)

    def _start_container_docker(self) -> None:
        """Start container with docker."""
        docker_prefix = self._runtime_prefix(RUNTIME_DOCKER)
        volumes = self.build_volumes()
        env_args = self.build_env_args()
        image = self.config.get("container.image", "docker.io/library/ubuntu:22.04")
        capabilities = self.config.get("container.capabilities", ["SYS_PTRACE"])

        docker_network_mode = self._docker_network_mode()
        optional_args = []
        if docker_network_mode == "managed":
            self._ensure_docker_network()
            optional_args.extend(["--network", self._DOCKER_NETWORK_NAME])
        else:
            optional_args.extend(["--network", docker_network_mode])

        ipc = self.config.get("container.ipc")
        if ipc:
            optional_args.extend(["--ipc", ipc])

        devices = self.config.get("container.devices", [])
        for device in devices:
            optional_args.extend(["--device", device])

        ip = self.get_ip()
        if ip and docker_network_mode == "managed":
            optional_args.extend(["--ip", ip])

        extra_args = self.config.get("container.extra_args", [])
        optional_args.extend(extra_args)

        cap_args = []
        for cap in ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID", "NET_BIND_SERVICE"]:
            cap_args.extend(["--cap-add", cap])
        for cap in capabilities:
            cap_args.extend(["--cap-add", cap])

        cmd = docker_prefix + [
            "docker", "run", "-d",
            "--name", self.container_name,
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--hostname", self.container_name,
        ] + volumes + [
            "--tmpfs", "/tmp:mode=1777",
            "--tmpfs", "/run",
            "--tmpfs", "/var/tmp:mode=1777",
            "--cap-drop", "ALL",
        ] + cap_args + optional_args + [
            "--security-opt", "no-new-privileges",
            "--pids-limit", "4096",
        ] + env_args + [
            image,
            "sleep", "infinity"
        ]

        try:
            run_cmd(cmd, stdout=subprocess.DEVNULL)
        except FileNotFoundError as e:
            raise BoqError(f"Failed to start docker container: {e}")

        if ip and docker_network_mode == "managed":
            self._update_hosts(ip)

    def _ensure_docker_network(self) -> None:
        """Ensure docker network for boq exists."""
        docker_prefix = self._runtime_prefix(RUNTIME_DOCKER)
        subnet = self._get_or_allocate_docker_subnet()
        try:
            result = run_cmd(
                docker_prefix + ["docker", "network", "inspect", self._DOCKER_NETWORK_NAME, "--format", "{{range .IPAM.Config}}{{println .Subnet}}{{end}}"],
                check=False,
                capture=True,
            )
        except FileNotFoundError:
            raise BoqError("Docker runtime selected but 'docker' command is not available.")
        if result.returncode == 0:
            existing = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            if subnet in existing:
                return
            existing_str = ", ".join(sorted(existing)) if existing else "(no subnet)"
            raise BoqError(
                f"Docker network '{self._DOCKER_NETWORK_NAME}' exists with subnet {existing_str}, "
                f"expected {subnet}. Remove/recreate the network or delete {self._docker_subnet_file()}."
            )

        try:
            create = run_cmd(
                docker_prefix + [
                    "docker", "network", "create",
                    "--driver", "bridge",
                    "--subnet", subnet,
                    self._DOCKER_NETWORK_NAME,
                ],
                check=False,
                capture=True,
            )
        except FileNotFoundError:
            raise BoqError("Docker runtime selected but 'docker' command is not available.")
        if create.returncode == 0:
            return

        # Handle races (created by another process in between).
        try:
            result = run_cmd(
                docker_prefix + ["docker", "network", "inspect", self._DOCKER_NETWORK_NAME, "--format", "{{range .IPAM.Config}}{{println .Subnet}}{{end}}"],
                check=False,
                capture=True,
            )
        except FileNotFoundError:
            raise BoqError("Docker runtime selected but 'docker' command is not available.")
        if result.returncode == 0:
            existing = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            if subnet in existing:
                return
            existing_str = ", ".join(sorted(existing)) if existing else "(no subnet)"
            raise BoqError(
                f"Docker network '{self._DOCKER_NETWORK_NAME}' exists with subnet {existing_str}, "
                f"expected {subnet}. Remove/recreate the network or delete {self._docker_subnet_file()}."
            )

        stderr = create.stderr.strip() if create.stderr else "unknown error"
        raise BoqError(
            f"Failed to create docker network '{self._DOCKER_NETWORK_NAME}': {stderr}"
        )

    def _remove_container_all_backends(self) -> None:
        """Best-effort cleanup of stale containers across runtimes."""
        for prefix in ([], ["sudo"]):
            try:
                run_cmd(
                    prefix + ["docker", "rm", "-f", self.container_name],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                continue
        for prefix in (["sudo"], []):
            try:
                run_cmd(
                    prefix + ["podman", "rm", "-f", self.container_name],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                continue

    def stop_container(self) -> bool:
        """Stop and remove the container. Returns True if was running."""
        was_running = self.is_running()
        runtime = self._effective_runtime()

        if runtime == RUNTIME_DOCKER:
            had_command = False
            for prefix in self._ordered_prefixes_for_runtime(RUNTIME_DOCKER):
                try:
                    run_cmd(
                        prefix + ["docker", "stop", "-t", "5", self.container_name],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    had_command = True
                    run_cmd(
                        prefix + ["docker", "rm", "-f", self.container_name],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except FileNotFoundError:
                    continue
            if not had_command:
                raise BoqError("Docker runtime selected but 'docker' command is not available.")
        else:
            had_command = False
            for prefix in self._ordered_prefixes_for_runtime(RUNTIME_PODMAN):
                try:
                    run_cmd(
                        prefix + ["podman", "stop", "-t", "5", self.container_name],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    had_command = True
                    run_cmd(
                        prefix + ["podman", "rm", "-f", self.container_name],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except FileNotFoundError:
                    continue
            if not had_command:
                raise BoqError("Podman runtime selected but 'podman' command is not available.")

        self._remove_hosts()
        return was_running

    def _ensure_runtime_available(self, runtime: str) -> None:
        """Validate selected runtime command is available."""
        if runtime == RUNTIME_DOCKER and shutil.which("docker") is None:
            raise BoqError("Docker runtime requested but 'docker' command is not installed.")
        if runtime == RUNTIME_PODMAN and shutil.which("podman") is None:
            raise BoqError("Podman runtime requested but 'podman' command is not installed.")

    def _cleanup_failed_create(self) -> None:
        """Best-effort cleanup for partially created boq."""
        self._remove_container_all_backends()
        self._remove_hosts()
        self.unmount_all_overlays()
        if self.boq_dir.exists():
            safe_rmtree(self.boq_dir)

    def create(
        self,
        enter: bool = True,
        workdir: str | None = None,
        runtime: str | None = None,
        docker_sudo: bool | None = None,
    ) -> int:
        """Create a new boq.

        Args:
            enter: If True, enter the boq shell after creation.
            workdir: Working directory for the shell.
            runtime: Runtime backend ('podman'|'docker'). If unset, use configured default.
            docker_sudo: Whether to run docker with sudo (docker runtime only).

        Returns:
            Shell exit code if enter=True, otherwise 0.
        """
        requested_runtime = runtime or self._runtime_override
        selected_runtime = self._resolve_create_runtime(requested_runtime)
        selected_use_sudo = self._resolve_create_sudo_mode(selected_runtime, docker_sudo)

        # Step 1: Global lock to protect exists check + mkdir + per-boq lock acquisition
        # This prevents destroy from intervening between mkdir and per-boq lock
        global_lock = get_global_lock(self.boq_root, timeout=self._lock_timeout)
        with global_lock.exclusive():
            if self.exists():
                raise BoqError(f"Boq '{self.name}' already exists")
            try:
                # Create boq directory (makes per-boq lock available)
                self.boq_dir.mkdir(parents=True, exist_ok=True)
                self._save_runtime(selected_runtime)
                self._save_use_sudo(selected_use_sudo)

                # Allocate static IP (safe under global lock - no races)
                if self._should_use_static_ip_for_runtime(selected_runtime):
                    ip = self._allocate_ip_for_runtime(selected_runtime, assume_global_lock=True)
                    self._save_ip(ip)

                # Acquire per-boq lock while still holding global lock
                # This closes the race window where destroy could intervene
                self._lock._acquire(fcntl.LOCK_EX, "exclusive")
            except Exception:
                try:
                    self._cleanup_failed_create()
                except Exception as cleanup_err:
                    logging.getLogger("boq").warning(
                        "Cleanup after failed create setup for %s failed: %s",
                        self.name, cleanup_err,
                    )
                raise
        # Global lock released, but we still hold per-boq lock

        # Step 2: Setup with per-boq exclusive lock (already acquired)
        try:
            try:
                # Reload config now that we know boq doesn't exist
                self.config = Config()

                # Create overlay directories
                for _, overlay_name, _ in self.overlay_dirs():
                    self.create_overlay_dirs(overlay_name)

                # Mount overlays
                self.mount_all_overlays()

                # Start container
                self.start_container()

                # Step 3: If entering, downgrade to shared lock for shell
                if enter:
                    self._lock.downgrade_to_shared()
                    return self._exec_shell(workdir)
                return 0
            except Exception:
                try:
                    self._cleanup_failed_create()
                except Exception as cleanup_err:
                    logging.getLogger("boq").warning(
                        "Cleanup after failed create for %s failed: %s",
                        self.name, cleanup_err,
                    )
                raise
        finally:
            # Always release per-boq lock when done
            # (either exclusive after setup, or shared after shell exits)
            self._lock._release()

    def enter(self, workdir: str | None = None, migrate_to_docker: bool = False) -> int:
        """Enter the boq shell. Returns exit code.

        If container is already running, directly attach (shared lock).
        If not running, start it first (exclusive lock, then downgrade to shared).
        """
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        if migrate_to_docker and self.is_running():
            running_type = self._running_container_type_for_instance()
            if running_type and running_type not in {CONTAINER_TYPE_DOCKER, CONTAINER_TYPE_DOCKER_SUDO}:
                raise BoqError(
                    f"Boq '{self.name}' is running with {running_type}; stop it before switching to docker."
                )

        # Fast path: container already running, just need shared lock for shell
        if self.is_running():
            with self._lock.shared():
                return self._exec_shell(workdir)

        # Slow path: need to start container, acquire exclusive lock first
        with self._lock.exclusive() as lock:
            # Double-check after acquiring lock (another process might have started it)
            running_type = self._running_container_type_for_instance()
            existing_runtime = self.get_runtime()
            # Backward compatibility: migrate legacy .ip metadata under exclusive lock.
            self._migrate_legacy_ip_to_settings()
            if migrate_to_docker and running_type is None and existing_runtime != RUNTIME_DOCKER:
                self._ensure_runtime_available(RUNTIME_DOCKER)
                self._save_runtime(RUNTIME_DOCKER)
                self._save_use_sudo(self._default_docker_sudo())
            elif not existing_runtime:
                # Backward compatibility: legacy boqs default to podman.
                if running_type in {CONTAINER_TYPE_DOCKER, CONTAINER_TYPE_DOCKER_SUDO}:
                    self._save_runtime(RUNTIME_DOCKER)
                    self._save_use_sudo(running_type == CONTAINER_TYPE_DOCKER_SUDO)
                elif running_type == CONTAINER_TYPE_PODMAN_ROOTLESS:
                    self._save_runtime(RUNTIME_PODMAN)
                    self._save_use_sudo(False)
                else:
                    self._save_runtime(RUNTIME_PODMAN)
                    self._save_use_sudo(True)

            if not self.is_running():
                # Clean up stale container state from all backends.
                if self._container_exists_for_instance():
                    self._remove_container_all_backends()

                # Legacy boqs may not have persisted IP. Allocate one before rootful start.
                runtime_for_start = self._effective_runtime()
                if self._should_use_static_ip_for_runtime(runtime_for_start):
                    global_lock = get_global_lock(self.boq_root, timeout=self._lock_timeout)
                    with global_lock.exclusive():
                        current_ip = self.get_ip()
                        needs_ip = (
                            not current_ip
                            or not self._ip_matches_runtime_subnet(
                                current_ip,
                                runtime_for_start,
                                assume_global_lock=True,
                            )
                        )
                        if needs_ip:
                            self._save_ip(self._allocate_ip_for_runtime(runtime_for_start, assume_global_lock=True))

                # Create missing overlay directories (for newly added overlays)
                for src_path, overlay_name, merged in self.overlay_dirs():
                    if not merged.exists():
                        self.create_overlay_dirs(overlay_name)

                # Mount and start; if startup fails, roll back mounts/container state.
                overlays_mounted = False
                try:
                    self.mount_all_overlays()
                    overlays_mounted = True
                    self.start_container()
                except Exception as e:
                    try:
                        self._remove_container_all_backends()
                        self._remove_hosts()
                        if overlays_mounted:
                            self.unmount_all_overlays()
                    except Exception as cleanup_err:
                        logging.getLogger("boq").warning(
                            "Cleanup after failed enter-start for %s failed: %s",
                            self.name, cleanup_err,
                        )

                    if isinstance(e, BoqError):
                        raise
                    if isinstance(e, subprocess.CalledProcessError):
                        cmd = e.cmd
                        if isinstance(cmd, (list, tuple)):
                            cmd_text = shlex.join([str(p) for p in cmd])
                        else:
                            cmd_text = str(cmd)
                        raise BoqError(
                            f"Failed to start container for boq '{self.name}': "
                            f"command exited with code {e.returncode}: {cmd_text}"
                        ) from e
                    raise BoqError(
                        f"Failed to start container for boq '{self.name}': {e}"
                    ) from e

            # Downgrade to shared lock for shell execution
            lock.downgrade_to_shared()
            return self._exec_shell(workdir)

    def _exec_shell(self, workdir: str | None = None) -> int:
        """Execute shell in container."""
        shell = self.config.get("container.shell", "/bin/zsh")
        wd = workdir or os.getcwd()
        runtime, cmd_prefix = self._resolve_exec_backend()

        # Check if workdir exists in container, fallback to $HOME
        if runtime == RUNTIME_DOCKER:
            check_cmd = cmd_prefix + ["docker", "exec", self.container_name, "test", "-d", wd]
        else:
            check_cmd = cmd_prefix + ["podman", "exec", self.container_name, "test", "-d", wd]
        try:
            check = run_cmd(check_cmd, check=False)
        except FileNotFoundError as e:
            raise BoqError(f"Failed to execute shell backend command: {e}")
        if check.returncode != 0:
            wd = os.environ.get("HOME", "/")

        if runtime == RUNTIME_DOCKER:
            exec_cmd = cmd_prefix + ["docker", "exec", "-it", "-w", wd, self.container_name, shell]
        else:
            exec_cmd = cmd_prefix + ["podman", "exec", "-it", "-w", wd, self.container_name, shell]
        try:
            result = run_cmd(exec_cmd, check=False)
        except FileNotFoundError as e:
            raise BoqError(f"Failed to execute shell backend command: {e}")
        return result.returncode

    def run(self, command: str | list[str], workdir: str | None = None) -> int:
        """
        Run a command in the boq. Returns exit code.

        Uses a shared lock for session-level coordination with enter/start flows.

        Args:
            command: Command string or list of arguments.
            workdir: Working directory inside container.
        """
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        # Acquire shared lock for the entire command execution
        with self._lock.shared():
            if not self.is_running():
                raise BoqError(f"Boq '{self.name}' is not running")

            shell = self.config.get("container.shell", "/bin/zsh")
            wd = workdir or os.getcwd()
            runtime, cmd_prefix = self._resolve_exec_backend()

            # Check if workdir exists in container, fallback to $HOME
            if runtime == RUNTIME_DOCKER:
                check_cmd = cmd_prefix + ["docker", "exec", self.container_name, "test", "-d", wd]
            else:
                check_cmd = cmd_prefix + ["podman", "exec", self.container_name, "test", "-d", wd]
            try:
                check = run_cmd(check_cmd, check=False)
            except FileNotFoundError as e:
                raise BoqError(f"Failed to execute run backend command: {e}")
            if check.returncode != 0:
                wd = os.environ.get("HOME", "/")

            # Prepare command string for shell execution
            if isinstance(command, list):
                cmd_str = shlex.join(command)
            else:
                cmd_str = command

            if runtime == RUNTIME_DOCKER:
                exec_cmd = cmd_prefix + ["docker", "exec", "-w", wd, self.container_name, shell, "-c", cmd_str]
            else:
                exec_cmd = cmd_prefix + ["podman", "exec", "-w", wd, self.container_name, shell, "-c", cmd_str]
            try:
                result = run_cmd(exec_cmd, check=False)
            except FileNotFoundError as e:
                raise BoqError(f"Failed to execute run backend command: {e}")
            return result.returncode

    def stop(self) -> bool:
        """Stop the boq immediately. Returns True if was running."""
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        was_running = self.stop_container()
        self.unmount_all_overlays()
        return was_running

    def destroy(self) -> None:
        """Destroy the boq immediately (active sessions may be interrupted)."""
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        self.stop_container()
        self.unmount_all_overlays()
        safe_rmtree(self.boq_dir)

    def get_status(self) -> dict:
        """Get boq status information."""
        status = {
            "name": self.name,
            "location": str(self.boq_dir),
            "exists": self.exists(),
            "running": self.is_running(),
            "container_type": self._runtime_label(),
            "runtime": self._effective_runtime(),
            "use_sudo": self._effective_use_sudo(self._effective_runtime()),
            "ip": self.get_ip(),
            "overlays": {},
            "changes": {},
        }

        if not self.exists():
            return status

        for src_path, overlay_name, merged in self.overlay_dirs():
            status["overlays"][src_path] = is_mountpoint(merged)

            upper = self.boq_dir / overlay_name / "upper"
            if upper.exists():
                result = run_cmd(["du", "-sh", str(upper)], capture=True, check=False)
                if result.returncode == 0:
                    status["changes"][src_path] = result.stdout.split()[0]

        return status


def list_boqs(show_size: bool = False) -> list[dict]:
    """List all boq instances."""
    root = Path.home() / ".boq"

    if not root.is_dir():
        return []

    boqs = []
    config = Config()

    for item in root.iterdir():
        if not item.is_dir():
            continue

        # Skip if not a boq directory (check for overlay dirs)
        has_overlay = False
        for _, overlay_name in config.overlays.items():
            if (item / overlay_name).is_dir():
                has_overlay = True
                break

        if not has_overlay:
            continue

        name = item.name
        boq = Boq(name)

        # Calculate total size (only when requested)
        total_size = 0
        if show_size:
            for _, overlay_name, _ in boq.overlay_dirs():
                upper = boq.boq_dir / overlay_name / "upper"
                if upper.is_dir():
                    result = run_cmd(["du", "-sb", str(upper)], capture=True, check=False)
                    if result.returncode == 0:
                        try:
                            total_size += int(result.stdout.split()[0])
                        except (ValueError, IndexError):
                            pass

        runtime = boq._effective_runtime()
        container_type = boq._runtime_label()
        running = boq.is_running()
        rootless = container_type == CONTAINER_TYPE_PODMAN_ROOTLESS
        mounted = False
        if not running:
            for _, _, merged in boq.overlay_dirs():
                if is_mountpoint(merged):
                    mounted = True
                    break

        boqs.append({
            "name": name,
            "size": total_size,
            "running": running,
            "mounted": mounted,
            "ip": boq.get_ip(),
            "rootless": rootless,
            "runtime": runtime,
            "container_type": container_type,
            "use_sudo": boq._effective_use_sudo(runtime),
        })

    return boqs


def check_dependencies() -> list[str]:
    """Check for required dependencies. Returns list of missing deps."""
    missing = []
    for tool in ["mount", "umount", "rm", "git"]:
        if shutil.which(tool) is None:
            missing.append(tool)
    if shutil.which("podman") is None and shutil.which("docker") is None:
        missing.append("podman-or-docker")
    return missing
