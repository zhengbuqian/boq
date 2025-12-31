"""
Core boq operations: overlay mounting, container management.
"""

import fcntl
import os
import re
import shlex
import subprocess
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import Config


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


def container_exists(name: str) -> bool:
    """Check if container exists."""
    result = run_cmd(["podman", "container", "exists", name], check=False,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def container_running(name: str) -> bool:
    """Check if container is running."""
    if not container_exists(name):
        return False
    result = run_cmd(["podman", "inspect", "-f", "{{.State.Status}}", name],
                     check=False, capture=True)
    return result.returncode == 0 and result.stdout.strip() == "running"


class Boq:
    """Boq instance manager."""

    def __init__(self, name: str, lock_timeout: float = 30.0):
        validate_name(name)
        self.name = name
        self.boq_root = Path.home() / ".boq"
        self.boq_dir = self.boq_root / name
        self.container_name = f"boq-{name}"
        self.config = Config(boq_name=name if self.exists() else None)
        # Per-boq lock with check_destroyed=True to detect if boq was destroyed while waiting
        self._lock = BoqLock(self.boq_dir / ".lock", timeout=lock_timeout, check_destroyed=True)
        self._lock_timeout = lock_timeout

    def exists(self) -> bool:
        """Check if boq directory exists."""
        return self.boq_dir.is_dir()

    def is_running(self) -> bool:
        """Check if boq container is running."""
        return container_running(self.container_name)

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
        
        # Second, safety net: check for any remaining mounts in boq_dir
        # This handles cases where config changed or overlays were renamed
        if self.boq_dir.exists():
            for root, dirs, _ in os.walk(self.boq_dir, topdown=False):
                for d in dirs:
                    path = Path(root) / d
                    if is_mountpoint(path):
                        run_sudo(["umount", str(path)], check=False)

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
        """Start the container."""
        volumes = self.build_volumes()
        env_args = self.build_env_args()
        image = self.config.get("container.image", "docker.io/library/ubuntu:22.04")
        capabilities = self.config.get("container.capabilities", ["SYS_PTRACE"])

        cap_add = []
        for cap in capabilities:
            cap_add.extend(["--cap-add", cap])

        # Build optional container arguments
        optional_args = []

        # Network mode (host, bridge, none, slirp4netns, etc.)
        network = self.config.get("container.network")
        if network:
            optional_args.extend(["--network", network])

        # IPC namespace (host, private, shareable)
        ipc = self.config.get("container.ipc")
        if ipc:
            optional_args.extend(["--ipc", ipc])

        # Device mappings (for GPU, etc.)
        devices = self.config.get("container.devices", [])
        for device in devices:
            optional_args.extend(["--device", device])

        # Extra arbitrary podman arguments
        extra_args = self.config.get("container.extra_args", [])
        optional_args.extend(extra_args)

        cmd = [
            "podman", "run", "-d",
            "--name", self.container_name,
            "--userns=keep-id",
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

        run_cmd(cmd, stdout=subprocess.DEVNULL)

    def stop_container(self) -> bool:
        """Stop and remove the container. Returns True if was running."""
        was_running = self.is_running()

        if container_exists(self.container_name):
            run_cmd(["podman", "stop", "-t", "5", self.container_name],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run_cmd(["podman", "rm", "-f", self.container_name],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return was_running

    def create(self, enter: bool = True, workdir: str | None = None) -> int:
        """Create a new boq.

        Args:
            enter: If True, enter the boq shell after creation.
            workdir: Working directory for the shell.

        Returns:
            Shell exit code if enter=True, otherwise 0.
        """
        # Step 1: Global lock to protect exists check + mkdir + per-boq lock acquisition
        # This prevents destroy from intervening between mkdir and per-boq lock
        global_lock = get_global_lock(self.boq_root, timeout=self._lock_timeout)
        with global_lock.exclusive():
            if self.exists():
                raise BoqError(f"Boq '{self.name}' already exists")

            # Create boq directory (makes per-boq lock available)
            self.boq_dir.mkdir(parents=True, exist_ok=True)

            # Acquire per-boq lock while still holding global lock
            # This closes the race window where destroy could intervene
            self._lock._acquire(fcntl.LOCK_EX, "exclusive")
        # Global lock released, but we still hold per-boq lock

        # Step 2: Setup with per-boq exclusive lock (already acquired)
        try:
            # Reload config now that we know boq doesn't exist
            self.config = Config()

            # Create overlay directories
            for _, overlay_name, _ in self.overlay_dirs():
                self.create_overlay_dirs(overlay_name)

            # Mount overlays
            self.mount_all_overlays()

            # Start container
            try:
                self.start_container()
            except Exception:
                # Clean up if start fails
                self.unmount_all_overlays()
                raise

            # Step 3: If entering, downgrade to shared lock for shell
            if enter:
                self._lock.downgrade_to_shared()
                return self._exec_shell(workdir)

            return 0
        finally:
            # Always release per-boq lock when done
            # (either exclusive after setup, or shared after shell exits)
            self._lock._release()

    def enter(self, workdir: str | None = None) -> int:
        """Enter the boq shell. Returns exit code.

        If container is already running, directly attach (shared lock).
        If not running, start it first (exclusive lock, then downgrade to shared).
        """
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        # Fast path: container already running, just need shared lock for shell
        if self.is_running():
            with self._lock.shared():
                return self._exec_shell(workdir)

        # Slow path: need to start container, acquire exclusive lock first
        with self._lock.exclusive() as lock:
            # Double-check after acquiring lock (another process might have started it)
            if not self.is_running():
                # Clean up stale container
                if container_exists(self.container_name):
                    run_cmd(["podman", "rm", "-f", self.container_name],
                            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # Create missing overlay directories (for newly added overlays)
                for src_path, overlay_name, merged in self.overlay_dirs():
                    if not merged.exists():
                        self.create_overlay_dirs(overlay_name)

                # Mount and start
                self.mount_all_overlays()
                self.start_container()

            # Downgrade to shared lock for shell execution
            lock.downgrade_to_shared()
            return self._exec_shell(workdir)

    def _exec_shell(self, workdir: str | None = None) -> int:
        """Execute shell in container."""
        shell = self.config.get("container.shell", "/bin/zsh")
        wd = workdir or os.getcwd()

        # Check if workdir exists in container, fallback to $HOME
        check = run_cmd(
            ["podman", "exec", self.container_name, "test", "-d", wd],
            check=False
        )
        if check.returncode != 0:
            wd = os.environ.get("HOME", "/")

        result = run_cmd(
            ["podman", "exec", "-it", "-w", wd, self.container_name, shell],
            check=False
        )
        return result.returncode

    def run(self, command: str | list[str], workdir: str | None = None) -> int:
        """
        Run a command in the boq. Returns exit code.

        Uses shared lock to prevent stop/destroy during execution.

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

            # Check if workdir exists in container, fallback to $HOME
            check = run_cmd(
                ["podman", "exec", self.container_name, "test", "-d", wd],
                check=False
            )
            if check.returncode != 0:
                wd = os.environ.get("HOME", "/")

            # Prepare command string for shell execution
            if isinstance(command, list):
                cmd_str = shlex.join(command)
            else:
                cmd_str = command

            result = run_cmd(
                ["podman", "exec", "-w", wd, self.container_name, shell, "-c", cmd_str],
                check=False
            )
            return result.returncode

    def stop(self) -> bool:
        """Stop the boq. Returns True if was running.

        Acquires exclusive lock, waiting for all active sessions (shells, run commands)
        to finish before stopping.
        """
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        # Exclusive lock waits for all shared locks (active sessions) to release
        with self._lock.exclusive():
            was_running = self.stop_container()
            self.unmount_all_overlays()
            return was_running

    def destroy(self, force_stop: bool = False) -> None:
        """Destroy the boq.

        Acquires exclusive lock, waiting for all active sessions to finish.
        The rm -rf is done inside the lock so that any process waiting for the lock
        will detect the deletion via st_nlink check when it acquires the lock.
        """
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        # Exclusive lock waits for all shared locks (active sessions) to release
        with self._lock.exclusive():
            if self.is_running():
                if not force_stop:
                    raise BoqError(f"Boq '{self.name}' is still running. Use --force-stop to stop and destroy.")
                self.stop_container()
                self.unmount_all_overlays()
            else:
                # Clean up stale state
                self.stop_container()
                self.unmount_all_overlays()

            # Remove boq directory inside lock (includes lock file itself)
            # This ensures waiters detect deletion via st_nlink == 0
            safe_rmtree(self.boq_dir)

    def get_status(self) -> dict:
        """Get boq status information."""
        status = {
            "name": self.name,
            "location": str(self.boq_dir),
            "exists": self.exists(),
            "running": self.is_running(),
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


def list_boqs() -> list[dict]:
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
        container_name = f"boq-{name}"

        # Calculate total size
        total_size = 0
        for _, overlay_name in config.overlays.items():
            upper = item / overlay_name / "upper"
            if upper.is_dir():
                result = run_cmd(["du", "-sb", str(upper)], capture=True, check=False)
                if result.returncode == 0:
                    try:
                        total_size += int(result.stdout.split()[0])
                    except (ValueError, IndexError):
                        pass

        # Get status
        running = container_running(container_name)
        mounted = False
        if not running:
            for _, overlay_name in config.overlays.items():
                merged = item / overlay_name / "merged"
                if is_mountpoint(merged):
                    mounted = True
                    break

        boqs.append({
            "name": name,
            "size": total_size,
            "running": running,
            "mounted": mounted,
        })

    return boqs


def check_dependencies() -> list[str]:
    """Check for required dependencies. Returns list of missing deps."""
    missing = []
    for tool in ["podman", "mount", "umount", "rm", "git"]:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing
