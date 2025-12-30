"""
Core boq operations: overlay mounting, container management.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Iterator

from .config import Config


class BoqError(Exception):
    """Boq operation error."""
    pass


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

    def __init__(self, name: str, boq_root: Path | None = None):
        self.name = name
        self.boq_root = boq_root or Path(os.environ.get("BOQ_ROOT", Path.home() / ".boq"))
        self.boq_dir = self.boq_root / name
        self.container_name = f"boq-{name}"
        self.config = Config(boq_root=self.boq_root, boq_name=name if self.exists() else None)

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

        run_sudo([
            "mount", "-t", "overlay", f"overlay-{overlay_name}",
            "-o", f"lowerdir={src_path},upperdir={upper},workdir={work},userxattr",
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
        for _, overlay_name, _ in self.overlay_dirs():
            self.unmount_overlay(overlay_name)

    def create_overlay_dirs(self, overlay_name: str) -> None:
        """Create overlay directory structure."""
        base = self.boq_dir / overlay_name
        (base / "upper").mkdir(parents=True, exist_ok=True)
        (base / "work").mkdir(parents=True, exist_ok=True)
        (base / "merged").mkdir(parents=True, exist_ok=True)

    def _find_dns_resolv(self) -> str | None:
        """Find the best DNS resolver config file.

        Priority:
        1. User-specified in config (dns_resolv)
        2. systemd-resolved real config (not stub)
        3. /etc/resolv.conf fallback
        """
        # Check if user specified a path
        user_dns = self.config.dns_resolv
        if user_dns and Path(user_dns).exists():
            return user_dns

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

        # DNS resolver (auto-detect or use config override)
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
                import re
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
        image = self.config.get("container.image", "ubuntu:22.04")
        capabilities = self.config.get("container.capabilities", ["SYS_PTRACE"])

        cap_add = []
        for cap in capabilities:
            cap_add.extend(["--cap-add", cap])

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
        ] + cap_add + [
            "--security-opt", "no-new-privileges",
            "--pids-limit", "4096",
        ] + env_args + [
            f"docker.io/library/{image}",
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

    def create(self) -> None:
        """Create a new boq."""
        if self.exists():
            raise BoqError(f"Boq '{self.name}' already exists")

        # Reload config now that we know boq doesn't exist
        self.config = Config(boq_root=self.boq_root)

        # Create overlay directories
        for _, overlay_name, _ in self.overlay_dirs():
            self.create_overlay_dirs(overlay_name)

        # Mount overlays
        self.mount_all_overlays()

        # Start container
        self.start_container()

    def enter(self, workdir: str | None = None) -> int:
        """Enter the boq shell. Returns exit code."""
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        # If running, just attach
        if self.is_running():
            return self._exec_shell(workdir)

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

    def run(self, command: str, workdir: str | None = None) -> int:
        """Run a command in the boq. Returns exit code."""
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

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

        result = run_cmd(
            ["podman", "exec", "-w", wd, self.container_name, shell, "-c", command],
            check=False
        )
        return result.returncode

    def stop(self) -> bool:
        """Stop the boq. Returns True if was running."""
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        was_running = self.stop_container()
        self.unmount_all_overlays()
        return was_running

    def destroy(self, force_stop: bool = False) -> None:
        """Destroy the boq."""
        if not self.exists():
            raise BoqError(f"Boq '{self.name}' not found")

        if self.is_running():
            if not force_stop:
                raise BoqError(f"Boq '{self.name}' is still running. Use --force-stop to stop and destroy.")
            self.stop()
        else:
            # Clean up stale state
            self.stop_container()
            self.unmount_all_overlays()

        # Remove boq directory (may contain root-owned files)
        run_sudo(["rm", "-rf", str(self.boq_dir)])

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


def list_boqs(boq_root: Path | None = None) -> list[dict]:
    """List all boq instances."""
    root = boq_root or Path(os.environ.get("BOQ_ROOT", Path.home() / ".boq"))

    if not root.is_dir():
        return []

    boqs = []
    config = Config(boq_root=root)

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
    if shutil.which("podman") is None:
        missing.append("podman")
    return missing
