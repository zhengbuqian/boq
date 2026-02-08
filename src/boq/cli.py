"""
Command-line interface for boq tool.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from .core import Boq, BoqError, BoqDestroyed, LockTimeout, list_boqs, check_dependencies, run_cmd, detect_inside_boq


# ANSI colors
class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    NC = "\033[0m"  # No Color


def log_info(msg: str) -> None:
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def log_ok(msg: str) -> None:
    print(f"{Colors.GREEN}[OK]{Colors.NC} {msg}")


def log_warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def log_error(msg: str) -> None:
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ["B", "K", "M", "G", "T"]:
        if size_bytes < 1024:
            if unit == "B":
                return f"{size_bytes}{unit}"
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}P"


def cmd_create(args: argparse.Namespace) -> int:
    """Create a new boq."""
    boq = Boq(args.name)

    try:
        log_info("Creating boq...")
        if args.enter:
            log_info(f"Location: {boq.boq_dir}")
            log_info(f"Entering boq '{args.name}'...")
            rc = boq.create(
                enter=True,
                runtime=args.runtime,
                docker_sudo=args.docker_sudo,
            )
            ip = boq.get_ip()
            if ip:
                log_info(f"IP: {ip}  Hostname: {boq.container_name}")
            return rc
        else:
            boq.create(
                enter=False,
                runtime=args.runtime,
                docker_sudo=args.docker_sudo,
            )
            log_ok(f"Created boq: {args.name}")
            log_info(f"Location: {boq.boq_dir}")
            ip = boq.get_ip()
            if ip:
                log_info(f"IP: {ip}  Hostname: {boq.container_name}")
            log_info("Container is running. Use 'enter' to attach a shell.")
            return 0
    except LockTimeout as e:
        log_error(str(e))
        return 1
    except BoqError as e:
        log_error(str(e))
        return 1


def cmd_enter(args: argparse.Namespace) -> int:
    """Enter a boq."""
    boq = Boq(args.name)

    try:
        if not boq.exists():
            log_error(f"Boq '{args.name}' not found")
            print(f"Create it first: boq create {args.name}")
            return 1

        if boq.is_running():
            log_info(f"Attaching to boq '{args.name}'...")
        else:
            log_info("Mounting overlays...")
            log_info("Starting container...")
            log_info(f"Attaching to boq '{args.name}'...")

        return boq.enter(migrate_to_docker=args.migrate_to_docker)
    except BoqDestroyed as e:
        log_error(f"Boq '{args.name}' was destroyed while waiting")
        return 1
    except LockTimeout as e:
        log_error(str(e))
        return 1
    except BoqError as e:
        log_error(str(e))
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    """Run a command in boq."""
    boq = Boq(args.name)

    if not args.command:
        log_error("No command specified")
        print("Usage: boq run <name> <command>")
        return 1

    try:
        return boq.run(args.command)
    except BoqDestroyed as e:
        log_error(f"Boq '{args.name}' was destroyed while waiting")
        return 1
    except LockTimeout as e:
        log_error(str(e))
        return 1
    except BoqError as e:
        log_error(str(e))
        return 1


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop a boq."""
    boq = Boq(args.name)

    try:
        log_info(f"Stopping boq '{args.name}'...")
        was_running = boq.stop()
        if was_running:
            log_ok(f"Stopped boq: {args.name}")
        else:
            log_info(f"Boq '{args.name}' was not running")
        return 0
    except BoqError as e:
        log_error(str(e))
        return 1


def cmd_destroy(args: argparse.Namespace) -> int:
    """Destroy a boq."""
    boq = Boq(args.name)

    try:
        log_info(f"Destroying boq '{args.name}'...")
        boq.destroy()
        log_ok(f"Destroyed boq: {args.name}")
        return 0
    except BoqError as e:
        log_error(str(e))
        return 1


def cmd_diff(args: argparse.Namespace) -> int:
    """Show changes in boq."""
    boq = Boq(args.name)

    if not boq.exists():
        log_error(f"Boq '{args.name}' not found")
        return 1

    use_gitignore = not args.no_gitignore
    content_only = not args.include_metadata
    filter_path = args.path

    # Normalize filter_path
    if filter_path:
        filter_path = filter_path.rstrip("/")
        if not filter_path.startswith("/"):
            filter_path = str(Path.cwd() / filter_path)

    # Find git root for gitignore filtering
    git_root = None
    if use_gitignore and filter_path:
        result = run_cmd(
            ["git", "-C", filter_path, "rev-parse", "--show-toplevel"],
            check=False, capture=True
        )
        if result.returncode == 0:
            git_root = result.stdout.strip()

    def has_content_change(upper_file: Path, orig_file: Path) -> bool:
        """Check if file content differs from original."""
        if not orig_file.exists():
            return True  # New file
        if upper_file.is_dir() != orig_file.is_dir():
            return True  # Type changed
        result = run_cmd(["cmp", "-s", str(upper_file), str(orig_file)], check=False)
        return result.returncode != 0

    def get_changed_files(upper: Path, src_path: str, search_path: Path) -> list[str]:
        """Get list of changed files."""
        if not search_path.is_dir():
            return []

        # Find all files excluding .git
        result = run_cmd(
            ["find", str(search_path), "-name", ".git", "-prune", "-o", "-type", "f", "-print"],
            capture=True, check=False
        )
        if result.returncode != 0:
            return []

        all_files = result.stdout.strip().split("\n") if result.stdout.strip() else []

        # Build list of original paths
        files_with_orig = []
        for f in all_files:
            rel = f[len(str(upper)):]
            orig = src_path + rel
            files_with_orig.append((f, orig, rel))

        # Filter by gitignore if needed
        if use_gitignore and git_root:
            orig_paths = [orig for _, orig, _ in files_with_orig]
            result = run_cmd(
                ["git", "-C", git_root, "check-ignore", "--stdin"],
                input="\n".join(orig_paths),
                capture=True, check=False, text=True
            )
            ignored = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
            files_with_orig = [(f, orig, rel) for f, orig, rel in files_with_orig if orig not in ignored]

        # Filter by content change if needed
        changed = []
        for upper_file, orig, rel in files_with_orig:
            if not content_only or has_content_change(Path(upper_file), Path(orig)):
                changed.append(rel)

        return sorted(changed)

    # Collect output
    output_lines = []

    for src_path, overlay_name, _ in boq.overlay_dirs():
        upper = boq.boq_dir / overlay_name / "upper"

        # Determine search path
        search_path = upper
        display_filter = ""

        if filter_path:
            if filter_path.startswith(src_path):
                rel_path = filter_path[len(src_path):]
                search_path = upper / rel_path.lstrip("/")
                display_filter = f" (filtered: {filter_path})"
                if not search_path.is_dir():
                    continue
            else:
                continue

        if search_path.is_dir():
            files = get_changed_files(upper, src_path, search_path)
            if files:
                gitignore_note = ""
                if use_gitignore and git_root:
                    gitignore_note = " [respecting .gitignore]"
                output_lines.append(
                    f"{Colors.BLUE}=== Modified/Added in {src_path}{display_filter} ({len(files)} files){gitignore_note} ==={Colors.NC}"
                )
                output_lines.extend(files)
                output_lines.append("")

    # Disk usage
    output_lines.append(f"{Colors.BLUE}=== Disk usage ==={Colors.NC}")
    for src_path, overlay_name, _ in boq.overlay_dirs():
        upper = boq.boq_dir / overlay_name / "upper"

        search_path = upper
        display_path = src_path

        if filter_path:
            if filter_path.startswith(src_path):
                rel_path = filter_path[len(src_path):]
                search_path = upper / rel_path.lstrip("/")
                display_path = filter_path
                if not search_path.is_dir():
                    continue
            else:
                continue

        if search_path.is_dir():
            result = run_cmd(["du", "-sh", str(search_path)], capture=True, check=False)
            if result.returncode == 0:
                size = result.stdout.split()[0]
                output_lines.append(f"  {display_path}: {size}")

    # Output with pager if terminal
    output = "\n".join(output_lines)

    if sys.stdout.isatty():
        try:
            proc = subprocess.Popen(
                ["less", "-RF", "--mouse"],
                stdin=subprocess.PIPE,
                text=True
            )
            proc.communicate(input=output)
        except (FileNotFoundError, BrokenPipeError):
            print(output)
    else:
        print(output)

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show boq status."""
    boq = Boq(args.name)

    if not boq.exists():
        log_error(f"Boq '{args.name}' not found")
        return 1

    status = boq.get_status()

    print(f"{Colors.BLUE}Boq: {status['name']}{Colors.NC}")
    print(f"  Location: {status['location']}")
    print(f"  Container Type: {status.get('container_type', 'unknown')}")
    print(f"  Runtime Mode: {'sudo' if status.get('use_sudo') else 'direct'}")
    if status.get("ip"):
        print(f"  IP: {status['ip']}")
        print(f"  Hostname: boq-{status['name']}")

    print("  Overlays:")
    for src_path, mounted in status["overlays"].items():
        if mounted:
            print(f"    {src_path}: {Colors.GREEN}mounted{Colors.NC}")
        else:
            print(f"    {src_path}: {Colors.YELLOW}not mounted{Colors.NC}")

    for path in boq.config.direct_mounts:
        print(f"    {path}: {Colors.YELLOW}direct mount (has nested mounts){Colors.NC}")

    for mount in boq.config.custom_mounts:
        src = mount.get("src", "")
        dest = mount.get("dest", "")
        mode = mount.get("mode", "ro")
        print(f"    {src} -> {dest}: {Colors.YELLOW}custom mount ({mode}){Colors.NC}")

    if status["running"]:
        print(f"  Container: {Colors.GREEN}running{Colors.NC}")
    else:
        print(f"  Container: {Colors.YELLOW}not running{Colors.NC}")

    print("  Changes:")
    for src_path, size in status["changes"].items():
        print(f"    {src_path}: {size}")

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all boqs."""
    boqs = list_boqs(show_size=args.size)

    if not boqs:
        log_info("No boq instances found")
        print("Create one with: boq create <name>")
        return 0

    has_rootless = any(b.get("container_type") == "podman-rootless" for b in boqs)
    if has_rootless:
        log_warn("Some boqs are running in legacy rootless mode (no host network access).")
        print(f"  Run 'boq stop <name>' then 'boq enter <name>' to upgrade.")
        print(f"  Upgraded boqs get a static IP reachable from host (e.g. curl boq-<name>:8080).")
        print()

    print(f"{Colors.BLUE}Boq instances:{Colors.NC}")
    rows = []
    for b in boqs:
        boq_name = b["name"]
        container_name = f"boq-{boq_name}"
        ip = b.get("ip") or "-"
        container_type = b.get("container_type", "unknown")
        mode = "sudo" if b.get("use_sudo") else "direct"
        if b["running"]:
            status = "RUNNING/rootless" if container_type == "podman-rootless" else "RUNNING"
        elif b["mounted"]:
            status = "MOUNTED"
        else:
            status = "STOPPED"
        if status == "RUNNING":
            status_colored = f"{Colors.GREEN}{status}{Colors.NC}"
        else:
            status_colored = f"{Colors.YELLOW}{status}{Colors.NC}"

        rows.append({
            "boq_name": boq_name,
            "container_host": container_name,
            "ip": ip,
            "container_type": container_type,
            "mode": mode,
            "status": status,
            "status_colored": status_colored,
            "size": format_size(b["size"]) if args.size else "",
        })

    boq_name_w = max(len("Boq Name"), *(len(r["boq_name"]) for r in rows))
    container_host_w = max(len("Container Name/Hostname"), *(len(r["container_host"]) for r in rows))
    ip_w = max(len("IP"), *(len(r["ip"]) for r in rows))
    type_w = max(len("Container Type"), *(len(r["container_type"]) for r in rows))
    mode_w = max(len("Mode"), *(len(r["mode"]) for r in rows))
    status_w = max(len("Status"), *(len(r["status"]) for r in rows))
    size_w = max(len("Changes"), *(len(r["size"]) for r in rows)) if args.size else 0

    header_parts = [
        f"{'Boq Name':<{boq_name_w}}",
        f"{'Container Name/Hostname':<{container_host_w}}",
        f"{'IP':<{ip_w}}",
        f"{'Container Type':<{type_w}}",
        f"{'Mode':<{mode_w}}",
    ]
    if args.size:
        header_parts.append(f"{'Changes':<{size_w}}")
    header_parts.append(f"{'Status':<{status_w}}")
    header = "  " + "  ".join(header_parts)
    print(header)
    print("  " + "-" * (len(header) - 2))

    for r in rows:
        line_parts = [
            f"{r['boq_name']:<{boq_name_w}}",
            f"{r['container_host']:<{container_host_w}}",
            f"{r['ip']:<{ip_w}}",
            f"{r['container_type']:<{type_w}}",
            f"{r['mode']:<{mode_w}}",
        ]
        if args.size:
            line_parts.append(f"{r['size']:<{size_w}}")
        line_parts.append(r["status_colored"])
        print("  " + "  ".join(line_parts))

    return 0


BASH_COMPLETION = r'''
_boq_completions() {
    local cur prev commands boq_root
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    boq_root="$HOME/.boq"

    commands="create enter run stop destroy diff status list completion --help"

    case "$prev" in
        boq|*/boq)
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            return 0
            ;;
        enter)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--migrate-to-docker" -- "$cur") )
            elif [[ -d "$boq_root" ]]; then
                local boqs=""
                for dir in "$boq_root"/*/; do
                    [[ -d "$dir" ]] || continue
                    local name=$(basename "$dir")
                    [[ -d "$dir/home" || -d "$dir/usr" || -d "$dir/opt" ]] && boqs="$boqs $name"
                done
                COMPREPLY=( $(compgen -W "$boqs" -- "$cur") )
            fi
            return 0
            ;;
        stop|destroy|diff|status|run)
            if [[ -d "$boq_root" ]]; then
                local boqs=""
                for dir in "$boq_root"/*/; do
                    [[ -d "$dir" ]] || continue
                    local name=$(basename "$dir")
                    [[ -d "$dir/home" || -d "$dir/usr" || -d "$dir/opt" ]] && boqs="$boqs $name"
                done
                COMPREPLY=( $(compgen -W "$boqs" -- "$cur") )
            fi
            return 0
            ;;
        create)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--no-enter --runtime --docker-sudo --no-docker-sudo" -- "$cur") )
            else
                COMPREPLY=()
                compopt +o default 2>/dev/null
            fi
            return 0
            ;;
        --runtime)
            COMPREPLY=( $(compgen -W "docker podman" -- "$cur") )
            return 0
            ;;
        list)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--size" -- "$cur") )
            fi
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
            return 0
            ;;
        -s)
            COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
            return 0
            ;;
    esac

    local cmd=""
    for word in "${COMP_WORDS[@]}"; do
        case "$word" in
            create|enter|run|stop|destroy|diff|status|list|completion)
                cmd="$word"
                break
                ;;
        esac
    done

    case "$cmd" in
        create)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--no-enter --runtime --docker-sudo --no-docker-sudo" -- "$cur") )
            fi
            ;;
        enter)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--migrate-to-docker" -- "$cur") )
            fi
            ;;
        destroy)
            COMPREPLY=()
            compopt +o default 2>/dev/null
            ;;
        diff)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--no-gitignore --include-metadata" -- "$cur") )
            fi
            ;;
        completion)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-s" -- "$cur") )
            fi
            ;;
    esac

    return 0
}

complete -F _boq_completions boq
'''


def cmd_completion(args: argparse.Namespace) -> int:
    """Output shell completion script."""
    shell = args.shell

    if shell == "bash":
        print(BASH_COMPLETION.strip())
        if sys.stderr.isatty():
            print(f'# Add to ~/.bashrc:\n#   eval "$(boq completion -s bash)"', file=sys.stderr)
    elif shell == "zsh":
        # Zsh can use bash completion with bashcompinit
        print("autoload -U +X bashcompinit && bashcompinit")
        print(BASH_COMPLETION.strip())
        if sys.stderr.isatty():
            print(f'# Add to ~/.zshrc:\n#   eval "$(boq completion -s zsh)"', file=sys.stderr)
    else:
        log_error(f"Unsupported shell: {shell}")
        print("Supported shells: bash, zsh")
        return 1

    return 0


def main() -> int:
    """Main entry point."""
    # Check if running inside a boq container
    inside_boq, _ = detect_inside_boq()
    if inside_boq:
        log_error("Cannot run boq inside a boq container")
        print("Hint: exit the current boq first, then run boq commands on the host.")
        return 1

    # Check dependencies
    missing = check_dependencies()
    if missing:
        if "podman-or-docker" in missing:
            other_missing = [m for m in missing if m != "podman-or-docker"]
            if other_missing:
                log_error(f"Missing dependencies: {', '.join(other_missing)}, and one of podman/docker")
                print(f"Install with: sudo apt install {' '.join(other_missing)} podman")
                print("Or use docker instead of podman.")
            else:
                log_error("Missing container runtime: install podman or docker")
                print("Install with: sudo apt install podman")
                print("Or: sudo apt install docker.io")
        else:
            log_error(f"Missing dependencies: {', '.join(missing)}")
            print(f"Install with: sudo apt install {' '.join(missing)}")
        return 1

    parser = argparse.ArgumentParser(
        prog="boq",
        description="Universal isolated development environment.",
        epilog="""
Examples:
  boq create dev          # Create boq and enter it
  boq create dev --runtime docker          # Create boq with docker backend
  boq create dev --runtime docker --docker-sudo  # Use sudo docker backend
  boq create dev --no-enter  # Create boq without entering
  boq enter dev           # Re-enter existing boq
  boq enter dev --migrate-to-docker  # Migrate stopped boq to docker backend
  boq run dev "make"      # Run command in boq
  boq diff dev            # See what changed
  boq diff dev ~/project  # See changes in ~/project only
  boq stop dev            # Stop boq
  boq destroy dev         # Remove boq
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # create
    p = subparsers.add_parser("create", help="Create a new boq and enter it")
    p.add_argument("name", help="Boq name")
    p.add_argument("--no-enter", dest="enter", action="store_false",
                   help="Don't enter the boq after creating (default: enter)")
    p.add_argument(
        "--runtime",
        choices=["docker", "podman"],
        help="Container runtime for this boq (default: auto prefers docker, falls back to podman)",
    )
    p.add_argument(
        "--docker-sudo",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Use sudo for docker commands (docker runtime only)",
    )
    p.set_defaults(func=cmd_create, enter=True)

    # enter
    p = subparsers.add_parser("enter", help="Attach shell to boq (starts if not running)")
    p.add_argument("name", nargs="?", default="default", help="Boq name (default: default)")
    p.add_argument(
        "--migrate-to-docker",
        action="store_true",
        help="If stopped, migrate this boq from podman runtime to docker",
    )
    p.set_defaults(func=cmd_enter)

    # run
    p = subparsers.add_parser("run", help="Run a command in boq (must be running; may be interrupted by stop/destroy)")
    p.add_argument("name", help="Boq name")
    p.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")
    p.set_defaults(func=cmd_run)

    # stop
    p = subparsers.add_parser("stop", help="Stop a boq immediately (may interrupt sessions)")
    p.add_argument("name", nargs="?", default="default", help="Boq name (default: default)")
    p.set_defaults(func=cmd_stop)

    # destroy
    p = subparsers.add_parser("destroy", help="Destroy a boq immediately (may interrupt sessions)")
    p.add_argument("name", help="Boq name")
    p.add_argument("--force-stop", action="store_true", help=argparse.SUPPRESS)  # no-op, kept for compat
    p.set_defaults(func=cmd_destroy)

    # diff
    p = subparsers.add_parser("diff", help="Show changes made in boq")
    p.add_argument("name", nargs="?", default="default", help="Boq name (default: default)")
    p.add_argument("path", nargs="?", help="Filter by path")
    p.add_argument("--no-gitignore", action="store_true", help="Include files ignored by .gitignore")
    p.add_argument("--include-metadata", action="store_true", help="Include files with only metadata changes")
    p.set_defaults(func=cmd_diff)

    # status
    p = subparsers.add_parser("status", help="Show boq status")
    p.add_argument("name", nargs="?", default="default", help="Boq name (default: default)")
    p.set_defaults(func=cmd_status)

    # list
    p = subparsers.add_parser("list", help="List all boq instances")
    p.add_argument("--size", action="store_true", help="Show disk usage for each boq (slower)")
    p.set_defaults(func=cmd_list)

    # completion
    p = subparsers.add_parser("completion", help="Output shell completion script")
    p.add_argument("-s", dest="shell", default="bash", choices=["bash", "zsh"],
                   help="Shell type (default: bash)")
    p.set_defaults(func=cmd_completion)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
