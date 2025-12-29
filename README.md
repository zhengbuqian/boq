# boq

Isolated development environment using Linux kernel overlayfs.

## Why boq?

`boq` allows:

* You to use `yolo` or `--dangerously-skip-permissions` mode without worrying about AI screwing up your Linux system.
* You to instantly create an isolated environment that runs exactly like your familiar system.
    * All your familiar commands and AI tools ready to use - no need to re-install, login, authenticate, or configure.
    * Zero learning curve - same shell, same muscle memory, same dotfiles. It just feels like home.
    * Full access to your entire `$HOME` - all your projects, references, and personal scripts. Not trapped in a single project directory.
    * Your existing compilers, interpreters, and build cache ready to use - no re-downloading, no re-building.
* You to run multiple isolated environments simultaneously (`dev`, `experiment`, `feature-x`) - each with independent file changes, but sharing the same build toolchain.
* You to let multiple AI agents work in parallel on the same project, each in its own isolated environment.
* You to experiment fearlessly - don't like the result? `boq destroy` and start fresh. No leftover config files, broken dependencies, or system pollution.
* No Dockerfile to write, no image to build, instant start.

> **Note:** Files unchanged by boq are read from the host in real-time. If you `git pull` on the host, unmodified files will update inside the boq. Best practice: keep host files untouched while AI is working, and sync periodically.

## Features

- Configurable overlay directories (default: `$HOME`, `/usr`, `/opt`, `/home/linuxbrew`)
- Passthrough paths that bypass overlay and share with host
- Full file locking support (unlike fuse-overlayfs)
- TOML-based configuration with 3-tier override system

## Installation

Requires Python 3.11+ and podman.

```bash
# Install podman
sudo apt install podman

# Install boq (choose one)
pipx install boq          # Recommended: isolated global install
uv tool install boq       # Alternative: using uv
pip install boq           # Or: install to current environment

# For development
git clone <repo>
cd boq
uv pip install -e .               # Editable install
```

**Note:** Requires sudo for mounting kernel overlayfs.

## Quick Start

```bash
# Create a boq and enter it (exit shell to detach, container keeps running)
boq create dev

# Re-enter existing boq
boq enter dev

# See what changed
boq diff dev

# Run a command in boq
boq run dev "make test"

# Stop boq
boq stop dev

# Remove boq
boq destroy dev
```

## Commands

| Command | Description |
|---------|-------------|
| `create <name>` | Create a new boq and enter it (use `--no-enter` to skip) |
| `enter [name]` | Attach shell to boq (starts if not running) |
| `run <name> <cmd>` | Run a command in boq (must be running) |
| `stop [name]` | Stop a running boq |
| `destroy <name>` | Destroy a boq (fails if running, use `--force-stop`) |
| `diff [name] [path]` | Show changes made in boq |
| `status [name]` | Show boq status |
| `list` | List all boq instances |
| `completion -s <shell>` | Output shell completion script |

Default name is `default` for commands that accept `[name]`.

### diff options

```bash
boq diff dev                      # Show all content changes
boq diff dev ~/project            # Filter by path (respects .gitignore)
boq diff dev --no-gitignore       # Include gitignored files
boq diff dev --include-metadata   # Include metadata-only changes
```

## Shell Completion

```bash
# Bash: add to ~/.bashrc
eval "$(boq completion -s bash)"

# Zsh: add to ~/.zshrc
eval "$(boq completion -s zsh)"
```

## Configuration

TOML-based configuration with 3-tier override system:

1. **defaults.toml** (shipped with package) - base defaults
2. **~/.boq/config.toml** (user global) - override defaults
3. **~/.boq/`<name>`/config.toml** (per-boq) - override for specific boq

Higher priority overrides lower. Lists append by default (use `<key>_replace` to fully replace).

### Example ~/.boq/config.toml

```toml
[container]
# Change default shell
shell = "/bin/zsh"

# Change base image
image = "ubuntu:24.04"

[container.env]
# Add custom environment variables
MY_VAR = "value"

[overlays]
# Add additional overlay directory
"/data" = "data"

[passthrough]
# Add paths that bypass overlay (appends to default list)
paths = [
    "$HOME/.my-tool",
]

# Or replace the entire list
paths_replace = [
    "$HOME/.zsh_history",
    "$HOME/.claude",
]
```

### Default Configuration

```toml
[container]
image = "ubuntu:22.04"
shell = "/bin/bash"
capabilities = ["SYS_PTRACE"]

[overlays]
"$HOME" = "home"
"/usr" = "usr"
"/opt" = "opt"
"/home/linuxbrew" = "linuxbrew"

[passthrough]
paths = [
    "$HOME/.zsh_history",
    "$HOME/.bash_history",
    "$HOME/.claude",
    "$HOME/.gemini",
    "$HOME/.codex",
    "$HOME/.factory",
]

[mounts]
readonly = ["/bin", "/lib", "/lib64", "/lib32", "/sbin"]
direct = []
```

Environment variable expansion (`$HOME`, `$USER`, etc.) is supported in all string values.

## How It Works

- `create` sets up overlays, starts container, and enters shell (use `--no-enter` to skip)
- `enter` attaches a shell; exiting detaches but container stays running
- `run` executes a single command (container must be running)
- `stop` explicitly stops container and unmounts overlays
- Container manages its own `/proc`, `/sys`, `/dev`, `/tmp`

### Overlay Directories

Multiple directories are overlayed (copy-on-write) using kernel overlayfs. Changes are stored in `~/.boq/<name>/<overlay>/upper/`.

### Read-only Mounts

- `/bin`, `/lib`, `/lib64`, `/lib32`, `/sbin` - essential system directories, read-only from host

## Known Limitations

### Host file changes visible in running boq

**Symptom:** If you run `git pull` on the host while boq is running, new files appear inside the boq.

**Cause:** Overlayfs lowerdir is live, not a snapshot.

**Workaround:** Do NOT modify files on the host while boq is running.
- To update code: run `git pull` inside the boq, OR
- Stop the boq first, update on host, then re-enter

## Troubleshooting

### DNS resolution fails inside container

**Error:** "Temporary failure in name resolution"

**Cause:** systemd-resolved uses a stub resolver at 127.0.0.53 which doesn't work inside the container.

**Solution:** This tool mounts `/run/systemd/resolve/resolv.conf` (with actual upstream DNS servers) as `/etc/resolv.conf`. If your system uses a different DNS setup, override `dns_resolv` in config.

## Design Notes

**Why kernel overlayfs instead of fuse-overlayfs?**
- fuse-overlayfs mounts are only accessible by the user who created them (permission issues with podman)
- fuse-overlayfs doesn't fully support POSIX file locking
- Kernel overlayfs requires sudo but provides full compatibility
