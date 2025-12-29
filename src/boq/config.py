"""
Configuration system for boq tool.

3-tier configuration:
1. defaults.toml (shipped with code)
2. ~/.boq/config.toml (user global)
3. ~/.boq/<name>/config.toml (per-boq)

Higher priority overrides lower. Lists append by default, use `<key>_replace` to fully replace.
"""

import os
import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any


def _expand_string(s: str, env: dict[str, str]) -> str:
    """Expand environment variables in a single string."""
    import re
    # Expand ${VAR} format first
    result = s
    for key, val in env.items():
        result = result.replace(f"${{{key}}}", val)
    # Then $VAR format (only word characters after $)
    def replace_var(match):
        var_name = match.group(1)
        return env.get(var_name, match.group(0))
    result = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', replace_var, result)
    return result


def expand_vars(value: Any, env: dict[str, str] | None = None) -> Any:
    """Expand environment variables in strings ($VAR or ${VAR} format).

    Also expands keys in dictionaries (for overlays config where keys are paths).
    """
    if env is None:
        env = dict(os.environ)

    if isinstance(value, str):
        return _expand_string(value, env)
    elif isinstance(value, dict):
        # Expand both keys and values
        return {_expand_string(k, env): expand_vars(v, env) for k, v in value.items()}
    elif isinstance(value, list):
        return [expand_vars(item, env) for item in value]
    return value


def deep_merge(base: dict, override: dict) -> dict:
    """
    Deep merge two dictionaries.

    Rules:
    - Scalar values: override replaces base
    - Dicts: recursive merge
    - Lists: override appends to base (use `<key>_replace` to fully replace)
    """
    result = base.copy()

    for key, value in override.items():
        # Check for _replace suffix
        if key.endswith("_replace"):
            actual_key = key[:-8]  # Remove "_replace" suffix
            result[actual_key] = value
            continue

        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge(result[key], value)
            elif isinstance(result[key], list) and isinstance(value, list):
                result[key] = result[key] + value  # Append
            else:
                result[key] = value  # Override
        else:
            result[key] = value

    return result


def load_toml(path: Path) -> dict:
    """Load TOML file, return empty dict if not exists."""
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


class Config:
    """Boq configuration manager."""

    def __init__(self, boq_root: Path | None = None, boq_name: str | None = None):
        self.boq_root = boq_root or Path(os.environ.get("BOQ_ROOT", Path.home() / ".boq"))
        self.boq_name = boq_name
        self._config: dict = {}
        self._load()

    def _load(self):
        """Load and merge all configuration tiers."""
        # Tier 1: defaults.toml (shipped with code)
        defaults_file = files("boq").joinpath("defaults.toml")
        with defaults_file.open("rb") as f:
            defaults = tomllib.load(f)

        # Tier 2: user global config
        user_config_path = self.boq_root / "config.toml"
        user_config = load_toml(user_config_path)

        # Tier 3: per-boq config (if boq_name provided)
        boq_config = {}
        if self.boq_name:
            boq_config_path = self.boq_root / self.boq_name / "config.toml"
            boq_config = load_toml(boq_config_path)

        # Merge all tiers
        self._config = deep_merge(defaults, user_config)
        if boq_config:
            self._config = deep_merge(self._config, boq_config)

        # Expand environment variables
        self._config = expand_vars(self._config)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get config value by dot-separated key path.

        Example: config.get("container.image")
        """
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def __getitem__(self, key: str) -> Any:
        """Get top-level config section."""
        return self._config.get(key, {})

    @property
    def container(self) -> dict:
        """Container configuration."""
        return self._config.get("container", {})

    @property
    def overlays(self) -> dict[str, str]:
        """Overlay directories mapping (source_path -> overlay_name)."""
        return self._config.get("overlays", {})

    @property
    def passthrough_paths(self) -> list[str]:
        """Passthrough paths (bypass overlay)."""
        return self._config.get("passthrough", {}).get("paths", [])

    @property
    def mounts(self) -> dict:
        """Mount configuration."""
        return self._config.get("mounts", {})

    @property
    def readonly_mounts(self) -> list[str]:
        """Read-only bind mounts."""
        return self.mounts.get("readonly", [])

    @property
    def direct_mounts(self) -> list[str]:
        """Direct read-write mounts (bypass overlay)."""
        return self.mounts.get("direct", [])

    @property
    def etc_files(self) -> list[str]:
        """Files from /etc to mount."""
        return self.mounts.get("etc_files", [])

    @property
    def dns_resolv(self) -> str:
        """DNS resolver config file path."""
        return self.mounts.get("dns_resolv", "/etc/resolv.conf")

    def dump(self) -> dict:
        """Return the full merged configuration."""
        return self._config.copy()
