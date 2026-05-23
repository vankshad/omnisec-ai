"""Helper functions."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse


def load_config(path: str) -> dict:
    """Load configuration from JSON/env file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {path}")

    if config_path.suffix == ".json":
        return json.loads(config_path.read_text())
    elif config_path.suffix in (".env",):
        config = {}
        for line in config_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip().strip("\"'")
        return config
    else:
        raise ValueError(f"Unsupported config format: {config_path.suffix}")


def validate_target(target: str) -> str:
    """Validate and normalize target URL/domain."""
    # Add scheme if missing
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    if not parsed.hostname:
        raise ValueError(f"Invalid target: {target}")

    # Basic validation
    hostname = parsed.hostname
    if not re.match(r"^[\w\.\-\*]+$", hostname):
        raise ValueError(f"Invalid hostname: {hostname}")

    return target


def severity_color(severity: str) -> str:
    """Return emoji for severity level."""
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity, "⚪")


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"
