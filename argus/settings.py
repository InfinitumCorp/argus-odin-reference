"""Persisted program options. Geo-routing is off unless an operator turns it on."""

import json
from pathlib import Path

_TRUE = {"1", "true", "on", "yes"}
_FALSE = {"0", "false", "off", "no"}


def _as_bool(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().casefold()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    raise ValueError(f"{name} must be on or off")


def load_settings(path):
    """Return saved options. A missing file stays at the defaults and is not created."""
    path = Path(path)
    if not path.exists():
        return {"geo_routing": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read settings {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("settings must be a JSON object")
    if "geo_routing" not in data:
        enabled = False
    else:
        enabled = _as_bool(data.get("geo_routing"), "geo_routing")
    return {"geo_routing": enabled}


def save_settings(path, settings):
    path = Path(path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"geo_routing": bool(settings.get("geo_routing", False))}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def env_geo_override(environ):
    """Return True/False when INFINITUM_GEO_ENABLED is set, else None."""
    if "INFINITUM_GEO_ENABLED" not in environ:
        return None
    raw = environ.get("INFINITUM_GEO_ENABLED", "")
    if raw is None or str(raw).strip() == "":
        return None
    return _as_bool(str(raw), "INFINITUM_GEO_ENABLED")


def resolve_geo_enabled(environ, settings, cli=None):
    """CLI flag wins, then INFINITUM_GEO_ENABLED, then the persisted toggle. Default off."""
    if cli is not None:
        return bool(cli)
    override = env_geo_override(environ)
    if override is not None:
        return override
    return bool(settings.get("geo_routing", False))
