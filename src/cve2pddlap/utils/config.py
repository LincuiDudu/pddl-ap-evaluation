"""
Configuration management.
Loads settings from TOML (Python 3.11+ tomllib, or tomli fallback)
and API keys from environment / .env file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

# Project root: cve2pddlap/
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Load .env
load_dotenv(PROJECT_ROOT / ".env")

# Load TOML settings
_settings_path = PROJECT_ROOT / "resources" / "configs" / "settings.toml"
with open(_settings_path, "rb") as f:
    _raw = tomllib.load(f)

# Flatten: use "default" environment
settings = _raw.get("default", _raw)


class Settings:
    """Dot-access wrapper over nested dict."""

    def __init__(self, data: dict):
        self._data = data

    def __getattr__(self, key: str):
        try:
            val = self._data[key]
        except KeyError:
            raise AttributeError(f"No setting: {key}")
        if isinstance(val, dict):
            return Settings(val)
        return val

    def get(self, dotted_key: str, default=None):
        """Access nested keys with dot notation, e.g. 'LLM.models.deepseek'."""
        parts = dotted_key.split(".")
        current = self._data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def __repr__(self):
        return f"Settings({list(self._data.keys())})"


settings = Settings(settings)


def get_api_key(provider: str) -> str:
    """Get API key for a provider from environment variables."""
    key_map = {
        "gemini": "GOOGLE_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "qwen": "QWEN_API_KEY",
        "zhipu": "ZHIPU_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "gpt4": "OPENAI_API_KEY",
    }
    env_var = key_map.get(provider)
    if not env_var:
        raise ValueError(f"Unknown provider: {provider}")
    key = os.getenv(env_var)
    if not key:
        raise ValueError(f"API key not set: {env_var}")
    return key
