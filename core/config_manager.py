"""
NetPacket Inspector - Persistent Configuration Manager
Stores and retrieves user settings such as VirusTotal API key so it is entered only once.
"""

import json
import os
from typing import Dict, Any

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inspector_config.json")


class ConfigManager:
    """Manages persistent application settings."""

    @staticmethod
    def load_config() -> Dict[str, Any]:
        """Load settings from JSON file."""
        if not os.path.exists(CONFIG_FILE):
            return {"virustotal_api_key": "", "theme": "dark"}
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"virustotal_api_key": "", "theme": "dark"}

    @staticmethod
    def save_config(config: Dict[str, Any]):
        """Save settings to JSON file."""
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"[-] Could not save configuration: {e}")

    @classmethod
    def get_vt_api_key(cls) -> str:
        """Get saved VirusTotal API key."""
        config = cls.load_config()
        return config.get("virustotal_api_key", "")

    @classmethod
    def set_vt_api_key(cls, api_key: str):
        """Save VirusTotal API key persistently."""
        config = cls.load_config()
        config["virustotal_api_key"] = api_key.strip()
        cls.save_config(config)
