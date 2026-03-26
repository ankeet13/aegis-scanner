"""
AEGIS Scanner — Payload Manager
Loads attack payloads from text files at runtime.
Each scanner requests its relevant payload set by name.
"""

import json
import os
from backend.config import PAYLOAD_FILES


class PayloadManager:
    """
    Loads and caches payload sets from the /payloads directory.
    Payloads are stored one-per-line in .txt files, or as JSON.
    """

    _cache = {}

    @classmethod
    def load(cls, payload_name):
        """
        Load a payload set by name.

        Args:
            payload_name: Key from config.PAYLOAD_FILES
                          e.g. 'sqli_error', 'common_creds', 'sensitive_paths'

        Returns:
            list of payload strings (or dict for JSON files)
        """
        if payload_name in cls._cache:
            return cls._cache[payload_name]

        file_path = PAYLOAD_FILES.get(payload_name)
        if not file_path:
            raise ValueError(f"Unknown payload set: {payload_name}")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Payload file not found: {file_path}")

        if file_path.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)
                cls._cache[payload_name] = data
                return data
        else:
            with open(file_path, "r") as f:
                lines = [
                    line.strip()
                    for line in f.readlines()
                    if line.strip() and not line.startswith("#")
                ]
                cls._cache[payload_name] = lines
                return lines

    @classmethod
    def clear_cache(cls):
        """Clear the payload cache (useful for testing)."""
        cls._cache = {}

    @classmethod
    def get_sqli_error_payloads(cls):
        return cls.load("sqli_error")

    @classmethod
    def get_sqli_blind_payloads(cls):
        return cls.load("sqli_blind")

    @classmethod
    def get_sqli_time_payloads(cls):
        return cls.load("sqli_time")

    @classmethod
    def get_common_credentials(cls):
        """Returns list of 'username:password' strings."""
        return cls.load("common_creds")

    @classmethod
    def get_sensitive_paths(cls):
        return cls.load("sensitive_paths")

    @classmethod
    def get_security_headers_config(cls):
        """Returns dict of expected headers and descriptions."""
        return cls.load("security_headers")