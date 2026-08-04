#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration Manager - Singleton
Stores and retrieves application settings using configparser with encrypted secrets.
"""

import os
import base64
import configparser
import logging
from pathlib import Path
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


class ConfigManager:
    """Singleton configuration manager with encrypted secrets storage."""
    _instance = None
    _config_dir = Path.home() / ".aimas"
    _config_file = _config_dir / "config.ini"
    _key = None  # encryption key derived from machine ID (or fallback)

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        """Initialize config directory, load or create config file."""
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._config = configparser.ConfigParser()
        self._load_encryption_key()
        if not self._config_file.exists():
            self._create_default_config()
        self._config.read(self._config_file)

    def _load_encryption_key(self):
        """Derive encryption key from machine ID (or generate fallback)."""
        key_file = self._config_dir / ".key"
        if key_file.exists():
            self._key = key_file.read_bytes()
        else:
            # Use system machine-id if available, else generate random key
            try:
                machine_id = Path("/etc/machine-id").read_text().strip()
                salt = b"aimas_salt_2024"
                self._key = PBKDF2(machine_id.encode(), salt, dkLen=32, count=100000)
            except:
                self._key = get_random_bytes(32)
            key_file.write_bytes(self._key)

    def _create_default_config(self):
        """Create default configuration with empty sections."""
        self._config["General"] = {"last_project": "", "theme": "dark"}
        self._config["API"] = {"hibp_key": "", "openai_key": "", "ngrok_token": ""}
        self._config["AI"] = {"backend": "ollama", "ollama_model": "mistral",
                              "ollama_url": "http://localhost:11434"}
        self._config["Export"] = {"default_format": "html", "output_dir": "~/aimas_exports"}
        self._save()

    def _save(self):
        """Write config to disk."""
        with open(self._config_file, "w") as f:
            self._config.write(f)

    def _encrypt(self, plain: str) -> str:
        """Encrypt a string using AES-256-GCM, return base64."""
        if not plain:
            return ""
        cipher = AES.new(self._key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plain.encode())
        # Store nonce + tag + ciphertext
        data = cipher.nonce + tag + ciphertext
        return base64.b64encode(data).decode()

    def _decrypt(self, encrypted_b64: str) -> str:
        """Decrypt base64 string using AES-256-GCM, return plaintext."""
        if not encrypted_b64:
            return ""
        data = base64.b64decode(encrypted_b64)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ciphertext, tag)
        return plain.decode()

    def get(self, section: str, key: str, fallback: str = "") -> str:
        """Get plaintext value from config."""
        try:
            return self._config.get(section, key, fallback=fallback)
        except:
            return fallback

    def set(self, section: str, key: str, value: str):
        """Set plaintext value and save."""
        if not self._config.has_section(section):
            self._config.add_section(section)
        self._config.set(section, key, value)
        self._save()

    def get_secret(self, key: str) -> str:
        """Get decrypted secret from [API] section."""
        encrypted = self.get("API", key, "")
        return self._decrypt(encrypted)

    def set_secret(self, key: str, value: str):
        """Encrypt and store secret in [API] section."""
        encrypted = self._encrypt(value)
        self.set("API", key, encrypted)

    def save(self):
        self._save()
