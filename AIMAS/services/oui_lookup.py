#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OUI Lookup Service - Singleton
Loads MAC vendor database from CSV and provides lookup.
"""

import csv
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class OUILookup:
    _instance = None
    _oui_db = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_db()
        return cls._instance

    def _load_db(self):
        self._oui_db = {}
        db_path = Path(__file__).parent.parent / "data" / "oui_database.csv"
        if not db_path.exists():
            self._create_sample_db(db_path)
        try:
            with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        prefix = row[0].strip().replace(':', '').replace('-', '').upper()
                        vendor = row[1].strip()
                        if prefix and len(prefix) == 6:
                            self._oui_db[prefix] = vendor
        except Exception as e:
            logger.error(f"Error loading OUI DB: {e}")

    def _create_sample_db(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        sample = """00:00:0C,Cisco
00:11:22,Intel
00:1A:2B,Samsung
00:1C:42,Realtek
00:1E:37,Apple
00:24:7E,Dell
00:50:56,VMware
08:00:27,Oracle
00:0C:29,VMware
00:15:5D,Microsoft
00:1A:6B,TP-Link
00:25:9C,Atheros
"""
        db_path.write_text(sample)
        logger.info(f"Created sample OUI database at {db_path}")

    def lookup(self, mac: str) -> str:
        """Normalize MAC and return vendor name or 'Unknown'."""
        if not mac:
            return "Unknown"
        # Normalize: remove separators, uppercase
        prefix = mac.upper().replace(':', '').replace('-', '').replace('.', '')[:6]
        if len(prefix) != 6:
            return "Unknown"
        return self._oui_db.get(prefix, "Unknown")
