#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Manager - Singleton
Handles global and per-project SQLite databases with WAL mode.
Creates all tables as defined in PRD Section 7 (without triggers on virtual tables).
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class Database:
    """Singleton database manager for global and project databases."""
    _instance = None
    _global_db_path = Path.home() / ".aimas" / "aimas_global.db"
    _projects_root = Path.home() / ".aimas" / "projects"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        """Ensure directories exist and initialize global database."""
        self._global_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._projects_root.mkdir(parents=True, exist_ok=True)
        self._initialize_global_db()

    def get_global_conn(self) -> sqlite3.Connection:
        """Return connection to global database with WAL mode."""
        conn = sqlite3.connect(self._global_db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def get_project_conn(self, project_name: str) -> sqlite3.Connection:
        """
        Return connection to project database.
        Creates the project directory and database if not exists.
        """
        project_dir = self._projects_root / project_name
        project_dir.mkdir(parents=True, exist_ok=True)
        db_path = project_dir / "project.db"
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        self._initialize_project_db(conn)
        return conn

    def _initialize_global_db(self):
        """Create global tables if they don't exist (no triggers on virtual tables)."""
        with self.get_global_conn() as conn:
            # Projects table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL
                )
            """)
            # Settings table (key-value)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    encrypted INTEGER DEFAULT 0
                )
            """)
            # Global notes with FTS5 full-text search (virtual table, no triggers)
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS global_notes USING fts5(
                    id UNINDEXED,
                    title,
                    content,
                    tags,
                    created_at UNINDEXED,
                    updated_at UNINDEXED,
                    encrypted UNINDEXED
                )
            """)
            # Phishing campaigns (global for now, but could be project-specific in future)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS phishing_campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    template TEXT,
                    redirect_url TEXT,
                    port INTEGER,
                    public_url TEXT,
                    started_at DATETIME,
                    ended_at DATETIME,
                    cred_count INTEGER DEFAULT 0
                )
            """)
            # Captured credentials
            conn.execute("""
                CREATE TABLE IF NOT EXISTS captured_creds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL,
                    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    client_ip TEXT,
                    user_agent TEXT,
                    data_json TEXT,
                    FOREIGN KEY(campaign_id) REFERENCES phishing_campaigns(id)
                )
            """)
            conn.commit()

    def _initialize_project_db(self, conn: sqlite3.Connection):
        """Create per-project tables if they don't exist (no triggers on virtual tables)."""
        # Scans table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                target TEXT,
                flags TEXT,
                raw_output TEXT,
                parsed_json TEXT,
                status TEXT,
                started_at DATETIME,
                finished_at DATETIME
            )
        """)
        # Open ports (from network radar)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)
        # Vulnerabilities
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vuln_type TEXT,
                parameter TEXT,
                severity TEXT,
                evidence TEXT,
                suggestion TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)
        # OSINT results
        conn.execute("""
            CREATE TABLE IF NOT EXISTS osint_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                osint_type TEXT,
                target TEXT,
                result_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Project notes with FTS5 (virtual table, no triggers)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS project_notes USING fts5(
                id UNINDEXED,
                title,
                content,
                tags,
                encrypted UNINDEXED,
                created_at UNINDEXED
            )
        """)
        conn.commit()
