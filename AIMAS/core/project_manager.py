#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project Manager - Singleton
Manages projects: create, open, save results, list, delete.
Uses Database class for storage.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from core.database import Database

logger = logging.getLogger(__name__)

@dataclass
class Project:
    name: str
    description: str
    path: Path
    db_path: Path
    created_at: datetime


class ProjectManager:
    """Singleton project manager."""
    _instance = None
    _active_project: Optional[Project] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.db = Database()
        self._load_last_project()

    def _load_last_project(self):
        """Load last opened project from settings (if any)."""
        try:
            with self.db.get_global_conn() as conn:
                row = conn.execute("SELECT value FROM settings WHERE key = 'last_project'").fetchone()
                if row and row['value']:
                    self.open_project(row['value'])
        except Exception as e:
            logger.warning(f"Could not load last project: {e}")

    def create_project(self, name: str, description: str = "") -> Project:
        """Create a new project, returns Project object."""
        # Check if project already exists
        with self.db.get_global_conn() as conn:
            existing = conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()
            if existing:
                raise ValueError(f"Project '{name}' already exists")
            # Insert into global projects table
            projects_dir = Path.home() / ".aimas" / "projects" / name
            projects_dir.mkdir(parents=True, exist_ok=True)
            db_path = projects_dir / "project.db"
            conn.execute(
                "INSERT INTO projects (name, description, path) VALUES (?, ?, ?)",
                (name, description, str(projects_dir))
            )
            conn.commit()
        # Initialize project database tables
        self.db.get_project_conn(name)  # this creates tables
        proj = Project(name=name, description=description, path=projects_dir,
                       db_path=db_path, created_at=datetime.now())
        self._active_project = proj
        # Save as last project
        self._save_last_project(name)
        return proj

    def open_project(self, name: str) -> Optional[Project]:
        """Open existing project by name."""
        with self.db.get_global_conn() as conn:
            row = conn.execute(
                "SELECT name, description, path, created_at FROM projects WHERE name = ?",
                (name,)
            ).fetchone()
            if not row:
                logger.error(f"Project {name} not found")
                return None
            proj = Project(
                name=row['name'],
                description=row['description'],
                path=Path(row['path']),
                db_path=Path(row['path']) / "project.db",
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else datetime.now()
            )
            self._active_project = proj
            self._save_last_project(name)
            return proj

    def _save_last_project(self, name: str):
        """Store last project name in global settings."""
        with self.db.get_global_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value, encrypted) VALUES (?, ?, 0)",
                ("last_project", name)
            )
            conn.commit()

    def get_active_project(self) -> Optional[Project]:
        return self._active_project

    def list_projects(self) -> List[Project]:
        """Return list of all projects."""
        projects = []
        with self.db.get_global_conn() as conn:
            rows = conn.execute("SELECT name, description, path, created_at FROM projects ORDER BY created_at DESC").fetchall()
            for row in rows:
                projects.append(Project(
                    name=row['name'],
                    description=row['description'],
                    path=Path(row['path']),
                    db_path=Path(row['path']) / "project.db",
                    created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else datetime.now()
                ))
        return projects

    def save_result(self, module: str, data: Dict[str, Any]) -> int:
        """Save scan result to active project's database. Returns scan_id."""
        if not self._active_project:
            raise RuntimeError("No active project")
        conn = self.db.get_project_conn(self._active_project.name)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (module, target, parsed_json, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?)",
            (module, data.get('target', ''), json.dumps(data), 'completed',
             datetime.now().isoformat(), datetime.now().isoformat())
        )
        scan_id = cursor.lastrowid
        conn.commit()
        return scan_id

    def get_results(self, module: str) -> List[dict]:
        """Retrieve all saved results for a module in active project."""
        if not self._active_project:
            return []
        conn = self.db.get_project_conn(self._active_project.name)
        rows = conn.execute(
            "SELECT id, parsed_json, target, started_at FROM scans WHERE module = ? ORDER BY started_at DESC",
            (module,)
        ).fetchall()
        results = []
        for row in rows:
            data = json.loads(row['parsed_json'])
            data['scan_id'] = row['id']
            data['started_at'] = row['started_at']
            data['target'] = row['target']
            results.append(data)
        return results

    def delete_project(self, name: str) -> bool:
        """Delete project from global DB and filesystem."""
        if self._active_project and self._active_project.name == name:
            self._active_project = None
        with self.db.get_global_conn() as conn:
            row = conn.execute("SELECT path FROM projects WHERE name = ?", (name,)).fetchone()
            if not row:
                return False
            path = Path(row['path'])
            # Remove project entry
            conn.execute("DELETE FROM projects WHERE name = ?", (name,))
            conn.commit()
        # Delete directory
        import shutil
        try:
            shutil.rmtree(path)
            return True
        except Exception as e:
            logger.error(f"Failed to delete project directory: {e}")
            return False
