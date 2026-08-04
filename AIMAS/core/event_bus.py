#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Event Bus - Singleton
Central communication hub between modules using Qt signals.
"""

from PyQt6.QtCore import QObject, pyqtSignal

class EventBus(QObject):
    """Singleton event bus for cross-module communication."""
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # Ensure super().__init__() is called only once
        if not self.__class__._initialized:
            super().__init__()
            self.__class__._initialized = True

    # Signals
    status_update = pyqtSignal(str)
    send_to_radar = pyqtSignal(str)
    send_to_notes = pyqtSignal(str)
    project_changed = pyqtSignal(str)
    scan_started = pyqtSignal(str)
    scan_finished = pyqtSignal(str, dict)
    auth_required = pyqtSignal()
