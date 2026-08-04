#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AIMAS Main Window - Custom titlebar, sidebar, stacked content.
"""

import sys
import logging
import psutil
from pathlib import Path

from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QListWidget, QListWidgetItem,
                             QStackedWidget, QStatusBar, QSplitter, QApplication)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QPoint
from PyQt6.QtGui import QIcon, QFont

from core.event_bus import EventBus
from core.project_manager import ProjectManager

logger = logging.getLogger(__name__)


class AimasMainWindow(QMainWindow):
    """Main application window with custom frameless design and dynamic content."""
    status_update = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.resize(1280, 800)

        self.drag_pos = None
        self.event_bus = EventBus()
        self.project_manager = ProjectManager()

        # Stores mapping: (tab_name, sidebar_text) -> widget index in stack
        self.sidebar_to_index = {}
        self.widgets = []  # list of widgets in QStackedWidget

        self.setup_ui()
        self.setup_status_timers()
        self.connect_signals()
        self.apply_default_style()

        # Connect sidebar selection to switching
        self.sidebar.currentItemChanged.connect(self.on_sidebar_item_changed)

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ----- Custom titlebar (44px) -----
        self.titlebar = QWidget()
        self.titlebar.setFixedHeight(44)
        self.titlebar.setObjectName("TitleBar")
        title_layout = QHBoxLayout(self.titlebar)
        title_layout.setContentsMargins(10, 0, 10, 0)

        self.logo_label = QLabel("AIMAS")
        logo_font = QFont("Inter", 14, QFont.Weight.Bold)
        self.logo_label.setFont(logo_font)
        self.logo_label.setStyleSheet("color: #00FF9C;")
        title_layout.addWidget(self.logo_label)

        title_layout.addStretch()

        # Navigation tabs (center)
        self.nav_tabs = {}
        tab_names = ["Network", "Web", "Cryptography", "OSINT-AI", "Phishing", "Note"]
        nav_container = QHBoxLayout()
        nav_container.setSpacing(10)
        for name in tab_names:
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    border: none;
                    padding: 8px 12px;
                    font-weight: 500;
                }
                QPushButton:checked {
                    color: #00FF9C;
                    border-bottom: 2px solid #00FF9C;
                }
                QPushButton:hover:!checked {
                    color: #00B4D8;
                }
            """)
            self.nav_tabs[name] = btn
            nav_container.addWidget(btn)
        title_layout.addLayout(nav_container)

        title_layout.addStretch()

        # Project indicator + window controls
        self.project_label = QLabel("Project: None")
        self.project_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.project_label.setStyleSheet("color: #8B949E;")
        title_layout.addWidget(self.project_label)

        self.min_btn = QPushButton("─")
        self.max_btn = QPushButton("□")
        self.close_btn = QPushButton("✕")
        for btn in (self.min_btn, self.max_btn, self.close_btn):
            btn.setFixedSize(32, 28)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.min_btn.clicked.connect(self.showMinimized)
        self.max_btn.clicked.connect(self.toggle_maximize)
        self.close_btn.clicked.connect(self.close)
        title_layout.addWidget(self.min_btn)
        title_layout.addWidget(self.max_btn)
        title_layout.addWidget(self.close_btn)

        main_layout.addWidget(self.titlebar)

        # ----- Body: QSplitter (sidebar + content) -----
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(200)
        self.sidebar.setStyleSheet("""
            QListWidget { background: #161B22; border: none; }
            QListWidget::item { padding: 10px; border: none; margin: 2px 0; }
            QListWidget::item:selected {
                background: #00FF9C0F;
                border-left: 3px solid #00FF9C;
            }
            QListWidget::item:hover { background: #1C2128; }
        """)
        self.splitter.addWidget(self.sidebar)

        # Content stack
        self.content_stack = QStackedWidget()
        self.splitter.addWidget(self.content_stack)
        self.splitter.setSizes([200, self.width() - 200])

        main_layout.addWidget(self.splitter)

        # ----- Status Bar (28px) -----
        self.status_bar = QStatusBar()
        self.status_bar.setFixedHeight(28)
        self.status_bar.setStyleSheet("QStatusBar { background: #161B22; color: #8B949E; }")

        self.project_status_label = QLabel("Project: None")
        self.module_status_label = QLabel("Ready")
        self.cpu_label = QLabel("CPU: --%")
        self.ram_label = QLabel("RAM: -- MB")
        self.root_dot = QLabel("●")
        self.root_dot.setFixedSize(12, 12)
        self.root_dot.setStyleSheet("background: #FF4D4D; border-radius: 6px;")

        self.status_bar.addWidget(self.project_status_label)
        self.status_bar.addWidget(QLabel(" | "))
        self.status_bar.addWidget(self.module_status_label)
        self.status_bar.addWidget(self.cpu_label)
        self.status_bar.addWidget(self.ram_label)
        self.status_bar.addWidget(self.root_dot)

        main_layout.addWidget(self.status_bar)

        # Connect nav buttons to populate sidebar
        for name, btn in self.nav_tabs.items():
            btn.clicked.connect(lambda checked, n=name: self.set_active_tab(n))

        # Set initial active tab
        self.set_active_tab("Network")

    def apply_default_style(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0D1117; }
            QWidget { background-color: #0D1117; color: #E6EDF3; }
            QPushButton { background-color: #1C2128; border: 1px solid #30363D; border-radius: 4px; padding: 6px; }
            QPushButton:hover { border-color: #00FF9C; }
            QListWidget { background-color: #161B22; }
        """)

    def setup_status_timers(self):
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_system_stats)
        self.status_timer.start(2000)

    def update_system_stats(self):
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            self.cpu_label.setText(f"CPU: {cpu:.0f}%")
            self.ram_label.setText(f"RAM: {mem.used // (1024**2)} MB")
        except:
            pass

    def connect_signals(self):
        self.event_bus.status_update.connect(self.module_status_label.setText)
        self.event_bus.project_changed.connect(self.on_project_changed)

    def on_project_changed(self, project_name: str):
        self.project_status_label.setText(f"Project: {project_name}")
        self.project_label.setText(f"Project: {project_name}")

    def set_active_tab(self, tab_name: str):
        """Switch top tab and populate sidebar with predefined items."""
        for name, btn in self.nav_tabs.items():
            btn.setChecked(name == tab_name)

        # Define sidebar items per tab
        tab_items = {
            "Network": ["My Network", "Device Mapper", "Network Radar", "HTTP Sharing"],
            "Web": ["Recon", "Hidden", "Vuln Scanner", "WAF Detector"],
            "Cryptography": ["Cipher Identifier", "Encrypt", "Decrypt"],
            "OSINT-AI": ["Email OSINT", "Phone OSINT", "Image Metadata", "Chat AI"],
            "Phishing": ["Page Setup", "Server", "Exposure", "Sessions"],
            "Note": ["Notes Editor", "Global Notes", "Project Notes"],
        }
        items = tab_items.get(tab_name, [])
        self.sidebar.clear()
        for item_text in items:
            self.sidebar.addItem(item_text)

        # Store current tab name
        self.current_tab = tab_name

        # If any widgets registered for this tab, show first one
        if self.sidebar.count() > 0:
            self.sidebar.setCurrentRow(0)
            self._show_widget_for_item(self.sidebar.currentItem().text())

    def _show_widget_for_item(self, item_text: str):
        """Find widget registered for (current_tab, item_text) and show it."""
        key = (self.current_tab, item_text)
        idx = self.sidebar_to_index.get(key)
        if idx is not None:
            self.content_stack.setCurrentIndex(idx)
            self.module_status_label.setText(item_text)

    def on_sidebar_item_changed(self, current, previous):
        if current:
            self._show_widget_for_item(current.text())

    def register_widget(self, widget: QWidget, tab_name: str, sidebar_text: str):
        """
        Register a widget to be shown when a specific sidebar item is selected.
        The widget will be added to QStackedWidget and associated with the key.
        """
        idx = self.content_stack.addWidget(widget)
        self.sidebar_to_index[(tab_name, sidebar_text)] = idx
        self.widgets.append(widget)

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if self.titlebar.geometry().contains(event.pos()):
                self.drag_pos = event.globalPosition().toPoint()
                event.accept()

    def mouseMoveEvent(self, event):
        if self.drag_pos is not None:
            self.move(self.pos() + (event.globalPosition().toPoint() - self.drag_pos))
            self.drag_pos = event.globalPosition().toPoint()
            event.accept()

    def mouseReleaseEvent(self, event):
        self.drag_pos = None
        event.accept()
