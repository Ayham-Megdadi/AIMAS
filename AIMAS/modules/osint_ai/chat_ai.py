#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chat AI Module - Placeholder for upcoming AI integration.
"""

import logging
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QPlainTextEdit,
    QLabel, QScrollArea, QMessageBox, QApplication
)

from core.event_bus import EventBus

logger = logging.getLogger(__name__)


class ChatAIWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Top bar (simplified, without model selection)
        top = QHBoxLayout()
        top.addWidget(QLabel("AI Assistant"))
        top.addStretch()
        self.clear_btn = QPushButton("Clear")
        self.inject_btn = QPushButton("Inject Project Context")
        top.addWidget(self.clear_btn)
        top.addWidget(self.inject_btn)
        layout.addLayout(top)

        # Chat area (display coming soon message)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.chat_container = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.addStretch()

        # Coming soon message (Arabic + English)
        coming_msg = QLabel(
            "🔧 هذه الخاصية قيد التطوير وستتوفر في الإصدار القادم\n\n"
            "🔧 This feature is under development and will be available in the next release."
        )
        coming_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        coming_msg.setStyleSheet("background-color: #1C2128; border-radius: 12px; padding: 20px; font-size: 14px;")
        self.chat_layout.insertWidget(0, coming_msg)
        self.chat_layout.addStretch()

        self.scroll.setWidget(self.chat_container)
        layout.addWidget(self.scroll)

        # Input area (disabled)
        input_layout = QHBoxLayout()
        self.input_text = QPlainTextEdit()
        self.input_text.setPlaceholderText("AI chat will be available soon...")
        self.input_text.setReadOnly(True)
        self.input_text.setMaximumHeight(80)
        self.send_btn = QPushButton("Send")
        self.send_btn.setEnabled(False)
        input_layout.addWidget(self.input_text)
        input_layout.addWidget(self.send_btn)
        layout.addLayout(input_layout)

        # Bottom toolbar
        bottom = QHBoxLayout()
        self.save_conv_btn = QPushButton("Save Conversation")
        self.copy_last_btn = QPushButton("Copy Last Response")
        self.new_chat_btn = QPushButton("New Chat")
        bottom.addWidget(self.save_conv_btn)
        bottom.addWidget(self.copy_last_btn)
        bottom.addWidget(self.new_chat_btn)
        layout.addLayout(bottom)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def connect_signals(self):
        self.clear_btn.clicked.connect(self.clear_context)
        self.inject_btn.clicked.connect(self.inject_context)
        self.save_conv_btn.clicked.connect(self.save_conversation)
        self.copy_last_btn.clicked.connect(self.copy_last_response)
        self.new_chat_btn.clicked.connect(self.new_chat)

    def clear_context(self):
        QMessageBox.information(self, "Info", "AI chat is not yet available. This feature will be added in a future update.")

    def inject_context(self):
        QMessageBox.information(self, "Info", "Project context injection will be available with AI chat in the next release.")

    def save_conversation(self):
        EventBus().send_to_notes.emit("# AI Chat (Coming Soon)\n\nAI chat will be available in the next version.")
        self.status_update.emit("Placeholder note saved.")

    def copy_last_response(self):
        QApplication.clipboard().setText("AI chat coming soon in next release.")
        self.status_update.emit("Placeholder text copied.")

    def new_chat(self):
        QMessageBox.information(self, "New Chat", "AI chat will be available in the next release.")

    def get_module_name(self) -> str:
        return "Chat AI"
