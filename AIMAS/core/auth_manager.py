#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Authentication Manager - Handles sudo password caching with GUI dialog
"""

import subprocess
import logging
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QHBoxLayout, QMessageBox, QApplication
from PyQt6.QtCore import Qt

logger = logging.getLogger(__name__)

class SudoDialog(QDialog):
    """نافذة آمنة لإدخال كلمة مرور sudo مع رسالة ترحيبية مخصصة"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentication Required")
        self.setModal(True)
        self.setFixedWidth(450)
        layout = QVBoxLayout(self)

        # رسالة الترحيب
        welcome = QLabel("<b>Welcome to AIMAS</b>")
        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome.setStyleSheet("font-size: 14pt; color: #00FF9C; margin-top: 10px;")
        layout.addWidget(welcome)

        # شرح الحاجة إلى صلاحيات
        info = QLabel(
            "This tool needs administrator privileges to run network scans and advanced features.\n"
            "Please enter your sudo password below."
        )
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info)

        # حقل كلمة المرور
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("sudo password")
        self.password_input.returnPressed.connect(self.accept)
        layout.addWidget(self.password_input)

        # أزرار
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Authenticate")
        cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        # تذييل بأسماء الفريق
        team = QLabel(
            "A - Ayham   |   I - Ibrahim   |   M - Manar   |   A - Amira   |   S - Salsabeel"
        )
        team.setAlignment(Qt.AlignmentFlag.AlignCenter)
        team.setStyleSheet("font-size: 9pt; color: #8B949E; margin-top: 10px;")
        layout.addWidget(team)

        ok_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)

    def get_password(self) -> str:
        return self.password_input.text()


class AuthManager:
    _sudo_authenticated = False
    _sudo_password_bytes = b""

    @classmethod
    def authenticate(cls, parent=None) -> bool:
        """طلب كلمة مرور sudo عبر نافذة GUI وتخزينها"""
        if cls._sudo_authenticated:
            return True
        if QApplication.instance() is None:
            logger.error("QApplication not running, cannot authenticate")
            return False

        dialog = SudoDialog(parent)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        password = dialog.get_password()
        if not password:
            return False

        try:
            proc = subprocess.run(
                ['sudo', '-S', 'true'],
                input=(password + '\n').encode(),
                capture_output=True,
                timeout=5
            )
            if proc.returncode == 0:
                cls._sudo_password_bytes = (password + '\n').encode()
                cls._sudo_authenticated = True
                logger.info("sudo authentication successful")
                return True
            else:
                QMessageBox.critical(parent, "Authentication Failed", "Wrong sudo password. Please try again.")
                return False
        except Exception as e:
            logger.error(f"sudo auth error: {e}")
            QMessageBox.critical(parent, "Error", f"Authentication failed: {e}")
            return False

    @classmethod
    def get_sudo_input(cls) -> bytes:
        return cls._sudo_password_bytes

    @classmethod
    def get_sudo_prefix(cls):
        return ['sudo', '-S']

    @classmethod
    def is_authenticated(cls) -> bool:
        return cls._sudo_authenticated

    @classmethod
    def clear_auth(cls):
        cls._sudo_password_bytes = b""
        cls._sudo_authenticated = False
