#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QCheckBox, QPushButton
from PyQt6.QtCore import Qt

class EthicsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authorized Use Only")
        self.setModal(True)
        self.setFixedSize(550, 450)
        self.setWindowFlags(Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowCloseButtonHint)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint)
        layout = QVBoxLayout(self)
        warning = QLabel("⚠️")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning.setStyleSheet("font-size: 64pt; color: #FF4D4D;")
        layout.addWidget(warning)
        title = QLabel("Authorized Use Only")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20pt; font-weight: bold; color: #FF4D4D;")
        layout.addWidget(title)
        body = QLabel(
            "This tool is for educational and authorized security testing only.\n\n"
            "You must have explicit written permission from the system owner\n"
            "before conducting any phishing simulation or credential capture.\n\n"
            "Unauthorized use may violate local and international cybercrime laws,\n"
            "including the Jordanian Cybercrime Law No. 27 of 2015.\n\n"
            "The developers and ANU assume no liability for misuse."
        )
        body.setWordWrap(True)
        layout.addWidget(body)
        self.checkbox = QCheckBox("I confirm I have written authorization to conduct this test on the target system")
        layout.addWidget(self.checkbox)
        btn_layout = QHBoxLayout()
        self.confirm_btn = QPushButton("Confirm and Proceed")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.confirm_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)
        self.confirm_btn.setEnabled(False)
        self.checkbox.stateChanged.connect(lambda s: self.confirm_btn.setEnabled(s == Qt.CheckState.Checked.value))
        self.confirm_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
        else:
            super().keyPressEvent(event)

class EthicsGuard:
    _instance = None
    _acknowledged = False
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def check_acknowledged(self, parent=None):
        if self._acknowledged:
            return True
        dlg = EthicsDialog(parent)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._acknowledged = True
            return True
        return False
