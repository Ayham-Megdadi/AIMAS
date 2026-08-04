#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cipher Identifier - Analyzes hash/ciphertext from text or file input.
"""

import re
import math
from collections import Counter
from pathlib import Path
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QPlainTextEdit, QLabel, QTableWidget, QTableWidgetItem,
                             QHeaderView, QFileDialog, QMessageBox, QRadioButton,
                             QButtonGroup, QLineEdit)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QColor

class CipherAnalyzer:
    @staticmethod
    def analyze(text: str):
        text = text.strip()
        if not text:
            return []
        scores = []
        length = len(text)
        if re.fullmatch(r'^[a-fA-F0-9]+$', text):
            if length == 32:
                scores.append(('MD5', 95, 'Hash'))
            elif length == 40:
                scores.append(('SHA1', 95, 'Hash'))
            elif length == 64:
                scores.append(('SHA256', 95, 'Hash'))
            elif length == 128:
                scores.append(('SHA512', 95, 'Hash'))
            elif length == 56:
                scores.append(('SHA224', 90, 'Hash'))
            elif length == 96:
                scores.append(('SHA384', 90, 'Hash'))
            else:
                scores.append(('Hex string', 60, 'Encoding'))

        if text.startswith('$2y$') or text.startswith('$2b$') or text.startswith('$2a$'):
            scores.append(('bcrypt', 99, 'Hash'))
        if text.startswith('$5$'):
            scores.append(('SHA256-crypt', 99, 'Hash'))
        if text.startswith('$6$'):
            scores.append(('SHA512-crypt', 99, 'Hash'))
        if text.startswith('$1$'):
            scores.append(('MD5-crypt', 99, 'Hash'))

        b64_pattern = re.compile(r'^[A-Za-z0-9+/]+=*$')
        if b64_pattern.match(text) and len(text) % 4 == 0:
            scores.append(('Base64', 85, 'Encoding'))
        urlsafe_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
        if urlsafe_pattern.match(text):
            scores.append(('URL-safe Base64', 70, 'Encoding'))

        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        if jwt_pattern.match(text):
            scores.append(('JWT', 99, 'Token'))

        if text.startswith('U2Fsd'):
            scores.append(('OpenSSL AES (Salted)', 98, 'Symmetric'))

        if text.isprintable() and not any(c.isdigit() for c in text):
            scores.append(('ROT13 (likely)', 50, 'Encoding'))
            scores.append(('Caesar cipher', 45, 'Encoding'))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:5]

class CipherIdentifierWidget(QWidget):
    status_update = pyqtSignal(str)
    send_to_decrypt = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_analysis = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Input mode
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup()
        self.text_radio = QRadioButton("Text")
        self.file_radio = QRadioButton("File")
        self.text_radio.setChecked(True)
        self.mode_group.addButton(self.text_radio)
        self.mode_group.addButton(self.file_radio)
        mode_layout.addWidget(self.text_radio)
        mode_layout.addWidget(self.file_radio)
        layout.addLayout(mode_layout)

        self.input_text = QPlainTextEdit()
        self.input_text.setPlaceholderText("Paste hash, ciphertext, or encoded string here...")
        layout.addWidget(self.input_text)

        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select a file...")
        self.file_path.setVisible(False)
        self.file_browse_btn = QPushButton("Browse")
        self.file_browse_btn.setVisible(False)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(self.file_browse_btn)
        layout.addLayout(file_layout)

        self.text_radio.toggled.connect(lambda checked: self.input_text.setVisible(checked))
        self.text_radio.toggled.connect(lambda checked: self.file_path.setVisible(not checked))
        self.text_radio.toggled.connect(lambda checked: self.file_browse_btn.setVisible(not checked))
        self.file_radio.toggled.connect(lambda checked: self.input_text.setVisible(not checked))
        self.file_radio.toggled.connect(lambda checked: self.file_path.setVisible(checked))
        self.file_radio.toggled.connect(lambda checked: self.file_browse_btn.setVisible(checked))
        self.file_browse_btn.clicked.connect(self.browse_file)

        analyze_btn = QPushButton("Analyze")
        analyze_btn.clicked.connect(self.analyze)
        layout.addWidget(analyze_btn)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Algorithm", "Confidence", "Category", "Top Match"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        self.char_stats = QLabel("Length: 0 | Charset: - | Entropy: -")
        layout.addWidget(self.char_stats)

        self.send_btn = QPushButton("Send to Decrypt")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.on_send)
        layout.addWidget(self.send_btn)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.file_path.setText(path)

    def get_input_text(self) -> str:
        if self.text_radio.isChecked():
            return self.input_text.toPlainText().strip()
        else:
            path = self.file_path.text().strip()
            if not path:
                return ""
            try:
                return Path(path).read_text(encoding='utf-8', errors='ignore').strip()
            except Exception as e:
                QMessageBox.critical(self, "File Error", str(e))
                return ""

    def analyze(self):
        text = self.get_input_text()
        if not text:
            QMessageBox.warning(self, "No Input", "Please provide text or select a file.")
            return
        self.current_analysis = CipherAnalyzer.analyze(text)
        self.results_table.setRowCount(len(self.current_analysis))
        best_confidence = self.current_analysis[0][1] if self.current_analysis else 0
        for row, (name, score, category) in enumerate(self.current_analysis):
            self.results_table.setItem(row, 0, QTableWidgetItem(name))
            conf_item = QTableWidgetItem(f"{score}%")
            if score == best_confidence:
                conf_item.setBackground(QColor("#00FF9C"))
                conf_item.setForeground(QColor("#0D1117"))
            self.results_table.setItem(row, 1, conf_item)
            self.results_table.setItem(row, 2, QTableWidgetItem(category))
            is_top = (score == best_confidence)
            self.results_table.setItem(row, 3, QTableWidgetItem("✓" if is_top else ""))
        self.results_table.sortItems(1, Qt.SortOrder.DescendingOrder)
        length = len(text)
        charset = "unknown"
        if re.fullmatch(r'^[a-fA-F0-9]+$', text):
            charset = "hex"
        elif re.fullmatch(r'^[A-Za-z0-9+/]+=*$', text):
            charset = "base64"
        elif text.isprintable():
            charset = "ascii"
        counts = Counter(text)
        entropy = 0.0
        for c in counts.values():
            p = c / length
            entropy -= p * math.log2(p)
        self.char_stats.setText(f"Length: {length} | Charset: {charset} | Entropy: {entropy:.2f} bits/char")
        if self.current_analysis and self.current_analysis[0][0] in ('Base64', 'URL-safe Base64', 'ROT13 (likely)', 'OpenSSL AES (Salted)'):
            self.send_btn.setEnabled(True)
        else:
            self.send_btn.setEnabled(False)
        self.status_update.emit(f"Analysis completed: {self.current_analysis[0][0] if self.current_analysis else 'None'}")

    def on_send(self):
        if self.current_analysis:
            alg = self.current_analysis[0][0]
            self.send_to_decrypt.emit(self.get_input_text(), alg)
