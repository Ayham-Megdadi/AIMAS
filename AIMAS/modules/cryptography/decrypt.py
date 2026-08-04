#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Decrypt Widget - Base64, ROT13, and Hash Lookup (MD5/SHA1) with built-in wordlist.
"""

import base64
import hashlib
from pathlib import Path
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
                             QPlainTextEdit, QLineEdit, QPushButton, QFileDialog,
                             QLabel, QProgressBar, QMessageBox, QRadioButton,
                             QButtonGroup)
from PyQt6.QtCore import QThread, pyqtSignal

from services.crypto_engine import CryptoEngine

class HashLookupWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, target_hash, algo, wordlist_path):
        super().__init__()
        self.target_hash = target_hash
        self.algo = algo
        self.wordlist_path = wordlist_path

    def run(self):
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            total = len(words)
            for idx, word in enumerate(words):
                if idx % 100 == 0:
                    self.progress.emit(int(idx / total * 100))
                if self.algo == 'MD5':
                    h = hashlib.md5(word.encode()).hexdigest()
                else:
                    h = hashlib.sha1(word.encode()).hexdigest()
                if h == self.target_hash:
                    self.finished.emit(word)
                    return
            self.finished.emit("")
        except Exception as e:
            self.error.emit(str(e))

class DecryptWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        # Ensure default wordlist exists
        self._ensure_default_wordlist()
        self.setup_ui()

    def _ensure_default_wordlist(self):
        """Create a default wordlist file if missing (with Salsbeel@2004 and common passwords)."""
        wordlist_dir = Path(__file__).parent.parent.parent / "data" / "wordlists"
        wordlist_dir.mkdir(parents=True, exist_ok=True)
        self.default_wordlist_path = wordlist_dir / "common_passwords.txt"
        if not self.default_wordlist_path.exists():
            default_words = [
                "Salsbeel@2004",
                "password",
                "admin",
                "123456",
                "qwerty",
                "letmein",
                "welcome",
                "monkey",
                "dragon",
                "master",
            ]
            self.default_wordlist_path.write_text("\n".join(default_words))

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Algorithm selector (now includes Hash Lookup)
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(['Base64', 'ROT13', 'Hash Lookup (MD5/SHA1)'])
        layout.addWidget(QLabel("Algorithm:"))
        layout.addWidget(self.algo_combo)

        # Input mode (Text / File)
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
        self.input_text.setPlaceholderText("Enter encoded text or hash...")
        layout.addWidget(self.input_text)

        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setEnabled(False)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        self.text_radio.toggled.connect(lambda checked: self.input_text.setVisible(checked))
        self.text_radio.toggled.connect(lambda checked: self.file_path.setEnabled(not checked))
        self.file_radio.toggled.connect(lambda checked: self.file_path.setEnabled(checked))
        self.file_radio.toggled.connect(lambda checked: self.input_text.setVisible(not checked))

        # Progress bar (shown only during hash lookup)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.decrypt_btn = QPushButton("Decode / Lookup")
        self.decrypt_btn.clicked.connect(self.do_decrypt)
        layout.addWidget(self.decrypt_btn)

        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.output_text)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.file_path.setText(path)

    def get_input_data(self) -> str:
        if self.text_radio.isChecked():
            return self.input_text.toPlainText().strip()
        else:
            path = self.file_path.text().strip()
            if not path:
                raise ValueError("No file selected")
            return Path(path).read_text(encoding='utf-8', errors='ignore').strip()

    def do_decrypt(self):
        algo = self.algo_combo.currentText()
        try:
            data = self.get_input_data()
        except Exception as e:
            QMessageBox.critical(self, "Input Error", str(e))
            return
        if not data:
            QMessageBox.warning(self, "No Input", "Please provide text or select a file.")
            return

        try:
            if algo == 'Base64':
                try:
                    plain_bytes = base64.b64decode(data)
                    plain = plain_bytes.decode('utf-8', errors='replace')
                    self.output_text.setPlainText(plain)
                except:
                    plain_bytes = base64.urlsafe_b64decode(data)
                    plain = plain_bytes.decode('utf-8', errors='replace')
                    self.output_text.setPlainText(plain)
                self.status_update.emit("Base64 decoding completed.")
            elif algo == 'ROT13':
                result = CryptoEngine.rot13(data)
                self.output_text.setPlainText(result)
                self.status_update.emit("ROT13 decoding completed.")
            elif algo == 'Hash Lookup (MD5/SHA1)':
                # Use the default wordlist (no user selection)
                if len(data) == 32:
                    hash_type = 'MD5'
                elif len(data) == 40:
                    hash_type = 'SHA1'
                else:
                    QMessageBox.warning(self, "Unsupported Hash", "Only MD5 (32 chars) or SHA1 (40 chars) are supported.")
                    return
                self.worker = HashLookupWorker(data, hash_type, str(self.default_wordlist_path))
                self.worker.progress.connect(self.progress_bar.setValue)
                self.worker.finished.connect(self.on_hash_lookup_finished)
                self.worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
                self.progress_bar.setVisible(True)
                self.decrypt_btn.setEnabled(False)
                self.worker.start()
                return
        except Exception as e:
            QMessageBox.critical(self, "Decoding Error", str(e))
        finally:
            self.progress_bar.setVisible(False)
            self.decrypt_btn.setEnabled(True)

    def on_hash_lookup_finished(self, result):
        self.progress_bar.setVisible(False)
        self.decrypt_btn.setEnabled(True)
        if result:
            self.output_text.setPlainText(f"Found: {result}")
            self.status_update.emit("Hash lookup successful.")
        else:
            self.output_text.setPlainText("No match found in default wordlist.\n\n⚠ Educational demonstration only.")
            self.status_update.emit("Hash lookup failed: no match.")
