#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Encrypt Widget - Hashing (MD5, SHA1, SHA256, SHA512, SHA224, SHA384) and Encryption (AES, ChaCha20, RSA).
No tabs - both sections visible.
"""

from pathlib import Path
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
                             QPlainTextEdit, QLineEdit, QPushButton, QFileDialog,
                             QRadioButton, QButtonGroup, QLabel, QMessageBox,
                             QGroupBox)
from PyQt6.QtCore import pyqtSignal

from services.crypto_engine import CryptoEngine

class EncryptWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)

        # ========== Hashing Section ==========
        hash_group = QGroupBox("Hashing")
        hash_layout = QVBoxLayout(hash_group)

        # Algorithm selection
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Algorithm:"))
        self.hash_algo = QComboBox()
        self.hash_algo.addItems(['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA224', 'SHA384'])
        algo_layout.addWidget(self.hash_algo)
        hash_layout.addLayout(algo_layout)

        # Input mode
        mode_layout = QHBoxLayout()
        self.hash_mode_group = QButtonGroup()
        self.hash_text_radio = QRadioButton("Text")
        self.hash_file_radio = QRadioButton("File")
        self.hash_text_radio.setChecked(True)
        self.hash_mode_group.addButton(self.hash_text_radio)
        self.hash_mode_group.addButton(self.hash_file_radio)
        mode_layout.addWidget(self.hash_text_radio)
        mode_layout.addWidget(self.hash_file_radio)
        hash_layout.addLayout(mode_layout)

        self.hash_input_text = QPlainTextEdit()
        self.hash_input_text.setPlaceholderText("Enter text to hash...")
        hash_layout.addWidget(self.hash_input_text)

        file_layout = QHBoxLayout()
        self.hash_file_path = QLineEdit()
        self.hash_file_path.setEnabled(False)
        self.hash_browse_btn = QPushButton("Browse")
        self.hash_browse_btn.clicked.connect(lambda: self.browse_file(self.hash_file_path))
        file_layout.addWidget(self.hash_file_path)
        file_layout.addWidget(self.hash_browse_btn)
        hash_layout.addLayout(file_layout)

        self.hash_text_radio.toggled.connect(lambda checked: self.hash_input_text.setVisible(checked))
        self.hash_text_radio.toggled.connect(lambda checked: self.hash_file_path.setEnabled(not checked))
        self.hash_file_radio.toggled.connect(lambda checked: self.hash_file_path.setEnabled(checked))
        self.hash_file_radio.toggled.connect(lambda checked: self.hash_input_text.setVisible(not checked))

        self.hash_output = QLineEdit()
        self.hash_output.setReadOnly(True)
        hash_layout.addWidget(QLabel("Hash:"))
        hash_layout.addWidget(self.hash_output)

        self.hash_btn = QPushButton("Hash")
        self.hash_btn.clicked.connect(self.do_hash)
        hash_layout.addWidget(self.hash_btn)

        main_layout.addWidget(hash_group)

        # ========== Encryption Section ==========
        enc_group = QGroupBox("Encryption")
        enc_layout = QVBoxLayout(enc_group)

        # Algorithm selection
        enc_algo_layout = QHBoxLayout()
        enc_algo_layout.addWidget(QLabel("Algorithm:"))
        self.enc_algo = QComboBox()
        self.enc_algo.addItems(['AES-256-GCM', 'ChaCha20-Poly1305', 'RSA-2048'])
        enc_algo_layout.addWidget(self.enc_algo)
        enc_layout.addLayout(enc_algo_layout)

        # Input mode
        enc_mode_layout = QHBoxLayout()
        self.enc_mode_group = QButtonGroup()
        self.enc_text_radio = QRadioButton("Text")
        self.enc_file_radio = QRadioButton("File")
        self.enc_text_radio.setChecked(True)
        self.enc_mode_group.addButton(self.enc_text_radio)
        self.enc_mode_group.addButton(self.enc_file_radio)
        enc_mode_layout.addWidget(self.enc_text_radio)
        enc_mode_layout.addWidget(self.enc_file_radio)
        enc_layout.addLayout(enc_mode_layout)

        self.enc_input_text = QPlainTextEdit()
        self.enc_input_text.setPlaceholderText("Enter plaintext...")
        enc_layout.addWidget(self.enc_input_text)

        enc_file_layout = QHBoxLayout()
        self.enc_file_path = QLineEdit()
        self.enc_file_path.setEnabled(False)
        self.enc_browse_btn = QPushButton("Browse")
        self.enc_browse_btn.clicked.connect(lambda: self.browse_file(self.enc_file_path))
        enc_file_layout.addWidget(self.enc_file_path)
        enc_file_layout.addWidget(self.enc_browse_btn)
        enc_layout.addLayout(enc_file_layout)

        self.enc_text_radio.toggled.connect(lambda checked: self.enc_input_text.setVisible(checked))
        self.enc_text_radio.toggled.connect(lambda checked: self.enc_file_path.setEnabled(not checked))
        self.enc_file_radio.toggled.connect(lambda checked: self.enc_file_path.setEnabled(checked))
        self.enc_file_radio.toggled.connect(lambda checked: self.enc_input_text.setVisible(not checked))

        # Password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Password (for AES/ChaCha20)")
        enc_layout.addWidget(self.password_input)

        # RSA public key
        self.rsa_public_key = QLineEdit()
        self.rsa_public_key.setPlaceholderText("RSA public key PEM file path")
        self.rsa_public_key.setVisible(False)
        self.rsa_gen_btn = QPushButton("Generate Key Pair")
        self.rsa_gen_btn.setVisible(False)
        rsa_layout = QHBoxLayout()
        rsa_layout.addWidget(self.rsa_public_key)
        rsa_layout.addWidget(self.rsa_gen_btn)
        enc_layout.addLayout(rsa_layout)

        self.enc_algo.currentIndexChanged.connect(self.on_enc_algo_changed)
        self.rsa_gen_btn.clicked.connect(self.generate_rsa)

        # Output
        self.enc_output = QPlainTextEdit()
        self.enc_output.setReadOnly(True)
        enc_layout.addWidget(QLabel("Output (Base64):"))
        enc_layout.addWidget(self.enc_output)

        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.do_encrypt)
        enc_layout.addWidget(self.encrypt_btn)

        main_layout.addWidget(enc_group)

    def browse_file(self, line_edit):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            line_edit.setText(path)

    def on_enc_algo_changed(self, idx):
        algo = self.enc_algo.currentText()
        rsa_visible = (algo == 'RSA-2048')
        self.rsa_public_key.setVisible(rsa_visible)
        self.rsa_gen_btn.setVisible(rsa_visible)
        self.password_input.setVisible(algo != 'RSA-2048')

    def generate_rsa(self):
        priv, pub = CryptoEngine.rsa_generate_keypair()
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "private.pem", "PEM Files (*.pem)")
        if save_path:
            Path(save_path).write_text(priv)
            QMessageBox.information(self, "Key Saved", f"Private key saved to {save_path}")
        load_path, _ = QFileDialog.getOpenFileName(self, "Load Public Key", "", "PEM Files (*.pem)")
        if load_path:
            self.rsa_public_key.setText(load_path)

    def do_hash(self):
        algo = self.hash_algo.currentText()
        if self.hash_text_radio.isChecked():
            data = self.hash_input_text.toPlainText().encode()
        else:
            path = self.hash_file_path.text().strip()
            if not path:
                QMessageBox.warning(self, "No File", "Please select a file.")
                return
            try:
                data = Path(path).read_bytes()
            except Exception as e:
                QMessageBox.critical(self, "File Error", str(e))
                return
        try:
            if algo == 'MD5':
                result = CryptoEngine.hash_md5(data)
            elif algo == 'SHA1':
                result = CryptoEngine.hash_sha1(data)
            elif algo == 'SHA256':
                result = CryptoEngine.hash_sha256(data)
            elif algo == 'SHA512':
                result = CryptoEngine.hash_sha512(data)
            elif algo == 'SHA224':
                result = CryptoEngine.hash_sha224(data)
            elif algo == 'SHA384':
                result = CryptoEngine.hash_sha384(data)
            else:
                raise ValueError("Unknown hash algorithm")
            self.hash_output.setText(result)
            self.status_update.emit(f"Hash ({algo}) completed.")
        except Exception as e:
            QMessageBox.critical(self, "Hash Error", str(e))

    def do_encrypt(self):
        algo = self.enc_algo.currentText()
        password = self.password_input.text()
        if algo != 'RSA-2048' and not password:
            QMessageBox.warning(self, "No Password", "Please enter a password.")
            return
        if self.enc_text_radio.isChecked():
            plaintext = self.enc_input_text.toPlainText().encode()
        else:
            path = self.enc_file_path.text().strip()
            if not path:
                QMessageBox.warning(self, "No File", "Please select a file.")
                return
            try:
                plaintext = Path(path).read_bytes()
            except Exception as e:
                QMessageBox.critical(self, "File Error", str(e))
                return
        try:
            if algo == 'AES-256-GCM':
                result = CryptoEngine.aes_encrypt(plaintext, password)
            elif algo == 'ChaCha20-Poly1305':
                result = CryptoEngine.chacha_encrypt(plaintext, password)
            elif algo == 'RSA-2048':
                pub_path = self.rsa_public_key.text().strip()
                if not pub_path:
                    QMessageBox.warning(self, "No Public Key", "Please select a public key.")
                    return
                pub_pem = Path(pub_path).read_text()
                result = CryptoEngine.rsa_encrypt(plaintext, pub_pem)
            else:
                raise ValueError("Unknown algorithm")
            self.enc_output.setPlainText(result)
            self.status_update.emit(f"Encryption completed using {algo}")
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))
