#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP File Sharing with ngrok and real-time request logging via queue
Fixed: QTimer moved to main thread (Widget), not inside Worker.
"""

import os
import logging
import socket
import http.server
import socketserver
import queue
from pathlib import Path
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, QTimer, QObject
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QSpinBox, QGroupBox, QCheckBox, QFileDialog, QMessageBox,
    QTextEdit, QLabel, QApplication
)
import pyngrok

logger = logging.getLogger(__name__)

class AimasTerminal(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet("background-color: #0D1117; color: #E6EDF3; font-family: 'JetBrains Mono'; font-size: 11px;")

    def append_log(self, text: str):
        self.append(text)

class HTTPServerWorker(QThread):
    server_started = pyqtSignal(str)
    request_logged = pyqtSignal(str)   # يمكن استخدامها للتنبيه الفوري، ولكن سنعتمد على الـ queue
    server_stopped = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, directory: str, port: int):
        super().__init__()
        self.directory = Path(directory).resolve()
        self.port = port
        self.httpd = None
        self._log_queue = queue.Queue()
        self._running = False

    def run(self):
        try:
            # Handler that puts logs into queue
            class QueueHTTPHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    client_ip = self.client_address[0]
                    method = self.command
                    path = self.path
                    status = args[0] if args else '???'
                    log_line = f"[{timestamp}] {client_ip} {method} {path} → {status}"
                    # store in queue
                    if hasattr(self.server, 'log_queue'):
                        self.server.log_queue.put(log_line)

                def translate_path(self, path):
                    # serve from selected directory
                    return super().translate_path(path)

            class CustomTCPServer(socketserver.TCPServer):
                log_queue = None
                allow_reuse_address = True

            server = CustomTCPServer(("", self.port), QueueHTTPHandler)
            server.log_queue = self._log_queue
            self.httpd = server

            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            url = f"http://{local_ip}:{self.port}"
            self.server_started.emit(url)

            self._running = True
            os.chdir(self.directory)
            self.httpd.serve_forever()
        except Exception as e:
            self.error.emit(str(e))

    def flush_logs(self):
        """إرجاع قائمة السجلات المتراكمة (يُستدعى من الـ widget بانتظام)"""
        logs = []
        while not self._log_queue.empty():
            logs.append(self._log_queue.get_nowait())
        return logs

    def stop(self):
        self._running = False
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_stopped.emit()

class HTTPSharingWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self._log_timer = QTimer(self)          # Timer في الـ main thread
        self._log_timer.timeout.connect(self._poll_logs)
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Directory
        dir_layout = QHBoxLayout()
        self.dir_edit = QLineEdit()
        self.dir_edit.setReadOnly(True)
        self.browse_btn = QPushButton("Browse")
        dir_layout.addWidget(QLabel("Directory:"))
        dir_layout.addWidget(self.dir_edit)
        dir_layout.addWidget(self.browse_btn)
        layout.addLayout(dir_layout)

        # Port
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(8080)
        port_layout.addWidget(self.port_spin)
        layout.addLayout(port_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Server")
        self.stop_btn = QPushButton("Stop Server")
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        # Local URL
        local_layout = QHBoxLayout()
        local_layout.addWidget(QLabel("Local URL:"))
        self.local_url_edit = QLineEdit()
        self.local_url_edit.setReadOnly(True)
        self.copy_local_btn = QPushButton("Copy")
        local_layout.addWidget(self.local_url_edit)
        local_layout.addWidget(self.copy_local_btn)
        layout.addLayout(local_layout)

        # ngrok
        self.ngrok_group = QGroupBox("ngrok Tunnel")
        ngrok_layout = QVBoxLayout()
        self.ngrok_check = QCheckBox("Enable ngrok tunnel")
        self.ngrok_token = QLineEdit()
        self.ngrok_token.setPlaceholderText("ngrok auth token")
        self.ngrok_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.public_url_edit = QLineEdit()
        self.public_url_edit.setReadOnly(True)
        self.copy_public_btn = QPushButton("Copy")
        ngrok_layout.addWidget(self.ngrok_check)
        ngrok_layout.addWidget(QLabel("Auth Token:"))
        ngrok_layout.addWidget(self.ngrok_token)
        ngrok_layout.addWidget(QLabel("Public URL:"))
        ngrok_layout.addWidget(self.public_url_edit)
        ngrok_layout.addWidget(self.copy_public_btn)
        self.ngrok_group.setLayout(ngrok_layout)
        layout.addWidget(self.ngrok_group)

        # Log
        layout.addWidget(QLabel("Request Log:"))
        self.log_terminal = AimasTerminal()
        layout.addWidget(self.log_terminal)

        self.setLayout(layout)

    def connect_signals(self):
        self.browse_btn.clicked.connect(self.browse_directory)
        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn.clicked.connect(self.stop_server)
        self.copy_local_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.local_url_edit.text()))
        self.copy_public_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.public_url_edit.text()))

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Share")
        if directory:
            self.dir_edit.setText(directory)

    def start_server(self):
        directory = self.dir_edit.text()
        if not directory:
            QMessageBox.warning(self, "No Directory", "Select a directory first.")
            return
        port = self.port_spin.value()
        self.worker = HTTPServerWorker(directory, port)
        self.worker.server_started.connect(self.on_server_started)
        self.worker.server_stopped.connect(self.on_server_stopped)
        self.worker.error.connect(self.on_server_error)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_update.emit(f"Starting HTTP server on port {port}...")
        self._log_timer.start(500)   # بدء الـ timer بعد تشغيل الخادم

        if self.ngrok_check.isChecked():
            token = self.ngrok_token.text().strip()
            if token:
                try:
                    pyngrok.ngrok.set_auth_token(token)
                    tunnel = pyngrok.ngrok.connect(port)
                    self.public_url_edit.setText(tunnel.public_url)
                    self.status_update.emit(f"ngrok tunnel: {tunnel.public_url}")
                except Exception as e:
                    self.status_update.emit(f"ngrok error: {e}")

    def stop_server(self):
        self._log_timer.stop()   # إيقاف الـ timer
        if self.worker:
            self.worker.stop()
            self.worker.wait()
            self.worker = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_update.emit("HTTP server stopped.")
        if self.ngrok_check.isChecked():
            try:
                pyngrok.ngrok.disconnect()
            except:
                pass
            self.public_url_edit.clear()

    def _poll_logs(self):
        """جلب السجلات من الـ worker وعرضها في الطرفية"""
        if self.worker:
            logs = self.worker.flush_logs()
            for msg in logs:
                self.log_terminal.append_log(msg)

    def on_server_started(self, url):
        self.local_url_edit.setText(url)
        self.status_update.emit(f"Server started at {url}")

    def on_server_stopped(self):
        self.status_update.emit("Server stopped.")

    def on_server_error(self, err):
        self.status_update.emit(f"Server error: {err}")
        QMessageBox.critical(self, "Server Error", err)
        self.stop_server()

    def get_module_name(self) -> str:
        return "HTTP File Sharing"
