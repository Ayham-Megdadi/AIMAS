#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AIMAS - Advanced Intelligence & Multi-purpose Attack Suite
Final stable version: Network, Web, Cryptography, OSINT‑AI, Phishing (Zphisher‑like).
Notes module removed.
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QStatusBar, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon

# Network modules
from modules.network.my_network import MyNetworkWidget
from modules.network.device_mapper import DeviceMapperWidget
from modules.network.network_radar import NetworkRadarWidget
from modules.network.http_sharing import HTTPSharingWidget

# Web modules
from modules.web.recon_web import ReconWebWidget
from modules.web.hidden import HiddenWidget
from modules.web.vuln_scanner import VulnScannerWidget
from modules.web.waf_detector import WAFDetectorWidget

# Cryptography modules
from modules.cryptography.cipher_identifier import CipherIdentifierWidget
from modules.cryptography.encrypt import EncryptWidget
from modules.cryptography.decrypt import DecryptWidget

# OSINT-AI modules
from modules.osint_ai.email_osint import EmailOSINTWidget
from modules.osint_ai.phone_osint import PhoneOSINTWidget
from modules.osint_ai.image_metadata import ImageMetadataWidget
from modules.osint_ai.chat_ai import ChatAIWidget

# Phishing module – Zphisher‑like (fully functional)
from modules.phishing.zphisher_like import ZphisherLikeWidget

from core.auth_manager import AuthManager

def setup_logging():
    log_dir = Path.home() / ".aimas" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "aimas.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
    )

class MainWindow(QMainWindow):
    status_update = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AIMAS - Cyber Security Toolkit")
        self.setWindowIcon(QIcon("aimas_icon.png"))
        self.resize(1200, 800)

        self.apply_dark_style()
        self.status_update.connect(self.update_status_bar)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # ---------- Network Module (nested tabs) ----------
        self.network_tabs = QTabWidget()
        self.my_network_tab = MyNetworkWidget()
        self.my_network_tab.status_update.connect(self.status_update.emit)
        self.network_tabs.addTab(self.my_network_tab, "🌐 My Network")
        self.device_mapper_tab = DeviceMapperWidget()
        self.device_mapper_tab.status_update.connect(self.status_update.emit)
        self.device_mapper_tab.send_to_radar.connect(self.on_send_to_radar)
        self.device_mapper_tab.send_to_notes.connect(self.on_send_to_notes)
        self.network_tabs.addTab(self.device_mapper_tab, "📡 Device Mapper")
        self.network_radar_tab = NetworkRadarWidget()
        self.network_radar_tab.status_update.connect(self.status_update.emit)
        self.network_tabs.addTab(self.network_radar_tab, "🔍 Network Radar")
        self.http_sharing_tab = HTTPSharingWidget()
        self.http_sharing_tab.status_update.connect(self.status_update.emit)
        self.network_tabs.addTab(self.http_sharing_tab, "📁 HTTP Sharing")
        self.tabs.addTab(self.network_tabs, "🌍 Network")

        # ---------- Web Module (nested tabs) ----------
        self.web_tabs = QTabWidget()
        self.recon_tab = ReconWebWidget()
        self.recon_tab.status_update.connect(self.status_update.emit)
        self.web_tabs.addTab(self.recon_tab, "🕵️ Recon")
        self.hidden_tab = HiddenWidget()
        self.hidden_tab.status_update.connect(self.status_update.emit)
        self.web_tabs.addTab(self.hidden_tab, "🔍 Hidden")
        self.vuln_tab = VulnScannerWidget()
        self.vuln_tab.status_update.connect(self.status_update.emit)
        self.web_tabs.addTab(self.vuln_tab, "⚠️ Vuln Scanner")
        self.waf_tab = WAFDetectorWidget()
        self.waf_tab.status_update.connect(self.status_update.emit)
        self.web_tabs.addTab(self.waf_tab, "🛡️ WAF Detector")
        self.tabs.addTab(self.web_tabs, "🌍 Web")

        # ---------- Cryptography Module (nested tabs) ----------
        self.crypto_tabs = QTabWidget()
        self.cipher_tab = CipherIdentifierWidget()
        self.cipher_tab.status_update.connect(self.status_update.emit)
        self.crypto_tabs.addTab(self.cipher_tab, "🔍 Cipher Identifier")
        self.encrypt_tab = EncryptWidget()
        self.encrypt_tab.status_update.connect(self.status_update.emit)
        self.crypto_tabs.addTab(self.encrypt_tab, "🔐 Encrypt")
        self.decrypt_tab = DecryptWidget()
        self.decrypt_tab.status_update.connect(self.status_update.emit)
        self.crypto_tabs.addTab(self.decrypt_tab, "🔓 Decrypt")
        self.tabs.addTab(self.crypto_tabs, "🔐 Cryptography")

        # ---------- OSINT-AI Module (nested tabs) ----------
        self.osint_tabs = QTabWidget()
        self.email_tab = EmailOSINTWidget()
        self.email_tab.status_update.connect(self.status_update.emit)
        self.osint_tabs.addTab(self.email_tab, "📧 Email OSINT")
        self.phone_tab = PhoneOSINTWidget()
        self.phone_tab.status_update.connect(self.status_update.emit)
        self.osint_tabs.addTab(self.phone_tab, "📞 Phone OSINT")
        self.image_tab = ImageMetadataWidget()
        self.image_tab.status_update.connect(self.status_update.emit)
        self.osint_tabs.addTab(self.image_tab, "🖼️ Image Metadata")
        self.chat_tab = ChatAIWidget()
        self.chat_tab.status_update.connect(self.status_update.emit)
        self.osint_tabs.addTab(self.chat_tab, "🤖 Chat AI")
        self.tabs.addTab(self.osint_tabs, "🧠 OSINT-AI")

        # ---------- Phishing Module (Zphisher‑like) ----------
        self.phishing_tab = ZphisherLikeWidget()
        self.phishing_tab.status_update.connect(self.status_update.emit)
        self.tabs.addTab(self.phishing_tab, "🎣 Phishing")

        # Notes module removed

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def apply_dark_style(self):
        dark_qss = """
        QWidget { background-color: #0D1117; color: #E6EDF3; font-family: "Inter"; font-size: 13px; }
        QPushButton { background-color: #1C2128; border: 1px solid #30363D; border-radius: 4px; padding: 6px; }
        QPushButton:hover { border-color: #00FF9C; }
        QTableWidget { background-color: #161B22; alternate-background-color: #1C2128; gridline-color: #30363D; }
        QHeaderView::section { background-color: #0D1117; color: #00B4D8; padding: 6px; }
        QLineEdit, QTextEdit { background-color: #161B22; border: 1px solid #30363D; border-radius: 4px; }
        QGroupBox { border: 1px solid #30363D; border-radius: 6px; margin-top: 12px; }
        QTabWidget::pane { border: 1px solid #30363D; background-color: #0D1117; }
        QTabBar::tab { background-color: #161B22; padding: 8px 16px; border: 1px solid #30363D; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; }
        QTabBar::tab:selected { background-color: #1C2128; color: #00FF9C; border-bottom: 2px solid #00FF9C; }
        QProgressBar { border: 1px solid #30363D; border-radius: 4px; text-align: center; }
        QProgressBar::chunk { background-color: #00FF9C; width: 10px; margin: 0px; }
        """
        self.setStyleSheet(dark_qss)

    def update_status_bar(self, message: str):
        self.status_bar.showMessage(message, 5000)

    def on_send_to_radar(self, ip: str):
        self.tabs.setCurrentWidget(self.network_tabs)
        self.network_tabs.setCurrentWidget(self.network_radar_tab)
        self.network_radar_tab.target_input.setText(ip)
        self.status_update.emit(f"Loaded target {ip} into Network Radar")

    def on_send_to_notes(self, content: str):
        self.status_update.emit(f"Note: {content[:80]}... (Notes module not available)")

    def closeEvent(self, event):
        logging.info("Shutting down AIMAS")
        if hasattr(self, 'phishing_tab') and hasattr(self.phishing_tab, 'stop_server'):
            self.phishing_tab.stop_server()
        if hasattr(self, 'http_sharing_tab'):
            self.http_sharing_tab.stop_server()
        event.accept()

def main():
    setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("AIMAS")
    app.setOrganizationName("ANU")
    app.setWindowIcon(QIcon("aimas_icon.png"))

    # Request sudo authentication; exit if failed
    if not AuthManager.authenticate():
        QMessageBox.critical(None, "Authentication Failed",
                             "Sudo authentication failed. The application will now exit.")
        sys.exit(1)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
