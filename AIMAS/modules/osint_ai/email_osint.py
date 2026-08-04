#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Email OSINT Module - Enhanced with breach details, disposable detection, and full reporting.
"""

import re
import hashlib
import logging
import requests
import dns.resolver
from pathlib import Path
from tempfile import NamedTemporaryFile
from datetime import datetime
from typing import List, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal, Qt, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QLabel, QScrollArea, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QFileDialog, QApplication, QGridLayout
)
from PyQt6.QtGui import QPixmap, QDesktopServices

from core.event_bus import EventBus
from core.config_manager import ConfigManager
from services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

# List of disposable/temporary email domains (partial)
DISPOSABLE_DOMAINS = {
    "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com",
    "trashmail.com", "yopmail.com", "throwaway.email", "temp-mail.org",
    "dispostable.com", "getnada.com", "mailnator.com", "mintemail.com",
    "sharklasers.com", "spamgourmet.com", "sogetthis.com", "tempail.com",
    "zippymail.info", "guerrillamail.org", "guerrillamail.net", "guerrillamail.biz"
}


def is_disposable_domain(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS


class EmailInvestigateWorker(QThread):
    hibp_result = pyqtSignal(dict)          # {'status': 'pwned'/'clean'/'no_key'/'error', 'breaches': []}
    gravatar_result = pyqtSignal(dict)      # {'found': bool, 'pixmap': QPixmap or None}
    social_result = pyqtSignal(dict)        # {'platform': str, 'status': str, 'url': str}
    mx_result = pyqtSignal(dict)            # {'domain': str, 'mx_records': list, 'error': str, 'valid_mx': bool}
    domain_info = pyqtSignal(dict)          # {'domain': str, 'disposable': bool, 'age_days': int, 'registrar': str}
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, email: str):
        super().__init__()
        self.email = email.lower().strip()
        self._abort = False
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'AIMAS/1.0'})

    def abort(self):
        self._abort = True
        self.session.close()

    def run(self):
        try:
            # 1. Domain & MX checks
            domain = self.email.split('@')[1]
            self._check_mx(domain)
            if self._abort: return
            self._check_domain_info(domain)
            if self._abort: return

            # 2. HIBP
            self._check_hibp()
            if self._abort: return

            # 3. Gravatar
            self._check_gravatar()
            if self._abort: return

            # 4. Social platforms
            self._check_github()
            if self._abort: return
            self._check_reddit()
            if self._abort: return
            self._check_twitter()
            if self._abort: return
            self._check_linkedin()

            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def _check_mx(self, domain: str):
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(r.exchange).rstrip('.') for r in answers]
            valid_mx = len(mx_records) > 0
            self.mx_result.emit({'domain': domain, 'mx_records': mx_records, 'valid_mx': valid_mx, 'error': None})
        except Exception as e:
            self.mx_result.emit({'domain': domain, 'mx_records': [], 'valid_mx': False, 'error': str(e)})

    def _check_domain_info(self, domain: str):
        disposable = is_disposable_domain(domain)
        # Optionally query WHOIS for age (would require external tool; skip for speed)
        self.domain_info.emit({'domain': domain, 'disposable': disposable, 'age_days': None, 'registrar': ''})

    def _check_hibp(self):
        config = ConfigManager()
        api_key = config.get_secret('hibp_key')
        if not api_key:
            self.hibp_result.emit({'status': 'no_key', 'breaches': []})
            return
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.email}"
        headers = {'hibp-api-key': api_key}
        try:
            resp = self.session.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                breaches = resp.json()
                self.hibp_result.emit({'status': 'pwned', 'breaches': breaches})
            elif resp.status_code == 404:
                self.hibp_result.emit({'status': 'clean', 'breaches': []})
            else:
                self.hibp_result.emit({'status': 'error', 'breaches': []})
        except Exception as e:
            logger.error(f"HIBP error: {e}")
            self.hibp_result.emit({'status': 'error', 'breaches': []})

    def _check_gravatar(self):
        email_hash = hashlib.md5(self.email.encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200 and resp.content:
                with NamedTemporaryFile(suffix='.png', delete=False) as f:
                    f.write(resp.content)
                    pixmap = QPixmap(f.name)
                    Path(f.name).unlink()
                self.gravatar_result.emit({'found': True, 'pixmap': pixmap})
            else:
                self.gravatar_result.emit({'found': False, 'pixmap': None})
        except Exception as e:
            logger.error(f"Gravatar error: {e}")
            self.gravatar_result.emit({'found': False, 'pixmap': None})

    def _check_github(self):
        prefix = self.email.split('@')[0]
        url = f"https://api.github.com/search/users?q={prefix}"
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('total_count', 0) > 0:
                    self.social_result.emit({
                        'platform': 'GitHub',
                        'status': 'Possible match',
                        'url': f"https://github.com/search?q={prefix}"
                    })
                else:
                    self.social_result.emit({'platform': 'GitHub', 'status': 'Not found', 'url': ''})
            else:
                self.social_result.emit({'platform': 'GitHub', 'status': 'Error', 'url': ''})
        except Exception as e:
            logger.error(f"GitHub error: {e}")
            self.social_result.emit({'platform': 'GitHub', 'status': 'Error', 'url': ''})

    def _check_reddit(self):
        username = self.email.split('@')[0]
        url = f"https://www.reddit.com/user/{username}/about.json"
        try:
            resp = self.session.get(url, timeout=15, headers={'User-Agent': 'AIMAS/1.0'})
            if resp.status_code == 200:
                self.social_result.emit({
                    'platform': 'Reddit',
                    'status': 'Found',
                    'url': f"https://www.reddit.com/user/{username}"
                })
            else:
                self.social_result.emit({'platform': 'Reddit', 'status': 'Not found', 'url': ''})
        except Exception as e:
            logger.error(f"Reddit error: {e}")
            self.social_result.emit({'platform': 'Reddit', 'status': 'Error', 'url': ''})

    def _check_twitter(self):
        username = self.email.split('@')[0]
        url = f"https://twitter.com/{username}"
        try:
            resp = self.session.head(url, timeout=15, allow_redirects=True)
            if resp.status_code == 200:
                self.social_result.emit({'platform': 'Twitter/X', 'status': 'Found', 'url': url})
            else:
                self.social_result.emit({'platform': 'Twitter/X', 'status': 'Not found', 'url': ''})
        except Exception as e:
            logger.error(f"Twitter error: {e}")
            self.social_result.emit({'platform': 'Twitter/X', 'status': 'Error', 'url': ''})

    def _check_linkedin(self):
        username = self.email.split('@')[0]
        url = f"https://www.linkedin.com/in/{username}"
        try:
            resp = self.session.head(url, timeout=10, allow_redirects=False)
            if resp.status_code == 200:
                self.social_result.emit({'platform': 'LinkedIn', 'status': 'Possible profile', 'url': url})
            else:
                self.social_result.emit({'platform': 'LinkedIn', 'status': 'Not found', 'url': ''})
        except:
            pass


class EmailOSINTWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.social_data = []
        self.hibp_breaches = []
        self.domain_data = {}
        self.mx_data = None
        self.gravatar_pixmap = None
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Input area
        input_layout = QHBoxLayout()
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email address (e.g., user@example.com)")
        self.investigate_btn = QPushButton("Investigate")
        input_layout.addWidget(self.email_input)
        input_layout.addWidget(self.investigate_btn)
        layout.addLayout(input_layout)

        # Scrollable results area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        self.results_widget = QWidget()
        self.results_layout = QVBoxLayout(self.results_widget)
        self.results_layout.setSpacing(10)
        scroll.setWidget(self.results_widget)
        layout.addWidget(scroll)

        # Toolbar
        toolbar = QHBoxLayout()
        self.save_notes_btn = QPushButton("Save to Notes")
        self.copy_report_btn = QPushButton("Copy Report")
        self.export_html_btn = QPushButton("Export HTML")
        self.export_pdf_btn = QPushButton("Export PDF")
        toolbar.addWidget(self.save_notes_btn)
        toolbar.addWidget(self.copy_report_btn)
        toolbar.addWidget(self.export_html_btn)
        toolbar.addWidget(self.export_pdf_btn)
        layout.addLayout(toolbar)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        self.clear_results()

    def connect_signals(self):
        self.investigate_btn.clicked.connect(self.start_investigation)
        self.save_notes_btn.clicked.connect(self.save_to_notes)
        self.copy_report_btn.clicked.connect(self.copy_report)
        self.export_html_btn.clicked.connect(self.export_html)
        self.export_pdf_btn.clicked.connect(self.export_pdf)

    def validate_email(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def start_investigation(self):
        email = self.email_input.text().strip()
        if not self.validate_email(email):
            QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address.")
            return
        if self.worker and self.worker.isRunning():
            self.worker.abort()
            self.worker.wait()
        self.clear_results()
        self.status_label.setText(f"Investigating {email}...")
        self.status_update.emit(f"Starting OSINT investigation for {email}")
        self.worker = EmailInvestigateWorker(email)
        self.worker.hibp_result.connect(self.display_hibp)
        self.worker.gravatar_result.connect(self.display_gravatar)
        self.worker.social_result.connect(self.add_social_result)
        self.worker.mx_result.connect(self.display_mx)
        self.worker.domain_info.connect(self.display_domain_info)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def clear_results(self):
        while self.results_layout.count():
            child = self.results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.social_data = []
        self.hibp_breaches = []
        self.domain_data = {}
        self.mx_data = None
        self.gravatar_pixmap = None

    def display_domain_info(self, info: dict):
        group = QGroupBox("🌐 Domain Information")
        layout = QVBoxLayout(group)
        layout.addWidget(QLabel(f"Domain: <b>{info['domain']}</b>"))
        if info['disposable']:
            layout.addWidget(QLabel("⚠️ This domain is a <b>disposable/temporary email</b> service."))
        else:
            layout.addWidget(QLabel("✅ Domain is not recognized as disposable."))
        self.results_layout.addWidget(group)
        self.domain_data = info

    def display_mx(self, result: dict):
        group = QGroupBox("📧 Mail Exchange (MX) Records")
        layout = QVBoxLayout(group)
        if result.get('error'):
            layout.addWidget(QLabel(f"Error: {result['error']}"))
        else:
            if result['valid_mx']:
                layout.addWidget(QLabel(f"✅ Found {len(result['mx_records'])} MX record(s):"))
                for mx in result['mx_records']:
                    layout.addWidget(QLabel(f"• {mx}"))
            else:
                layout.addWidget(QLabel("❌ No MX records found. Email may not be deliverable."))
        self.results_layout.addWidget(group)
        self.mx_data = result

    def display_hibp(self, result: dict):
        group = QGroupBox("🔓 Have I Been Pwned (HIBP)")
        layout = QVBoxLayout(group)
        if result['status'] == 'no_key':
            layout.addWidget(QLabel("⚠️ No HIBP API key configured. Add it in Settings."))
        elif result['status'] == 'clean':
            layout.addWidget(QLabel("✅ No breaches found for this email."))
        elif result['status'] == 'pwned':
            breaches = result['breaches']
            layout.addWidget(QLabel(f"⚠️ This email was found in <b>{len(breaches)} breach(es)</b>:"))
            for breach in breaches:
                breach_group = QGroupBox(breach.get('Name', 'Unknown'))
                bl = QVBoxLayout(breach_group)
                bl.addWidget(QLabel(f"Domain: {breach.get('Domain', 'N/A')}"))
                bl.addWidget(QLabel(f"Date: {breach.get('BreachDate', 'N/A')}"))
                data_classes = ', '.join(breach.get('DataClasses', []))
                bl.addWidget(QLabel(f"Data classes: {data_classes}"))
                bl.addWidget(QLabel(f"Description: {breach.get('Description', 'N/A')[:200]}..."))
                layout.addWidget(breach_group)
            self.hibp_breaches = breaches
        else:
            layout.addWidget(QLabel("❌ Error checking HIBP."))
        self.results_layout.addWidget(group)

    def display_gravatar(self, result: dict):
        group = QGroupBox("🖼️ Gravatar")
        layout = QHBoxLayout(group)
        if result['found'] and result['pixmap']:
            label = QLabel()
            label.setPixmap(result['pixmap'].scaled(150, 150, Qt.AspectRatioMode.KeepAspectRatio))
            label.setStyleSheet("border-radius: 75px; background-color: #1C2128;")
            layout.addWidget(label)
            layout.addWidget(QLabel("Gravatar profile found"))
            self.gravatar_pixmap = result['pixmap']
        else:
            layout.addWidget(QLabel("No Gravatar profile associated."))
        layout.addStretch()
        self.results_layout.addWidget(group)

    def add_social_result(self, result: dict):
        self.social_data.append(result)
        self._rebuild_social_table()

    def _rebuild_social_table(self):
        for i in range(self.results_layout.count()):
            w = self.results_layout.itemAt(i).widget()
            if w and isinstance(w, QGroupBox) and w.title() == "🌐 Social Platforms":
                w.deleteLater()
                break
        group = QGroupBox("🌐 Social Platforms")
        layout = QVBoxLayout(group)
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Platform", "Status", "Action"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setRowCount(len(self.social_data))
        for row, data in enumerate(self.social_data):
            table.setItem(row, 0, QTableWidgetItem(data['platform']))
            status_item = QTableWidgetItem(data['status'])
            if 'Found' in data['status']:
                status_item.setForeground(Qt.GlobalColor.green)
            elif 'Possible' in data['status']:
                status_item.setForeground(Qt.GlobalColor.yellow)
            elif data['status'] == 'Error':
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.gray)
            table.setItem(row, 1, status_item)
            if data['url']:
                btn = QPushButton("Open")
                btn.clicked.connect(lambda checked, url=data['url']: QDesktopServices.openUrl(QUrl(url)))
                table.setCellWidget(row, 2, btn)
            else:
                table.setItem(row, 2, QTableWidgetItem("-"))
        layout.addWidget(table)
        self.results_layout.addWidget(group)

    def on_finished(self):
        self.status_label.setText("Investigation completed.")
        self.status_update.emit("Email OSINT completed.")
        self.worker = None

    def on_error(self, err: str):
        self.status_label.setText(f"Error: {err}")
        self.status_update.emit(f"Email OSINT error: {err}")
        QMessageBox.critical(self, "Error", err)
        self.worker = None

    def save_to_notes(self):
        content = self._generate_markdown()
        EventBus().send_to_notes.emit(content)
        self.status_update.emit("Report sent to Notes.")

    def copy_report(self):
        QApplication.clipboard().setText(self._generate_markdown())
        self.status_update.emit("Report copied.")

    def export_html(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save HTML", "email_report.html", "HTML (*.html)")
        if path:
            Path(path).write_text(self._generate_html(), encoding='utf-8')
            self.status_update.emit(f"Saved to {path}")

    def export_pdf(self):
        from weasyprint import HTML
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "email_report.pdf", "PDF (*.pdf)")
        if not path:
            return
        try:
            HTML(string=self._generate_html()).write_pdf(path)
            self.status_update.emit(f"PDF saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _generate_markdown(self) -> str:
        email = self.email_input.text()
        md = f"# Email OSINT Report\n\n**Email:** {email}\n\n"
        if self.domain_data:
            md += f"## Domain\n- {self.domain_data['domain']}\n"
            if self.domain_data.get('disposable'):
                md += "- ⚠️ Disposable/temporary email domain\n"
        if self.mx_data and self.mx_data.get('valid_mx'):
            md += "\n## MX Records\n" + "\n".join([f"- {mx}" for mx in self.mx_data['mx_records']])
        if self.hibp_breaches:
            md += f"\n\n## Breaches ({len(self.hibp_breaches)})\n"
            for b in self.hibp_breaches:
                md += f"- **{b.get('Name')}** ({b.get('BreachDate')}) – {', '.join(b.get('DataClasses', []))}\n"
        else:
            md += "\n\n## Breaches: No known breaches.\n"
        if self.social_data:
            md += "\n## Social Platforms\n"
            for s in self.social_data:
                md += f"- {s['platform']}: {s['status']} {s['url'] if s['url'] else ''}\n"
        return md

    def _generate_html(self) -> str:
        email = self.email_input.text()
        html = f"<html><head><title>Email OSINT Report</title><style>body{{font-family:sans-serif;}} table, th, td{{border:1px solid #ddd;border-collapse:collapse;padding:6px;}}</style></head><body>"
        html += f"<h1>Email OSINT Report</h1><p><strong>Email:</strong> {email}</p>"
        if self.domain_data:
            html += f"<h2>Domain</h2><p><strong>{self.domain_data['domain']}</strong>"
            if self.domain_data.get('disposable'):
                html += " <span style='color:red;'>(Disposable/Temporary)</span>"
            html += "</p>"
        if self.mx_data and self.mx_data.get('valid_mx'):
            html += "<h2>MX Records</h2><ul>"
            for mx in self.mx_data['mx_records']:
                html += f"<li>{mx}</li>"
            html += "</ul>"
        if self.hibp_breaches:
            html += f"<h2>Breaches ({len(self.hibp_breaches)})</h2><ul>"
            for b in self.hibp_breaches:
                html += f"<li><b>{b.get('Name')}</b> ({b.get('BreachDate')}) – {', '.join(b.get('DataClasses', []))}</li>"
            html += "</ul>"
        else:
            html += "<h2>Breaches</h2><p>No known breaches.</p>"
        if self.social_data:
            html += "<h2>Social Platforms</h2><ul>"
            for s in self.social_data:
                html += f"<li><b>{s['platform']}</b>: {s['status']}"
                if s['url']:
                    html += f" (<a href='{s['url']}'>link</a>)"
                html += "</li>"
            html += "</ul>"
        html += "</body></html>"
        return html

    def get_module_name(self) -> str:
        return "Email OSINT"
