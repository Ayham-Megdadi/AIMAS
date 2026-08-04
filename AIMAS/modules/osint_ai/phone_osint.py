#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phone OSINT Module - Enhanced parsing, carrier, timezone, links, and export.
"""

import logging
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from pathlib import Path
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QLabel, QScrollArea, QGroupBox, QFormLayout, QMessageBox, QFileDialog,
    QApplication, QGridLayout
)
from PyQt6.QtGui import QDesktopServices

from core.event_bus import EventBus

logger = logging.getLogger(__name__)

# Emoji flags mapping (simple version)
FLAG_EMOJI = {
    "US": "🇺🇸", "GB": "🇬🇧", "SA": "🇸🇦", "AE": "🇦🇪", "EG": "🇪🇬", "JO": "🇯🇴",
    "PS": "🇵🇸", "IQ": "🇮🇶", "SY": "🇸🇾", "LB": "🇱🇧", "YE": "🇾🇪", "OM": "🇴🇲",
    "QA": "🇶🇦", "KW": "🇰🇼", "BH": "🇧🇭", "TR": "🇹🇷", "IR": "🇮🇷", "DE": "🇩🇪",
    "FR": "🇫🇷", "IT": "🇮🇹", "ES": "🇪🇸", "RU": "🇷🇺", "CN": "🇨🇳", "IN": "🇮🇳",
    "PK": "🇵🇰", "BD": "🇧🇩", "ZA": "🇿🇦", "NG": "🇳🇬", "BR": "🇧🇷", "MX": "🇲🇽",
    "CA": "🇨🇦", "AU": "🇦🇺", "NZ": "🇳🇿", "JP": "🇯🇵", "KR": "🇰🇷", "ID": "🇮🇩"
}
DEFAULT_FLAG = "🏳️"


def get_flag(country_code: str) -> str:
    return FLAG_EMOJI.get(country_code.upper(), DEFAULT_FLAG)


class PhoneInvestigateWorker(QThread):
    parsed_info = pyqtSignal(dict)
    platform_result = pyqtSignal(str, str, str)  # platform, status, url
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, number: str):
        super().__init__()
        self.number = number
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        try:
            parsed = phonenumbers.parse(self.number, None)
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            country_code = phonenumbers.region_code_for_number(parsed)
            country_name = geocoder.description_for_number(parsed, 'en')
            line_type = phonenumbers.number_type(parsed)
            line_type_str = self._line_type_str(line_type)
            carrier_name = carrier.name_for_number(parsed, 'en')
            timezones_list = list(timezone.time_zones_for_number(parsed))
            tz_str = ', '.join(timezones_list)
            location_desc = geocoder.description_for_number(parsed, 'en')
            # Additional formats
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            international = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            info = {
                'original': self.number,
                'is_valid': is_valid,
                'is_possible': is_possible,
                'country_code': country_code,
                'flag': get_flag(country_code),
                'country_name': country_name,
                'line_type': line_type_str,
                'carrier': carrier_name if carrier_name else "Unknown",
                'timezones': tz_str,
                'location': location_desc,
                'e164': e164,
                'international': international,
                'national': national,
                'national_number': str(parsed.national_number),
                'country_dialing_code': parsed.country_code
            }
            self.parsed_info.emit(info)
            if self._abort:
                return

            digits = str(parsed.national_number)
            e164_clean = e164.lstrip('+')
            # Telegram (link)
            url_telegram = f"https://t.me/+{digits}"
            self.platform_result.emit("Telegram", "Link generated", url_telegram)
            # WhatsApp
            url_wa = f"https://wa.me/{e164_clean}"
            self.platform_result.emit("WhatsApp", "Link generated", url_wa)
            # Signal
            url_signal = f"https://signal.me/#p/{e164_clean}"
            self.platform_result.emit("Signal", "Link generated", url_signal)
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def _line_type_str(self, typ):
        types = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
        }
        return types.get(typ, "Unknown")


class PhoneOSINTWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.platforms = []  # store (platform, status, url)
        self.parsed_info = None
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Input area
        input_layout = QHBoxLayout()
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("+962791234567")
        self.investigate_btn = QPushButton("Investigate")
        input_layout.addWidget(self.phone_input)
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

    def connect_signals(self):
        self.investigate_btn.clicked.connect(self.start_investigation)
        self.save_notes_btn.clicked.connect(self.save_to_notes)
        self.copy_report_btn.clicked.connect(self.copy_report)
        self.export_html_btn.clicked.connect(self.export_html)
        self.export_pdf_btn.clicked.connect(self.export_pdf)

    def start_investigation(self):
        number = self.phone_input.text().strip()
        if not number:
            QMessageBox.warning(self, "No Number", "Please enter a phone number.")
            return
        try:
            phonenumbers.parse(number, None)
        except Exception:
            QMessageBox.warning(
                self,
                "Invalid Number",
                "Please enter a valid international phone number (e.g., +962791234567)."
            )
            return

        if self.worker and self.worker.isRunning():
            self.worker.abort()
            self.worker.wait()
        self.clear_results()
        self.status_label.setText(f"Investigating {number}...")
        self.status_update.emit(f"Starting phone OSINT for {number}")
        self.worker = PhoneInvestigateWorker(number)
        self.worker.parsed_info.connect(self.display_parsed)
        self.worker.platform_result.connect(self.add_platform)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def clear_results(self):
        while self.results_layout.count():
            child = self.results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.platforms = []
        self.parsed_info = None

    def display_parsed(self, info: dict):
        # Main card
        main_card = QGroupBox("📞 Phone Number Information")
        main_layout = QVBoxLayout(main_card)

        # Header with flag and country
        header = QHBoxLayout()
        flag_label = QLabel(info['flag'])
        flag_label.setStyleSheet("font-size: 32px;")
        country_label = QLabel(f"<b>{info['country_name']}</b> ({info['country_code']})")
        header.addWidget(flag_label)
        header.addWidget(country_label)
        header.addStretch()
        main_layout.addLayout(header)

        # Grid of details
        grid = QGridLayout()
        grid.addWidget(QLabel("📌 Validity:"), 0, 0)
        validity = "✅ Valid" if info['is_valid'] else "❌ Invalid"
        validity += " / " + ("✅ Possible" if info['is_possible'] else "❌ Impossible")
        grid.addWidget(QLabel(validity), 0, 1)
        grid.addWidget(QLabel("📱 Line Type:"), 1, 0)
        grid.addWidget(QLabel(info['line_type']), 1, 1)
        grid.addWidget(QLabel("🏢 Carrier:"), 2, 0)
        grid.addWidget(QLabel(info['carrier']), 2, 1)
        grid.addWidget(QLabel("🌍 Timezone:"), 3, 0)
        grid.addWidget(QLabel(info['timezones']), 3, 1)
        grid.addWidget(QLabel("📍 Location:"), 4, 0)
        grid.addWidget(QLabel(info['location']), 4, 1)
        main_layout.addLayout(grid)

        # Formats section
        formats_group = QGroupBox("📎 Formatted Numbers")
        formats_layout = QVBoxLayout(formats_group)
        for fmt_name, fmt_val in [("E.164", info['e164']),
                                  ("International", info['international']),
                                  ("National", info['national'])]:
            row = QHBoxLayout()
            row.addWidget(QLabel(f"{fmt_name}:"))
            val_label = QLabel(fmt_val)
            val_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(val_label)
            copy_btn = QPushButton("Copy")
            copy_btn.clicked.connect(lambda checked, txt=fmt_val: QApplication.clipboard().setText(txt))
            row.addWidget(copy_btn)
            formats_layout.addLayout(row)
        main_layout.addWidget(formats_group)

        self.results_layout.addWidget(main_card)
        self.parsed_info = info

    def add_platform(self, platform: str, status: str, url: str):
        self.platforms.append((platform, status, url))
        self._rebuild_platforms()

    def _rebuild_platforms(self):
        # Remove existing platforms group
        for i in range(self.results_layout.count()):
            w = self.results_layout.itemAt(i).widget()
            if w and isinstance(w, QGroupBox) and w.title() == "🔗 Platform Links":
                w.deleteLater()
                break
        group = QGroupBox("🔗 Platform Links")
        layout = QVBoxLayout(group)
        for platform, status, url in self.platforms:
            row = QHBoxLayout()
            row.addWidget(QLabel(f"<b>{platform}</b>"))
            row.addWidget(QLabel(status))
            if url:
                btn_open = QPushButton("Open in Browser")
                btn_open.clicked.connect(lambda checked, u=url: QDesktopServices.openUrl(QUrl(u)))
                row.addWidget(btn_open)
                btn_copy = QPushButton("Copy URL")
                btn_copy.clicked.connect(lambda checked, u=url: QApplication.clipboard().setText(u))
                row.addWidget(btn_copy)
            else:
                row.addWidget(QLabel("Not available"))
            row.addStretch()
            layout.addLayout(row)
        self.results_layout.addWidget(group)

    def on_finished(self):
        self.status_label.setText("Investigation completed.")
        self.status_update.emit("Phone OSINT completed.")
        self.worker = None

    def on_error(self, err: str):
        self.status_label.setText(f"Error: {err}")
        self.status_update.emit(f"Phone OSINT error: {err}")
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
        path, _ = QFileDialog.getSaveFileName(self, "Save HTML", "phone_report.html", "HTML (*.html)")
        if path:
            Path(path).write_text(self._generate_html(), encoding='utf-8')
            self.status_update.emit(f"Saved to {path}")

    def export_pdf(self):
        from weasyprint import HTML
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "phone_report.pdf", "PDF (*.pdf)")
        if not path:
            return
        try:
            HTML(string=self._generate_html()).write_pdf(path)
            self.status_update.emit(f"PDF saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _generate_markdown(self) -> str:
        md = f"# Phone OSINT Report\n\n**Number:** {self.phone_input.text()}\n\n"
        if self.parsed_info:
            info = self.parsed_info
            md += f"- **Country:** {info['flag']} {info['country_name']}\n"
            md += f"- **Valid:** {info['is_valid']} | **Line Type:** {info['line_type']}\n"
            md += f"- **Carrier:** {info['carrier']}\n"
            md += f"- **E.164:** `{info['e164']}`\n"
            md += f"- **International:** `{info['international']}`\n"
        if self.platforms:
            md += "\n## Platform Links\n"
            for p, s, u in self.platforms:
                md += f"- **{p}**: {s} – {u}\n"
        return md

    def _generate_html(self) -> str:
        html = f"<html><head><title>Phone OSINT Report</title>"
        html += "<style>body{font-family:sans-serif;} table, th, td{border:1px solid #ddd;border-collapse:collapse;padding:6px;}</style>"
        html += f"</head><body><h1>Phone OSINT Report</h1><p>Number: {self.phone_input.text()}</p>"
        if self.parsed_info:
            info = self.parsed_info
            html += f"<h2>Details</h2><ul>"
            html += f"<li><strong>Country:</strong> {info['flag']} {info['country_name']}</li>"
            html += f"<li><strong>Valid:</strong> {info['is_valid']}</li>"
            html += f"<li><strong>Line Type:</strong> {info['line_type']}</li>"
            html += f"<li><strong>Carrier:</strong> {info['carrier']}</li>"
            html += f"<li><strong>E.164:</strong> {info['e164']}</li>"
            html += f"<li><strong>International:</strong> {info['international']}</li>"
            html += f"<li><strong>Timezone:</strong> {info['timezones']}</li>"
            html += f"<li><strong>Location:</strong> {info['location']}</li></ul>"
        if self.platforms:
            html += "<h2>Platform Links</h2><ul>"
            for p, s, u in self.platforms:
                html += f"<li><strong>{p}</strong>: {s} – <a href='{u}'>{u}</a></li>"
            html += "</ul>"
        html += "</body></html>"
        return html

    def get_module_name(self) -> str:
        return "Phone OSINT"
