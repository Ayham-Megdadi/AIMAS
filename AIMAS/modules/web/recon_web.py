#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Recon Web Module - WHOIS, DNS, Ping, Traceroute
"""

import re
import subprocess
import logging
from typing import List, Dict
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QFormLayout, QLabel, QTextEdit, QFileDialog, QMessageBox, QApplication, QMenu
)
from PyQt6.QtGui import QAction

from core.project_manager import ProjectManager

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

logger = logging.getLogger(__name__)


class AimasTerminal(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet("background-color: #0D1117; color: #E6EDF3; font-family: 'JetBrains Mono'; font-size: 11px;")


class WhoisWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        try:
            proc = subprocess.run(['whois', self.target], capture_output=True, text=True, timeout=30)
            if self._abort:
                return
            output = proc.stdout.replace('\r\n', '\n')
            self.finished.emit(output)
        except Exception as e:
            self.error.emit(str(e))


class DNSWorker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        records = []
        types = ['A', 'MX', 'NS', 'TXT', 'AAAA']
        for typ in types:
            if self._abort:
                break
            try:
                proc = subprocess.run(['dig', self.target, typ, '+short'], capture_output=True, text=True, timeout=10)
                for line in proc.stdout.splitlines():
                    if line.strip():
                        records.append((typ, line.strip()))
            except:
                pass
        # Reverse lookup if IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', self.target):
            try:
                proc = subprocess.run(['dig', '-x', self.target, '+short'], capture_output=True, text=True, timeout=10)
                for line in proc.stdout.splitlines():
                    if line.strip():
                        records.append(('PTR', line.strip()))
            except:
                pass
        self.finished.emit(records)


class PingWorker(QThread):
    finished = pyqtSignal(dict, str)
    error = pyqtSignal(str)

    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        try:
            proc = subprocess.run(['ping', '-c', '4', self.target], capture_output=True, text=True, timeout=15)
            if self._abort:
                return
            stdout = proc.stdout
            stats = {}
            rtt_match = re.search(r'min/avg/max/[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)', stdout)
            if rtt_match:
                stats['min'] = rtt_match.group(1)
                stats['avg'] = rtt_match.group(2)
                stats['max'] = rtt_match.group(3)
            else:
                stats['min'] = stats['avg'] = stats['max'] = 'N/A'
            loss_match = re.search(r'(\d+)% packet loss', stdout)
            stats['loss'] = loss_match.group(1) if loss_match else '100'
            ip_match = re.search(r'PING\s+[^\(]+\(([\d.]+)\)', stdout)
            stats['ip'] = ip_match.group(1) if ip_match else 'unknown'
            self.finished.emit(stats, stdout)
        except Exception as e:
            self.error.emit(str(e))


class TracerouteWorker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        hops = []
        try:
            proc = subprocess.run(['traceroute', '-n', self.target], capture_output=True, text=True, timeout=60)
            if self._abort:
                return
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    hop_num = int(parts[0])
                    ip = parts[1]
                    rtt1 = parts[2] if len(parts) > 2 else '*'
                    rtt2 = parts[3] if len(parts) > 3 else '*'
                    rtt3 = parts[4] if len(parts) > 4 else '*'
                    hops.append({'hop': hop_num, 'ip': ip, 'rtt1': rtt1, 'rtt2': rtt2, 'rtt3': rtt3})
            self.finished.emit(hops)
        except Exception as e:
            self.error.emit(str(e))


class ReconWebWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_data = {}
        self.whois_raw = ""
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        input_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter domain or IP (e.g., google.com or 8.8.8.8)")
        self.run_btn = QPushButton("Run Recon")
        self.export_btn = QPushButton("Export ▾")
        input_layout.addWidget(self.target_input)
        input_layout.addWidget(self.run_btn)
        input_layout.addWidget(self.export_btn)
        layout.addLayout(input_layout)

        self.result_tabs = QTabWidget()
        layout.addWidget(self.result_tabs)

        # WHOIS tab - table
        whois_widget = QWidget()
        whois_layout = QVBoxLayout(whois_widget)
        whois_toolbar = QHBoxLayout()
        whois_copy_btn = QPushButton("Copy Raw WHOIS")
        whois_toolbar.addWidget(whois_copy_btn)
        whois_toolbar.addStretch()
        whois_layout.addLayout(whois_toolbar)
        self.whois_table = QTableWidget()
        self.whois_table.setColumnCount(2)
        self.whois_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.whois_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        whois_layout.addWidget(self.whois_table)
        self.result_tabs.addTab(whois_widget, "WHOIS")
        whois_copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.whois_raw))

        # DNS tab
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(2)
        self.dns_table.setHorizontalHeaderLabels(["Record Type", "Value"])
        self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.result_tabs.addTab(self.dns_table, "DNS")

        # Ping tab
        ping_widget = QWidget()
        ping_layout = QVBoxLayout(ping_widget)
        self.ping_stats_layout = QFormLayout()
        self.ping_ip_label = QLabel("--")
        self.ping_min_label = QLabel("--")
        self.ping_avg_label = QLabel("--")
        self.ping_max_label = QLabel("--")
        self.ping_loss_label = QLabel("--")
        self.ping_stats_layout.addRow("Host IP:", self.ping_ip_label)
        self.ping_stats_layout.addRow("Min RTT:", self.ping_min_label)
        self.ping_stats_layout.addRow("Avg RTT:", self.ping_avg_label)
        self.ping_stats_layout.addRow("Max RTT:", self.ping_max_label)
        self.ping_stats_layout.addRow("Packet Loss:", self.ping_loss_label)
        ping_layout.addLayout(self.ping_stats_layout)
        self.ping_terminal = AimasTerminal()
        self.ping_terminal.setMaximumHeight(200)
        ping_layout.addWidget(self.ping_terminal)
        self.result_tabs.addTab(ping_widget, "Ping")

        # Traceroute tab
        self.trace_table = QTableWidget()
        self.trace_table.setColumnCount(5)
        self.trace_table.setHorizontalHeaderLabels(["Hop", "IP", "RTT1", "RTT2", "RTT3"])
        self.trace_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.result_tabs.addTab(self.trace_table, "Traceroute")

        self.setLayout(layout)

    def connect_signals(self):
        self.run_btn.clicked.connect(self.run_recon)
        self.export_btn.clicked.connect(self.show_export_menu)

    def show_export_menu(self):
        menu = QMenu(self)
        html_action = QAction("Export as HTML", self)
        pdf_action = QAction("Export as PDF", self)
        html_action.triggered.connect(lambda: self._do_export('html'))
        pdf_action.triggered.connect(lambda: self._do_export('pdf'))
        menu.addAction(html_action)
        menu.addAction(pdf_action)
        menu.exec(self.export_btn.mapToGlobal(self.export_btn.rect().bottomLeft()))

    def _do_export(self, fmt: str):
        if not self.current_data:
            QMessageBox.warning(self, "No Data", "Run a recon first.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Export as {fmt.upper()}",
            f"recon_report.{fmt}", f"{fmt.upper()} Files (*.{fmt})"
        )
        if not file_path:
            return
        html = self.generate_html_report()
        try:
            if fmt == 'html':
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html)
                self.status_update.emit(f"HTML report saved to {file_path}")
            elif fmt == 'pdf':
                if not WEASYPRINT_AVAILABLE:
                    QMessageBox.critical(self, "Missing Library", "WeasyPrint not installed. Saving as HTML instead.")
                    alt_path = file_path.replace('.pdf', '.html')
                    with open(alt_path, 'w', encoding='utf-8') as f:
                        f.write(html)
                    self.status_update.emit(f"PDF failed, HTML saved to {alt_path}")
                    return
                HTML(string=html).write_pdf(file_path)
                self.status_update.emit(f"PDF report saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def run_recon(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Empty Target", "Please enter a domain or IP.")
            return
        self.status_update.emit(f"Starting recon on {target}...")
        self.clear_results()

        self.whois_worker = WhoisWorker(target)
        self.whois_worker.finished.connect(self.display_whois)
        self.whois_worker.error.connect(lambda e: self.status_update.emit(f"WHOIS error: {e}"))
        self.whois_worker.start()

        self.dns_worker = DNSWorker(target)
        self.dns_worker.finished.connect(self.display_dns)
        self.dns_worker.error.connect(lambda e: self.status_update.emit(f"DNS error: {e}"))
        self.dns_worker.start()

        self.ping_worker = PingWorker(target)
        self.ping_worker.finished.connect(self.display_ping)
        self.ping_worker.error.connect(lambda e: self.status_update.emit(f"Ping error: {e}"))
        self.ping_worker.start()

        self.trace_worker = TracerouteWorker(target)
        self.trace_worker.finished.connect(self.display_traceroute)
        self.trace_worker.error.connect(lambda e: self.status_update.emit(f"Traceroute error: {e}"))
        self.trace_worker.start()

    def clear_results(self):
        self.whois_table.setRowCount(0)
        self.whois_raw = ""
        self.dns_table.setRowCount(0)
        self.ping_terminal.clear()
        self.trace_table.setRowCount(0)
        self.ping_ip_label.setText("--")
        self.ping_min_label.setText("--")
        self.ping_avg_label.setText("--")
        self.ping_max_label.setText("--")
        self.ping_loss_label.setText("--")

    def display_whois(self, data: str):
        self.whois_raw = data
        rows = []
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('%'):
                continue
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip()
                val = val.strip()
                if key and val:
                    rows.append((key, val))
        self.whois_table.setRowCount(len(rows))
        for row, (key, val) in enumerate(rows):
            self.whois_table.setItem(row, 0, QTableWidgetItem(key))
            self.whois_table.setItem(row, 1, QTableWidgetItem(val))
        self.current_data['whois_raw'] = data

    def display_dns(self, records: list):
        self.dns_table.setRowCount(len(records))
        for row, (typ, val) in enumerate(records):
            self.dns_table.setItem(row, 0, QTableWidgetItem(typ))
            self.dns_table.setItem(row, 1, QTableWidgetItem(val))
        self.current_data['dns'] = records

    def display_ping(self, stats: dict, raw: str):
        self.ping_ip_label.setText(stats.get('ip', '--'))
        self.ping_min_label.setText(f"{stats.get('min', '--')} ms")
        self.ping_avg_label.setText(f"{stats.get('avg', '--')} ms")
        self.ping_max_label.setText(f"{stats.get('max', '--')} ms")
        self.ping_loss_label.setText(f"{stats.get('loss', '--')}%")
        self.ping_terminal.append(raw)
        self.current_data['ping'] = stats

    def display_traceroute(self, hops: list):
        self.trace_table.setRowCount(len(hops))
        for row, h in enumerate(hops):
            self.trace_table.setItem(row, 0, QTableWidgetItem(str(h['hop'])))
            self.trace_table.setItem(row, 1, QTableWidgetItem(h['ip']))
            self.trace_table.setItem(row, 2, QTableWidgetItem(h['rtt1']))
            self.trace_table.setItem(row, 3, QTableWidgetItem(h['rtt2']))
            self.trace_table.setItem(row, 4, QTableWidgetItem(h['rtt3']))
            if row == 0:
                for col in range(5):
                    if self.trace_table.item(row, col):
                        self.trace_table.item(row, col).setForeground(Qt.GlobalColor.cyan)
            elif row == len(hops) - 1:
                for col in range(5):
                    if self.trace_table.item(row, col):
                        self.trace_table.item(row, col).setForeground(Qt.GlobalColor.green)
        self.current_data['traceroute'] = hops

    def generate_html_report(self) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Recon Report</title>
<style>
    body {{ font-family: sans-serif; background: white; }}
    h1, h2 {{ color: #0066cc; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
    th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
    th {{ background: #f2f2f2; }}
    pre {{ background: #f9f9f9; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }}
</style>
</head>
<body>
<h1>Recon Report for {self.target_input.text()}</h1>
<p>Generated: {timestamp}</p>
"""

        if 'whois_raw' in self.current_data:
            html += f"<h2>WHOIS (raw)</h2><pre>{self.current_data['whois_raw'][:5000]}</pre>"

        if 'dns' in self.current_data and self.current_data['dns']:
            html += "<h2>DNS Records</h2>"
            html += """<tr>
<thead><tr><th>Type</th><th>Value</th></tr></thead>
<tbody>"""
            for typ, val in self.current_data['dns']:
                html += f"<tr><td>{typ}</td><td>{val}</td></tr>"
            html += "</tbody></table>"

        if 'ping' in self.current_data:
            s = self.current_data['ping']
            html += f"""
<h2>Ping Stats</h2>
<ul>
<li>Host IP: {s.get('ip', '--')}</li>
<li>Min RTT: {s.get('min', '--')} ms</li>
<li>Avg RTT: {s.get('avg', '--')} ms</li>
<li>Max RTT: {s.get('max', '--')} ms</li>
<li>Packet Loss: {s.get('loss', '--')}%</li>
</ul>"""

        if 'traceroute' in self.current_data and self.current_data['traceroute']:
            html += "<h2>Traceroute</h2>"
            html += """社
<thead><tr><th>Hop</th><th>IP</th><th>RTT1</th><th>RTT2</th><th>RTT3</th></tr></thead>
<tbody>"""
            for h in self.current_data['traceroute']:
                html += f"<tr><td>{h['hop']}</td><td>{h['ip']}</td><td>{h['rtt1']}</td><td>{h['rtt2']}</td><td>{h['rtt3']}</td></tr>"
            html += "</tbody></table>"

        html += "</body></html>"
        return html

    def get_module_name(self) -> str:
        return "Recon Web"
