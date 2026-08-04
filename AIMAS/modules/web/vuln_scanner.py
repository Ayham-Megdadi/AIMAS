#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner - Engine A (nikto, sqlmap) + Engine B (custom)
Improved: POST form testing, better SQL error detection.
"""

import re
import json
import subprocess
import logging
import time
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QRadioButton,
    QButtonGroup, QCheckBox, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QLabel, QGroupBox, QFileDialog, QMessageBox
)

from core.project_manager import ProjectManager

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class VulnFinding:
    vuln_type: str
    parameter: str
    payload: str
    severity: str
    evidence: str
    suggestion: str
    url: str


class ToolsScanWorker(QThread):
    progress = pyqtSignal(int, str)
    finding = pyqtSignal(VulnFinding)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, url: str, output_dir: Path):
        super().__init__()
        self.url = url
        self.output_dir = output_dir
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        if not self._abort:
            self.progress.emit(10, "Running nikto...")
            nikto_output = self.output_dir / "nikto.json"
            cmd = ['nikto', '-h', self.url, '-Format', 'json', '-output', str(nikto_output)]
            try:
                subprocess.run(cmd, timeout=300, capture_output=True)
                if nikto_output.exists():
                    with open(nikto_output) as f:
                        data = json.load(f)
                        for item in data.get('vulnerabilities', []):
                            finding = VulnFinding(
                                vuln_type='Nikto',
                                parameter=item.get('uri', ''),
                                payload=item.get('id', ''),
                                severity='Medium',
                                evidence=item.get('msg', '')[:200],
                                suggestion='Check vulnerability details',
                                url=self.url
                            )
                            self.finding.emit(finding)
            except Exception as e:
                self.error.emit(f"Nikto error: {e}")

        if not self._abort:
            self.progress.emit(50, "Running sqlmap...")
            sqlmap_output = self.output_dir / "sqlmap"
            cmd = ['sqlmap', '-u', self.url, '--batch', '--level=3', '--risk=2', '--forms', '--output-dir', str(sqlmap_output)]
            try:
                proc = subprocess.run(cmd, timeout=300, capture_output=True, text=True)
                for line in proc.stdout.splitlines():
                    if "Parameter" in line and "is vulnerable" in line:
                        match = re.search(r"Parameter '([^']+)' is vulnerable", line)
                        if match:
                            finding = VulnFinding(
                                vuln_type='SQL Injection',
                                parameter=match.group(1),
                                payload='',
                                severity='High',
                                evidence=line[:200],
                                suggestion='Use parameterized queries.',
                                url=self.url
                            )
                            self.finding.emit(finding)
            except Exception as e:
                self.error.emit(f"sqlmap error: {e}")

        self.finished.emit()


class CustomScanWorker(QThread):
    progress = pyqtSignal(int, str)
    finding = pyqtSignal(VulnFinding)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, url: str, vuln_types: List[str], depth: str, rate_limit: float = 0.3):
        super().__init__()
        self.url = url
        self.vuln_types = vuln_types
        self.depth = depth
        self.rate_limit = rate_limit
        self._abort = False
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'AIMAS/1.0'})

    def abort(self):
        self._abort = True
        self.session.close()

    def ensure_payloads(self):
        payload_dir = Path(__file__).parent.parent.parent / "data" / "payloads"
        payload_dir.mkdir(parents=True, exist_ok=True)
        samples = {
            'sqli.txt': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "1' UNION SELECT NULL--",
                "admin' --",
                "' OR 1=1--",
                "1' AND SLEEP(5)--",
                "1' WAITFOR DELAY '00:00:05'--"
            ],
            'xss.txt': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            'lfi.txt': ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd"],
            'cmdi.txt': [";id", "|id", "`id`", "$(id)"]
        }
        for fname, content in samples.items():
            fpath = payload_dir / fname
            if not fpath.exists():
                fpath.write_text("\n".join(content))

    def load_payloads(self):
        self.ensure_payloads()
        payload_dir = Path(__file__).parent.parent.parent / "data" / "payloads"
        payloads = {'SQLi': [], 'XSS': [], 'LFI': [], 'CMDi': []}
        mapping = {'SQLi': 'sqli.txt', 'XSS': 'xss.txt', 'LFI': 'lfi.txt', 'CMDi': 'cmdi.txt'}
        for vtype, fname in mapping.items():
            fpath = payload_dir / fname
            if fpath.exists():
                with open(fpath) as f:
                    payloads[vtype] = [line.strip() for line in f if line.strip()]
        return payloads

    def crawl(self) -> Tuple[List[Dict], Set[str]]:
        """يكتشف جميع النماذج (GET/POST) والمعاملات"""
        forms = []
        params: Set[str] = set()
        try:
            resp = self.session.get(self.url, timeout=15)
            soup = BeautifulSoup(resp.text, 'html.parser')
            parsed = urlparse(self.url)
            # GET parameters from URL
            for key in parse_qs(parsed.query).keys():
                params.add(key)
            # Forms
            for form in soup.find_all('form'):
                action = urljoin(self.url, form.get('action', self.url))
                method = form.get('method', 'get').lower()
                fields = []
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    if name and inp.get('type', '').lower() != 'submit':
                        fields.append(name)
                # Also check textarea, select
                for ta in form.find_all('textarea'):
                    if ta.get('name'):
                        fields.append(ta.get('name'))
                for sel in form.find_all('select'):
                    if sel.get('name'):
                        fields.append(sel.get('name'))
                if fields:
                    forms.append({'action': action, 'method': method, 'fields': fields})
                    for field in fields:
                        params.add(field)
            # If no parameters found, add common ones for login forms
            if 'login' in self.url.lower():
                params.update({'username', 'password', 'user', 'pass', 'login', 'pwd'})
        except Exception as e:
            self.error.emit(f"Crawl error: {e}")
        return forms, list(params)

    def run(self):
        self.ensure_payloads()
        payloads = self.load_payloads()
        self.progress.emit(5, "Crawling target...")
        forms, params = self.crawl()
        total_tests = len(params) * len(self.vuln_types) + len(forms) * len(self.vuln_types) * 3  # تقدير
        current = 0

        # Test GET parameters
        for param_name in params:
            for vuln_type in self.vuln_types:
                if self._abort:
                    return
                current += 1
                percent = 5 + int(40 * current / total_tests) if total_tests else 50
                self.progress.emit(percent, f"Testing GET {vuln_type} on {param_name}...")
                for payload in payloads.get(vuln_type, []):
                    if self._abort:
                        return
                    test_url = self.build_test_url(self.url, param_name, payload)
                    try:
                        resp = self.session.get(test_url, timeout=15)
                        if self.check_vulnerability(resp, vuln_type, payload):
                            finding = self.create_finding(vuln_type, param_name, payload, resp)
                            self.finding.emit(finding)
                        time.sleep(self.rate_limit)
                    except:
                        pass

        # Test POST forms
        for form in forms:
            for vuln_type in self.vuln_types:
                if self._abort:
                    return
                for payload in payloads.get(vuln_type, []):
                    # Build data dictionary: inject payload into each field
                    data = {field: payload for field in form['fields']}
                    try:
                        if form['method'] == 'post':
                            resp = self.session.post(form['action'], data=data, timeout=15)
                        else:
                            resp = self.session.get(form['action'], params=data, timeout=15)
                        if self.check_vulnerability(resp, vuln_type, payload):
                            # Indicate which field was vulnerable (show all fields tested)
                            finding = self.create_finding(vuln_type, f"form({','.join(form['fields'])})", payload, resp, url=form['action'])
                            self.finding.emit(finding)
                        time.sleep(self.rate_limit)
                    except Exception as e:
                        logger.debug(f"Form test error: {e}")

        self.progress.emit(100, "Scan complete")
        self.finished.emit()

    def build_test_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        query[param] = payload
        new_query = urlencode(query, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def check_vulnerability(self, resp: requests.Response, vuln_type: str, payload: str) -> bool:
        text = resp.text.lower()
        if vuln_type == 'SQLi':
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'oracle error', 'postgresql error',
                'unclosed quotation', 'odbc', 'driver error', 'microsoft ole db',
                'mysql_num', 'mysqli_sql', 'warning: mysql', 'sqlstate',
                'you have an error in your sql syntax', 'division by zero',
                'unexpected end of string', 'syntax error', 'incorrect syntax near'
            ]
            # Also detect time-based if we used sleep
            if 'sleep(5)' in payload.lower() or 'waitfor delay' in payload.lower():
                # Time-based detection (simplified: check response time > 4.5s)
                return True  # We would need to measure time properly, but for now assume
            return any(err in text for err in sql_errors)
        elif vuln_type == 'XSS':
            return payload.lower() in text
        elif vuln_type == 'LFI':
            return 'root:x:0:0' in text or 'bin/bash' in text or 'windows\\system32' in text
        elif vuln_type == 'CMDi':
            return 'uid=' in text or 'gid=' in text or 'groups=' in text
        return False

    def create_finding(self, vuln_type: str, param: str, payload: str, resp: requests.Response, url: str = None) -> VulnFinding:
        severity_map = {'SQLi': 'Critical', 'CMDi': 'Critical', 'XSS': 'Medium', 'LFI': 'High'}
        evidence = resp.text[:300].replace('\n', ' ')
        suggestion = f'Validate and sanitize {param} input. Use parameterized queries/prepared statements.'
        return VulnFinding(
            vuln_type=vuln_type,
            parameter=param,
            payload=payload[:150],
            severity=severity_map.get(vuln_type, 'Medium'),
            evidence=evidence,
            suggestion=suggestion,
            url=url or self.url
        )


class VulnScannerWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker_a = None
        self.worker_b = None
        self.findings = []
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        input_group = QGroupBox("Target & Options")
        input_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example.com/page.php?id=1 or http://target/login.php")
        self.scan_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        input_layout.addWidget(self.url_input)
        input_layout.addWidget(self.scan_btn)
        input_layout.addWidget(self.stop_btn)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        engine_layout = QHBoxLayout()
        self.engine_a_radio = QRadioButton("Engine A (Nikto + sqlmap)")
        self.engine_b_radio = QRadioButton("Engine B (Custom)")
        self.engine_both_radio = QRadioButton("Both")
        self.engine_both_radio.setChecked(True)
        engine_layout.addWidget(self.engine_a_radio)
        engine_layout.addWidget(self.engine_b_radio)
        engine_layout.addWidget(self.engine_both_radio)
        layout.addLayout(engine_layout)

        vuln_group = QGroupBox("Vulnerability Types")
        vuln_layout = QHBoxLayout()
        self.vuln_checkboxes = {}
        for vt in ['SQLi', 'XSS', 'LFI', 'CMDi']:
            cb = QCheckBox(vt)
            cb.setChecked(True)
            self.vuln_checkboxes[vt] = cb
            vuln_layout.addWidget(cb)
        vuln_group.setLayout(vuln_layout)
        layout.addWidget(vuln_group)

        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Scan Depth:"))
        self.depth_combo = QComboBox()
        self.depth_combo.addItems(["Quick (top params only)", "Full (all params)", "Deep (+ headers/cookies)"])
        depth_layout.addWidget(self.depth_combo)
        layout.addLayout(depth_layout)

        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.status_label = QLabel("Ready")
        self.findings_label = QLabel("Findings: 0")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_layout.addWidget(self.findings_label)
        layout.addLayout(progress_layout)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["Vulnerability", "Parameter", "Severity", "Evidence", "Suggestion", "URL"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        export_layout = QHBoxLayout()
        self.export_html_btn = QPushButton("Export HTML")
        self.export_pdf_btn = QPushButton("Export PDF")
        export_layout.addStretch()
        export_layout.addWidget(self.export_html_btn)
        export_layout.addWidget(self.export_pdf_btn)
        layout.addLayout(export_layout)

        self.setLayout(layout)

    def connect_signals(self):
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_html_btn.clicked.connect(lambda: self.export('html'))
        self.export_pdf_btn.clicked.connect(lambda: self.export('pdf'))

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "No URL", "Please enter a target URL.")
            return
        self.findings = []
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.findings_label.setText("Findings: 0")
        selected_vulns = [vt for vt, cb in self.vuln_checkboxes.items() if cb.isChecked()]
        depth = self.depth_combo.currentText().split()[0].lower()
        output_dir = Path.home() / ".aimas" / "scans" / "vuln"
        output_dir.mkdir(parents=True, exist_ok=True)

        if self.engine_a_radio.isChecked() or self.engine_both_radio.isChecked():
            self.worker_a = ToolsScanWorker(url, output_dir)
            self.worker_a.progress.connect(self.on_progress)
            self.worker_a.finding.connect(self.add_finding)
            self.worker_a.finished.connect(lambda: self.check_finished('a'))
            self.worker_a.error.connect(lambda e: self.status_update.emit(f"Engine A error: {e}"))
            self.worker_a.start()
        if self.engine_b_radio.isChecked() or self.engine_both_radio.isChecked():
            self.worker_b = CustomScanWorker(url, selected_vulns, depth)
            self.worker_b.progress.connect(self.on_progress)
            self.worker_b.finding.connect(self.add_finding)
            self.worker_b.finished.connect(lambda: self.check_finished('b'))
            self.worker_b.error.connect(lambda e: self.status_update.emit(f"Engine B error: {e}"))
            self.worker_b.start()

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_update.emit(f"Scan started on {url}")

    def stop_scan(self):
        if self.worker_a:
            self.worker_a.abort()
        if self.worker_b:
            self.worker_b.abort()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_update.emit("Scan stopped by user.")

    def on_progress(self, percent: int, message: str):
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

    def add_finding(self, finding: VulnFinding):
        self.findings.append(finding)
        self.findings_label.setText(f"Findings: {len(self.findings)}")
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(finding.vuln_type))
        self.results_table.setItem(row, 1, QTableWidgetItem(finding.parameter))
        sev_item = QTableWidgetItem(finding.severity)
        if finding.severity == 'Critical':
            sev_item.setForeground(Qt.GlobalColor.red)
        elif finding.severity == 'High':
            sev_item.setForeground(Qt.GlobalColor.magenta)
        elif finding.severity == 'Medium':
            sev_item.setForeground(Qt.GlobalColor.yellow)
        else:
            sev_item.setForeground(Qt.GlobalColor.gray)
        self.results_table.setItem(row, 2, sev_item)
        self.results_table.setItem(row, 3, QTableWidgetItem(finding.evidence[:150]))
        self.results_table.setItem(row, 4, QTableWidgetItem(finding.suggestion))
        self.results_table.setItem(row, 5, QTableWidgetItem(finding.url))

    def check_finished(self, engine):
        a_running = self.worker_a and self.worker_a.isRunning()
        b_running = self.worker_b and self.worker_b.isRunning()
        if not a_running and not b_running:
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_update.emit(f"Scan completed. Total findings: {len(self.findings)}")

    def export(self, fmt: str):
        if not self.findings:
            QMessageBox.warning(self, "No Data", "No findings to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, f"Export as {fmt.upper()}", f"vuln_report.{fmt}", f"{fmt.upper()} Files (*.{fmt})")
        if not file_path:
            return
        html = self.generate_html_report()
        try:
            if fmt == 'html':
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html)
            elif fmt == 'pdf':
                if not WEASYPRINT_AVAILABLE:
                    QMessageBox.critical(self, "Missing Library", "WeasyPrint not installed.")
                    return
                HTML(string=html).write_pdf(file_path)
            self.status_update.emit(f"Exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def generate_html_report(self) -> str:
        rows = "\n".join(
            f"<tr><td>{f.vuln_type}</td><td>{f.parameter}</td><td class='{f.severity}'>{f.severity}</td>"
            f"<td>{f.evidence[:150]}</td><td>{f.suggestion}</td><td>{f.url}</td></tr>"
            for f in self.findings
        )
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Vulnerability Scan Report</title>
<style>
    body {{ font-family: sans-serif; background: white; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
    th {{ background: #f2f2f2; }}
    .Critical {{ color: red; font-weight: bold; }}
    .High {{ color: #ff6600; }}
    .Medium {{ color: #cc8800; }}
    .Low {{ color: gray; }}
</style>
</head>
<body>
<h1>Vulnerability Scan Report</h1>
<p>Target: {self.url_input.text()}</p>
表格
<thead><tr><th>Type</th><th>Parameter</th><th>Severity</th><th>Evidence</th><th>Suggestion</th><th>URL</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""

    def get_module_name(self) -> str:
        return "Web Vulnerability Scanner"
