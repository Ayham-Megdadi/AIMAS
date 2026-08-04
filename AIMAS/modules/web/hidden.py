#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Hidden - Directory busting using dirb and gobuster
"""

import re
import subprocess
import logging
from dataclasses import dataclass
from typing import List
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal, Qt, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QComboBox,
    QListWidget, QListWidgetItem, QAbstractItemView, QCheckBox, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QMessageBox,
    QTextEdit, QMenu, QGroupBox, QLabel
)
from PyQt6.QtGui import QAction, QDesktopServices

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


@dataclass
class DirBustResult:
    url: str
    status_code: int
    size: int
    source: str


class DirbWorker(QThread):
    result_found = pyqtSignal(DirBustResult)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    output_line = pyqtSignal(str)

    def __init__(self, url: str, wordlist: str, extensions: str, timeout: int):
        super().__init__()
        self.url = url
        self.wordlist = wordlist
        self.extensions = extensions
        self.timeout = timeout
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        cmd = ['dirb', self.url, self.wordlist, '-X', self.extensions, '-a', 'AIMAS/1.0']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ''):
                if self._abort:
                    proc.terminate()
                    break
                line = line.strip()
                self.output_line.emit(line)
                # dirb output: + http://example.com/path (CODE:200|SIZE:123)
                match = re.search(r'\+ ([^ ]+) \(CODE:(\d+)\|SIZE:(\d+)\)', line)
                if match:
                    url, code, size = match.groups()
                    self.result_found.emit(DirBustResult(url=url, status_code=int(code), size=int(size), source='dirb'))
            proc.wait()
        except Exception as e:
            self.error.emit(str(e))
        self.finished.emit()


class GobusterWorker(QThread):
    result_found = pyqtSignal(DirBustResult)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    output_line = pyqtSignal(str)

    def __init__(self, url: str, wordlist: str, extensions: str, threads: int, timeout: int):
        super().__init__()
        self.url = url
        self.wordlist = wordlist
        self.extensions = extensions
        self.threads = threads
        self.timeout = timeout
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        cmd = ['gobuster', 'dir', '-u', self.url, '-w', self.wordlist, '-x', self.extensions,
               '-t', str(self.threads), '--timeout', f'{self.timeout}s', '-q']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ''):
                if self._abort:
                    proc.terminate()
                    break
                line = line.strip()
                self.output_line.emit(line)
                # gobuster output: /path (Status: 200) [Size: 123]
                match = re.search(r'^([^\s]+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line, re.IGNORECASE)
                if match:
                    path, code, size = match.groups()
                    full_url = self.url.rstrip('/') + ('/' + path if not path.startswith('/') else path)
                    self.result_found.emit(DirBustResult(url=full_url, status_code=int(code), size=int(size), source='gobuster'))
            proc.wait()
        except Exception as e:
            self.error.emit(str(e))
        self.finished.emit()


class HiddenWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.dirb_worker = None
        self.gobuster_worker = None
        self.results = []
        self.setup_ui()
        self.connect_signals()
        self.ensure_wordlists()

    def ensure_wordlists(self):
        """إنشاء wordlists افتراضية تحتوي على الكلمات المطلوبة"""
        wordlist_dir = Path(__file__).parent.parent.parent / "data" / "wordlists"
        wordlist_dir.mkdir(parents=True, exist_ok=True)
        common_path = wordlist_dir / "common.txt"
        
        # الكلمات الأساسية التي يجب البحث عنها (بما فيها uploads, errors, robots.txt)
        essential_words = [
            "index.php", "admin", "login", "wp-admin", "backup", "config",
            "test", "css", "js", "images", "upload", "uploads", "errors",
            "robots.txt", "admin.php", "admin.html", "login.php", "error",
            "logs", "tmp", "backups", "sql", "dump", "export", "download"
        ]
        
        if not common_path.exists():
            common_path.write_text("\n".join(essential_words))
        else:
            content = common_path.read_text()
            missing = [w for w in essential_words if w not in content]
            if missing:
                with open(common_path, 'a') as f:
                    f.write("\n" + "\n".join(missing))
        
        big_path = wordlist_dir / "big.txt"
        if not big_path.exists():
            big_path.write_text(common_path.read_text())
        
        raft_path = wordlist_dir / "raft-medium.txt"
        if not raft_path.exists():
            system_raft = "/usr/share/dirb/wordlists/raft-medium.txt"
            if Path(system_raft).exists():
                # سنستخدم النظامي ولا ننسخه
                pass
            else:
                raft_path.write_text(common_path.read_text())

    def get_wordlist_path(self, wordlist_name: str) -> str:
        """إرجاع المسار الكامل لملف wordlist"""
        if Path(wordlist_name).exists():
            return wordlist_name
        local_path = Path(__file__).parent.parent.parent / "data" / "wordlists" / wordlist_name
        if local_path.exists():
            return str(local_path)
        system_paths = [
            f"/usr/share/wordlists/{wordlist_name}",
            f"/usr/share/wordlists/dirb/{wordlist_name}",
            f"/usr/share/dirb/wordlists/{wordlist_name}",
        ]
        for p in system_paths:
            if Path(p).exists():
                return p
        return str(local_path)

    def setup_ui(self):
        layout = QVBoxLayout(self)

        input_group = QGroupBox("Target & Options")
        form_layout = QHBoxLayout()

        left_layout = QVBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example.com")
        left_layout.addWidget(self.url_input)

        wordlist_layout = QHBoxLayout()
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.addItems(["common.txt", "big.txt", "raft-medium.txt"])
        self.wordlist_combo.setEditable(True)
        self.custom_wordlist_btn = QPushButton("Custom...")
        wordlist_layout.addWidget(self.wordlist_combo)
        wordlist_layout.addWidget(self.custom_wordlist_btn)
        left_layout.addLayout(wordlist_layout)

        ext_layout = QHBoxLayout()
        self.ext_list = QListWidget()
        self.ext_list.setMaximumHeight(80)
        self.ext_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        extensions = ["php", "html", "txt", "js", "json", "xml", "asp", "aspx", "bak", "sql"]
        for ext in extensions:
            item = QListWidgetItem(ext)
            self.ext_list.addItem(item)
            item.setSelected(True)
        ext_layout.addWidget(QLabel("Extensions:"))
        ext_layout.addWidget(self.ext_list)
        left_layout.addLayout(ext_layout)
        form_layout.addLayout(left_layout, 1)

        right_layout = QVBoxLayout()
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(50)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(10)
        right_layout.addWidget(QLabel("Threads:"))
        right_layout.addWidget(self.threads_spin)
        right_layout.addWidget(QLabel("Timeout (s):"))
        right_layout.addWidget(self.timeout_spin)
        self.run_dirb_cb = QCheckBox("Run dirb")
        self.run_dirb_cb.setChecked(True)
        self.run_gobuster_cb = QCheckBox("Run gobuster")
        self.run_gobuster_cb.setChecked(True)
        right_layout.addWidget(self.run_dirb_cb)
        right_layout.addWidget(self.run_gobuster_cb)
        form_layout.addLayout(right_layout, 1)

        input_group.setLayout(form_layout)
        layout.addWidget(input_group)

        toolbar = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("Export ▾")
        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addStretch()
        toolbar.addWidget(self.export_btn)
        layout.addLayout(toolbar)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Status:"))
        self.status_checkboxes = {}
        for code in [200, 301, 302, 403]:
            cb = QCheckBox(str(code))
            cb.setChecked(True)
            filter_layout.addWidget(cb)
            self.status_checkboxes[code] = cb
        self.other_cb = QCheckBox("Other")
        self.other_cb.setChecked(True)
        filter_layout.addWidget(self.other_cb)
        filter_layout.addStretch()
        filter_layout.addWidget(QLabel("Filter URL:"))
        self.filter_input = QLineEdit()
        filter_layout.addWidget(self.filter_input)
        layout.addLayout(filter_layout)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["URL", "Status", "Size (bytes)", "Source", "Action"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setSortingEnabled(True)
        layout.addWidget(self.results_table)

        self.terminal = AimasTerminal()
        self.terminal.setMaximumHeight(200)
        layout.addWidget(self.terminal)

        self.setLayout(layout)

    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.custom_wordlist_btn.clicked.connect(self.select_custom_wordlist)
        self.export_btn.clicked.connect(self.show_export_menu)
        self.filter_input.textChanged.connect(self.filter_results)
        for cb in self.status_checkboxes.values():
            cb.stateChanged.connect(self.filter_results)
        self.other_cb.stateChanged.connect(self.filter_results)

    def select_custom_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt)")
        if path:
            self.wordlist_combo.addItem(path)
            self.wordlist_combo.setCurrentText(path)

    def get_extensions_string(self):
        exts = []
        for i in range(self.ext_list.count()):
            item = self.ext_list.item(i)
            if item.isSelected():
                exts.append(item.text())
        return ','.join(exts)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "No URL", "Please enter a target URL.")
            return
        wordlist_name = self.wordlist_combo.currentText().strip()
        if not wordlist_name:
            QMessageBox.warning(self, "No Wordlist", "Please select a wordlist.")
            return
        wordlist = self.get_wordlist_path(wordlist_name)
        
        if not Path(wordlist).exists():
            QMessageBox.warning(self, "Wordlist Not Found", 
                                f"Wordlist file not found: {wordlist}\n\nPlease select a valid wordlist.")
            return
        
        extensions = self.get_extensions_string()
        threads = self.threads_spin.value()
        timeout = self.timeout_spin.value()

        self.results = []
        self.results_table.setRowCount(0)
        self.terminal.clear()

        if self.run_dirb_cb.isChecked():
            self.dirb_worker = DirbWorker(url, wordlist, extensions, timeout)
            self.dirb_worker.result_found.connect(self.on_result)
            self.dirb_worker.output_line.connect(self.terminal.append)
            self.dirb_worker.finished.connect(lambda: self.check_finished('dirb'))
            self.dirb_worker.error.connect(lambda e: self.status_update.emit(f"dirb error: {e}"))
            self.dirb_worker.start()
        if self.run_gobuster_cb.isChecked():
            self.gobuster_worker = GobusterWorker(url, wordlist, extensions, threads, timeout)
            self.gobuster_worker.result_found.connect(self.on_result)
            self.gobuster_worker.output_line.connect(self.terminal.append)
            self.gobuster_worker.finished.connect(lambda: self.check_finished('gobuster'))
            self.gobuster_worker.error.connect(lambda e: self.status_update.emit(f"gobuster error: {e}"))
            self.gobuster_worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_update.emit("Scan started...")

    def stop_scan(self):
        if self.dirb_worker:
            self.dirb_worker.abort()
        if self.gobuster_worker:
            self.gobuster_worker.abort()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_update.emit("Scan stopped by user.")

    def on_result(self, result: DirBustResult):
        # Remove duplicate by URL
        existing = next((r for r in self.results if r.url == result.url), None)
        if existing:
            if result.source not in existing.source:
                existing.source = 'both'
                for row in range(self.results_table.rowCount()):
                    if self.results_table.item(row, 0).text() == result.url:
                        self.results_table.setItem(row, 3, QTableWidgetItem('both'))
                        break
        else:
            self.results.append(result)
            self.add_result_to_table(result)
        self.filter_results()

    def add_result_to_table(self, r: DirBustResult):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(r.url))
        status_item = QTableWidgetItem(str(r.status_code))
        if r.status_code == 200:
            status_item.setForeground(Qt.GlobalColor.green)
        elif r.status_code in (301, 302):
            status_item.setForeground(Qt.GlobalColor.cyan)
        elif r.status_code == 403:
            status_item.setForeground(Qt.GlobalColor.yellow)
        else:
            status_item.setForeground(Qt.GlobalColor.gray)
        self.results_table.setItem(row, 1, status_item)
        self.results_table.setItem(row, 2, QTableWidgetItem(str(r.size)))
        self.results_table.setItem(row, 3, QTableWidgetItem(r.source))
        open_btn = QPushButton("Open")
        open_btn.clicked.connect(lambda checked, url=r.url: QDesktopServices.openUrl(QUrl(url)))
        self.results_table.setCellWidget(row, 4, open_btn)

    def check_finished(self, worker_name):
        dirb_running = self.dirb_worker and self.dirb_worker.isRunning()
        gobuster_running = self.gobuster_worker and self.gobuster_worker.isRunning()
        if not dirb_running and not gobuster_running:
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_update.emit(f"Scan completed. Found {len(self.results)} unique URLs.")

    def filter_results(self):
        status_filter = set()
        for code, cb in self.status_checkboxes.items():
            if cb.isChecked():
                status_filter.add(code)
        other_included = self.other_cb.isChecked()
        text_filter = self.filter_input.text().strip().lower()

        for row in range(self.results_table.rowCount()):
            url_item = self.results_table.item(row, 0)
            status_item = self.results_table.item(row, 1)
            if not url_item:
                continue
            url = url_item.text().lower()
            status = int(status_item.text())
            status_ok = (status in status_filter) or (other_included and status not in [200, 301, 302, 403])
            text_ok = text_filter in url if text_filter else True
            self.results_table.setRowHidden(row, not (status_ok and text_ok))

    def show_export_menu(self):
        menu = QMenu(self)
        html_action = QAction("Export as HTML", self)
        pdf_action = QAction("Export as PDF", self)
        html_action.triggered.connect(lambda: self.export('html'))
        pdf_action.triggered.connect(lambda: self.export('pdf'))
        menu.addAction(html_action)
        menu.addAction(pdf_action)
        menu.exec(self.export_btn.mapToGlobal(self.export_btn.rect().bottomLeft()))

    def export(self, fmt: str):
        if not self.results:
            QMessageBox.warning(self, "No Data", "No results to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Export as {fmt.upper()}",
            f"hidden_results.{fmt}", f"{fmt.upper()} Files (*.{fmt})"
        )
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
            f"<tr><td>{r.url}</td><td>{r.status_code}</td><td>{r.size}</td><td>{r.source}</td></tr>"
            for r in self.results
        )
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Hidden Scan Report</title>
<style>
    body {{ font-family: sans-serif; background: white; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
    th {{ background: #f2f2f2; }}
</style>
</head>
<body>
<h1>Directory Busting Results</h1>
<table>
<thead>
<tr><th>URL</th><th>Status</th><th>Size (bytes)</th><th>Source</th></tr>
</thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""

    def get_module_name(self) -> str:
        return "Hidden"
