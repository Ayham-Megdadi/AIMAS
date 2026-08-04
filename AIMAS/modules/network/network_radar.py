#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Radar - Advanced nmap GUI
Fixed: Stop button only stops the scan, does not exit the application.
"""

import logging
import re
import json
from typing import List, Dict
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, QProcess, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QComboBox, QButtonGroup,
    QCheckBox, QGroupBox, QFileDialog, QMessageBox, QTextEdit, QMenu
)
from PyQt6.QtGui import QAction

from core.project_manager import ProjectManager

logger = logging.getLogger(__name__)

class AimasTerminal(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet("background-color: #0D1117; color: #E6EDF3; font-family: 'JetBrains Mono'; font-size: 11px;")

    def append_colored(self, text: str, color: str = "#E6EDF3"):
        self.append(f'<span style="color:{color};">{text}</span>')

class NmapScanWorker(QThread):
    output_line = pyqtSignal(str, str)
    scan_complete = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, command: List[str]):
        super().__init__()
        self.command = command
        self.process = None
        self._abort = False
        self.full_output = []

    def abort(self):
        self._abort = True
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            self.process.terminate()
            self.process.waitForFinished(2000)
            self.process.kill()

    def run(self):
        try:
            self.process = QProcess()
            self.process.readyReadStandardOutput.connect(self.handle_stdout)
            self.process.readyReadStandardError.connect(self.handle_stderr)
            self.process.finished.connect(self.process_finished)
            self.process.start(self.command[0], self.command[1:])
            if not self.process.waitForStarted(5000):
                self.error.emit("Failed to start nmap")
                return
            self.process.waitForFinished(-1)
        except Exception as e:
            self.error.emit(str(e))

    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        text = bytes(data).decode('utf-8', errors='ignore')
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            self.full_output.append(line)
            if "open" in line:
                self.output_line.emit(line, "#00FF9C")
            elif "filtered" in line or "closed" in line:
                self.output_line.emit(line, "#8B949E")
            elif line.startswith("Nmap scan"):
                self.output_line.emit(line, "#00B4D8")
            else:
                self.output_line.emit(line, "#E6EDF3")

    def handle_stderr(self):
        data = self.process.readAllStandardError()
        text = bytes(data).decode('utf-8', errors='ignore')
        for line in text.splitlines():
            if line.strip():
                self.output_line.emit(line, "#FF4D4D")

    def parse_nmap_output(self) -> List[Dict]:
        ports = []
        pattern = re.compile(r'^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$')
        for line in self.full_output:
            match = pattern.match(line)
            if match:
                port, proto, state, service, version = match.groups()
                ports.append({
                    'port': int(port),
                    'protocol': proto,
                    'state': state,
                    'service': service,
                    'version': version.strip()
                })
        return ports

    def process_finished(self):
        ports = self.parse_nmap_output()
        self.scan_complete.emit(ports)

class NetworkRadarWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.current_ports = []
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)

        # Target
        target_group = QGroupBox("Target")
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.1, 192.168.1.1-50, 192.168.1.0/24, example.com")
        target_layout.addWidget(self.target_input)
        target_group.setLayout(target_layout)
        main_layout.addWidget(target_group)

        # Scan mode (exclusive QButtonGroup)
        mode_group = QGroupBox("Scan Mode")
        mode_layout = QHBoxLayout()
        self.mode_buttons = {}
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        modes = [("Normal (-sS)", "-sS"), ("Stealth (-sS -T2)", "-sS -T2"),
                 ("OS Detection (-O)", "-O"), ("Version (-sV)", "-sV"),
                 ("Scripts (-sC)", "-sC"), ("Aggressive (-A)", "-A"),
                 ("Custom", "custom")]
        for label, flag in modes:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setProperty("flag", flag)
            self.mode_buttons[flag] = btn
            self.mode_group.addButton(btn)
            mode_layout.addWidget(btn)
        list(self.mode_buttons.values())[0].setChecked(True)
        mode_group.setLayout(mode_layout)
        main_layout.addWidget(mode_group)

        # Port selection
        port_group = QGroupBox("Port Selection")
        port_layout = QHBoxLayout()
        self.port_combo = QComboBox()
        self.port_combo.addItems(["Top 1000 (default)", "Common Ports", "All Ports (1-65535)", "Custom Range"])
        self.custom_port_input = QLineEdit()
        self.custom_port_input.setPlaceholderText("e.g., 1-1024,8080,9000")
        self.custom_port_input.setVisible(False)
        port_layout.addWidget(self.port_combo)
        port_layout.addWidget(self.custom_port_input)
        port_group.setLayout(port_layout)
        main_layout.addWidget(port_group)

        # Options
        options_layout = QHBoxLayout()
        self.open_only_cb = QCheckBox("Open ports only (--open)")
        self.open_only_cb.setChecked(True)
        self.verbose_cb = QCheckBox("Verbose (-v)")
        self.no_ping_cb = QCheckBox("No ping (-Pn)")
        options_layout.addWidget(self.open_only_cb)
        options_layout.addWidget(self.verbose_cb)
        options_layout.addWidget(self.no_ping_cb)
        main_layout.addLayout(options_layout)

        # Custom flags
        self.custom_flags_input = QLineEdit()
        self.custom_flags_input.setPlaceholderText("Custom flags e.g., -sU -p 53,161")
        self.custom_flags_input.setVisible(False)
        main_layout.addWidget(self.custom_flags_input)

        # Toolbar
        toolbar = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")
        self.clear_btn = QPushButton("Clear")
        self.save_btn = QPushButton("Save to Project")
        self.export_btn = QPushButton("Export ▾")
        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.export_btn)
        main_layout.addLayout(toolbar)

        # Terminal
        self.terminal = AimasTerminal()
        main_layout.addWidget(self.terminal)

        # Results table
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(5)
        self.result_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Version"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        main_layout.addWidget(self.result_table)

        self.setLayout(main_layout)

        self.port_combo.currentIndexChanged.connect(self.on_port_combo_changed)
        for btn in self.mode_buttons.values():
            btn.clicked.connect(self.on_mode_changed)
        self.export_btn.clicked.connect(self.show_export_menu)

    def on_port_combo_changed(self, idx):
        self.custom_port_input.setVisible(idx == 3)

    def on_mode_changed(self):
        custom_btn = self.mode_buttons.get("custom")
        if custom_btn and custom_btn.isChecked():
            self.custom_flags_input.setVisible(True)
        else:
            self.custom_flags_input.setVisible(False)

    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn.clicked.connect(self.clear_all)
        self.save_btn.clicked.connect(self.save_to_project)

    def validate_target(self, target: str) -> bool:
        patterns = [
            r'^\d{1,3}(\.\d{1,3}){3}$',
            r'^\d{1,3}(\.\d{1,3}){3}-\d{1,3}$',
            r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$',
            r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$',
        ]
        return any(re.match(p, target) for p in patterns)

    def build_nmap_command(self) -> List[str]:
        target = self.target_input.text().strip()
        if not target:
            return []

        mode_flags = []
        for flag, btn in self.mode_buttons.items():
            if btn.isChecked():
                if flag == "custom":
                    custom = self.custom_flags_input.text().strip()
                    if custom:
                        mode_flags = custom.split()
                else:
                    mode_flags = flag.split()
                break

        port_idx = self.port_combo.currentIndex()
        port_arg = ""
        if port_idx == 0:
            port_arg = "--top-ports 1000"
        elif port_idx == 1:
            port_arg = "-p 22,80,443,3306,5432,8080,8443"
        elif port_idx == 2:
            port_arg = "-p-"
        elif port_idx == 3:
            custom_ports = self.custom_port_input.text().strip()
            if custom_ports:
                port_arg = f"-p {custom_ports}"

        extra = []
        if self.open_only_cb.isChecked():
            extra.append("--open")
        if self.verbose_cb.isChecked():
            extra.append("-v")
        if self.no_ping_cb.isChecked():
            extra.append("-Pn")

        cmd = ["nmap"] + mode_flags
        if port_arg:
            cmd.extend(port_arg.split())
        cmd.extend(extra)
        cmd.append(target)
        return cmd

    def start_scan(self):
        target = self.target_input.text().strip()
        if not self.validate_target(target):
            QMessageBox.warning(self, "Invalid Target", "Enter a valid IP, range, CIDR, or hostname.")
            return
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Busy", "Scan already in progress.")
            return
        cmd = self.build_nmap_command()
        if not cmd:
            return

        self.terminal.clear()
        self.result_table.setRowCount(0)
        self.status_update.emit(f"Starting nmap: {' '.join(cmd)}")
        self.worker = NmapScanWorker(cmd)
        self.worker.output_line.connect(self.terminal.append_colored)
        self.worker.scan_complete.connect(self.on_scan_complete)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_scan(self):
        """إيقاف الفحص فقط دون الخروج من التطبيق"""
        if self.worker:
            self.worker.abort()
            self.worker.quit()
            self.worker.wait(2000)
            self.worker = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_update.emit("Scan stopped by user.")

    def clear_all(self):
        self.terminal.clear()
        self.result_table.setRowCount(0)
        self.current_ports = []
        self.status_update.emit("Cleared output.")

    def on_scan_complete(self, ports):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.current_ports = ports
        self.populate_table(ports)
        self.status_update.emit(f"Scan completed. Found {len(ports)} open ports.")

    def populate_table(self, ports):
        self.result_table.setRowCount(len(ports))
        for row, p in enumerate(ports):
            self.result_table.setItem(row, 0, QTableWidgetItem(str(p['port'])))
            self.result_table.setItem(row, 1, QTableWidgetItem(p['protocol']))
            state_item = QTableWidgetItem(p['state'])
            if p['state'] == 'open':
                state_item.setForeground(Qt.GlobalColor.green)
            elif p['state'] == 'filtered':
                state_item.setForeground(Qt.GlobalColor.yellow)
            else:
                state_item.setForeground(Qt.GlobalColor.gray)
            self.result_table.setItem(row, 2, state_item)
            self.result_table.setItem(row, 3, QTableWidgetItem(p['service']))
            self.result_table.setItem(row, 4, QTableWidgetItem(p['version']))

    def on_scan_error(self, err):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_update.emit(f"Error: {err}")
        QMessageBox.critical(self, "Scan Error", err)

    def save_to_project(self):
        if not self.current_ports:
            QMessageBox.warning(self, "No Data", "No scan results to save.")
            return
        data = {
            'target': self.target_input.text(),
            'command': ' '.join(self.build_nmap_command()),
            'ports': self.current_ports,
            'timestamp': datetime.now().isoformat()
        }
        ProjectManager.save_result('network_radar', data)
        self.status_update.emit("Scan results saved to project.")

    def show_export_menu(self):
        menu = QMenu(self)
        html_action = QAction("Export as HTML", self)
        pdf_action = QAction("Export as PDF", self)
        html_action.triggered.connect(lambda: self.export_scan('html'))
        pdf_action.triggered.connect(lambda: self.export_scan('pdf'))
        menu.addAction(html_action)
        menu.addAction(pdf_action)
        menu.exec(self.export_btn.mapToGlobal(self.export_btn.rect().bottomLeft()))

    def export_scan(self, fmt: str):
        if not self.current_ports:
            QMessageBox.warning(self, "No Data", "No scan results to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, f"Export as {fmt.upper()}", f"nmap_report.{fmt}", f"{fmt.upper()} Files (*.{fmt})")
        if not file_path:
            return
        try:
            if fmt == 'html':
                html = self.generate_html_report()
                with open(file_path, 'w') as f:
                    f.write(html)
            elif fmt == 'pdf':
                html = self.generate_html_report()
                from weasyprint import HTML, CSS
                from weasyprint.text.fonts import FontConfiguration
                css = CSS(string='@page { size: A4; margin: 1.5cm; } table { page-break-inside: avoid; }')
                font_config = FontConfiguration()
                HTML(string=html).write_pdf(file_path, stylesheets=[css], font_config=font_config)
            self.status_update.emit(f"Exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def generate_html_report(self) -> str:
        rows = "\n".join(f"""
        <tr>
            <td>{p['port']}</td> <td>{p['protocol']}</td> <td>{p['state']}</td> <td>{p['service']}</td> <td>{p['version']}</td>
        </tr>
        """ for p in self.current_ports)
        return f"""
        <html><head><meta charset="UTF-8"><title>Nmap Scan Report</title>
        <style>body {{ background: white; color: black; }} table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ddd; padding: 6px; }} th {{ background: #f2f2f2; }}</style>
        </head><body><h1>Nmap Scan Report</h1><p>Target: {self.target_input.text()}</p>
        <table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>{rows}</tbody></table></body></html>
        """

    def get_module_name(self) -> str:
        return "Network Radar"
