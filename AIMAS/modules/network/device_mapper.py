#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Device Mapper - Network discovery using arp-scan and netdiscover
Fixed: Uses AuthManager.get_sudo_input() correctly, timeout handling, abort.
"""

import logging
import re
import subprocess
import socket
import fcntl
import struct
from typing import List, Dict

from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QComboBox, QMessageBox,
    QMenu, QApplication
)
from PyQt6.QtGui import QAction

from core.auth_manager import AuthManager
from services.oui_lookup import OUILookup

logger = logging.getLogger(__name__)

def get_default_interface_and_subnet():
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] != '00000000':
                    iface = parts[0]
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', iface.encode()[:15]))[20:24])
                    mask_bin = fcntl.ioctl(sock.fileno(), 0x891b, struct.pack('256s', iface.encode()[:15]))[20:24]
                    cidr = bin(int.from_bytes(mask_bin, 'big')).count('1')
                    ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
                    mask_int = int.from_bytes(mask_bin, 'big')
                    network_int = ip_int & mask_int
                    network = socket.inet_ntoa(network_int.to_bytes(4, 'big'))
                    subnet = f"{network}/{cidr}"
                    return iface, subnet
    except Exception as e:
        logger.error(f"Failed to detect subnet: {e}")
    return None, "192.168.1.0/24"

class DeviceScanWorker(QThread):
    device_found = pyqtSignal(dict)
    scan_complete = pyqtSignal(list)
    progress = pyqtSignal(int, str)
    error = pyqtSignal(str)

    def __init__(self, mode: str, subnet: str):
        super().__init__()
        self.mode = mode
        self.subnet = subnet
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        devices = []
        # الحصول على كلمة المرور من AuthManager (bytes)
        password_bytes = AuthManager.get_sudo_input()
        if not password_bytes:
            self.error.emit("No sudo password available. Please authenticate first.")
            return
        password = password_bytes.decode().strip()

        try:
            if self.mode == 'active':
                self.progress.emit(10, "Running arp-scan (max 20s)...")
                arp_devices = self.run_arp_scan(password)
                if self._abort: return
                devices.extend(arp_devices)
                self.progress.emit(40, "Running netdiscover active (max 20s)...")
                net_devices = self.run_netdiscover(password, active=True)
                if self._abort: return
                devices.extend(net_devices)
            else:
                self.progress.emit(10, "Running netdiscover passive (max 20s)...")
                net_devices = self.run_netdiscover(password, active=False)
                if self._abort: return
                devices.extend(net_devices)

            self.progress.emit(70, f"Merging {len(devices)} entries...")
            merged = self.merge_devices(devices)
            if self._abort: return

            self.progress.emit(80, "Measuring RTT and vendors...")
            total = len(merged)
            for idx, dev in enumerate(merged):
                if self._abort: return
                dev['rtt'] = self.ping_device(dev['ip'])
                if not dev.get('vendor') or dev['vendor'] == '':
                    dev['vendor'] = self.lookup_vendor(dev.get('mac', ''))
                self.device_found.emit(dev)
                self.progress.emit(80 + int(20 * (idx+1)/total), f"Processing {dev['ip']}")

            self.progress.emit(100, "Scan complete")
            self.scan_complete.emit(merged)
        except Exception as e:
            self.error.emit(str(e))

    def run_arp_scan(self, password: str) -> List[Dict]:
        devices = []
        cmd = ['sudo', '-S', 'arp-scan', '--localnet', '--retry=2', '--timeout=500']
        try:
            proc = subprocess.run(cmd, input=password + '\n', capture_output=True, text=True, timeout=20)
            for line in proc.stdout.splitlines():
                if self._abort: break
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.+)', line.strip())
                if match:
                    ip, mac, vendor = match.groups()
                    devices.append({
                        'ip': ip,
                        'mac': mac.upper(),
                        'vendor': vendor.strip(),
                        'source': 'arp-scan'
                    })
        except subprocess.TimeoutExpired:
            logger.warning("arp-scan timed out after 20s")
        except Exception as e:
            self.error.emit(f"arp-scan error: {e}")
        return devices

    def run_netdiscover(self, password: str, active: bool = True) -> List[Dict]:
        devices = []
        if active:
            cmd = ['sudo', '-S', 'netdiscover', '-r', self.subnet, '-c', '3']
        else:
            cmd = ['sudo', '-S', 'netdiscover', '-p', '-c', '3']
        try:
            proc = subprocess.run(cmd, input=password + '\n', capture_output=True, text=True, timeout=20)
            for line in proc.stdout.splitlines():
                if self._abort: break
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})', line, re.IGNORECASE)
                if match:
                    ip, mac = match.groups()
                    devices.append({
                        'ip': ip,
                        'mac': mac.upper(),
                        'vendor': '',
                        'source': 'netdiscover'
                    })
        except subprocess.TimeoutExpired:
            logger.warning("netdiscover timed out after 20s")
        except Exception as e:
            self.error.emit(f"netdiscover error: {e}")
        return devices

    def merge_devices(self, devices: List[Dict]) -> List[Dict]:
        merged = {}
        for dev in devices:
            mac = dev.get('mac')
            if not mac:
                continue
            if mac not in merged:
                merged[mac] = dev.copy()
            else:
                if 'source' in dev and dev['source'] not in merged[mac].get('source', ''):
                    merged[mac]['source'] = 'both'
        return list(merged.values())

    def ping_device(self, ip: str) -> str:
        try:
            proc = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                                  capture_output=True, text=True, timeout=3)
            match = re.search(r'time=(\d+(?:\.\d+)?)\s*ms', proc.stdout)
            if match:
                return f"{match.group(1)} ms"
            return "N/A"
        except:
            return "N/A"

    def lookup_vendor(self, mac: str) -> str:
        if mac and len(mac) >= 8:
            try:
                return OUILookup().get_vendor(mac)
            except:
                pass
        return "Unknown"

class DeviceMapperWidget(QWidget):
    status_update = pyqtSignal(str)
    send_to_radar = pyqtSignal(str)
    send_to_notes = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.devices = []
        self.subnet = "192.168.1.0/24"
        self.setup_ui()
        self.connect_signals()
        self.detect_subnet()

    def detect_subnet(self):
        _, subnet = get_default_interface_and_subnet()
        self.subnet = subnet
        self.status_update.emit(f"Detected subnet: {self.subnet}")

    def setup_ui(self):
        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Active (arp-scan + netdiscover)", "Passive (netdiscover only)"])
        self.start_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.export_html_btn = QPushButton("Export HTML")
        self.export_pdf_btn = QPushButton("Export PDF")
        self.subnet_label = QPushButton(f"Subnet: {self.subnet}")
        self.subnet_label.setEnabled(False)

        toolbar.addWidget(self.mode_combo)
        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addStretch()
        toolbar.addWidget(self.subnet_label)
        toolbar.addWidget(self.export_html_btn)
        toolbar.addWidget(self.export_pdf_btn)
        layout.addLayout(toolbar)

        self.device_table = QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels(["IP", "MAC", "Vendor", "RTT (ms)", "Source"])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.device_table.setSortingEnabled(True)
        self.device_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.device_table, 1)

        self.topology_text = QTextEdit()
        self.topology_text.setReadOnly(True)
        self.topology_text.setMaximumHeight(150)
        layout.addWidget(self.topology_text)

        self.setLayout(layout)

    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Busy", "A scan is already in progress.")
            return
        if not AuthManager.is_authenticated():
            if not AuthManager.authenticate(self):
                QMessageBox.critical(self, "Auth Required", "Cannot proceed without sudo privileges.")
                return
        mode = "active" if self.mode_combo.currentIndex() == 0 else "passive"
        self.worker = DeviceScanWorker(mode, self.subnet)
        self.worker.device_found.connect(self.add_device_to_table)
        self.worker.scan_complete.connect(self.scan_finished)
        self.worker.progress.connect(self.on_progress)
        self.worker.error.connect(self.on_error)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.device_table.setRowCount(0)
        self.devices.clear()
        self.status_update.emit(f"Starting {mode} scan on {self.subnet}...")

        # مهلة 35 ثانية لإنهاء المسح (أمان)
        QTimer.singleShot(35000, self.check_timeout)

    def check_timeout(self):
        if self.worker and self.worker.isRunning():
            self.stop_scan()
            self.status_update.emit("Scan timed out after 35 seconds. Partial results shown.")

    def stop_scan(self):
        if self.worker:
            self.worker.abort()
            self.worker.quit()
            self.worker.wait(2000)
            self.worker = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_update.emit("Scan stopped by user or timeout.")

    def add_device_to_table(self, device: dict):
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        self.device_table.setItem(row, 0, QTableWidgetItem(device.get('ip', '')))
        self.device_table.setItem(row, 1, QTableWidgetItem(device.get('mac', '')))
        self.device_table.setItem(row, 2, QTableWidgetItem(device.get('vendor', 'Unknown')))
        self.device_table.setItem(row, 3, QTableWidgetItem(device.get('rtt', 'N/A')))
        self.device_table.setItem(row, 4, QTableWidgetItem(device.get('source', '')))
        self.devices.append(device)

    def scan_finished(self, devices: list):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.update_topology(devices)
        self.status_update.emit(f"Scan completed. Found {len(devices)} devices.")

    def update_topology(self, devices: list):
        gateway = self.subnet.split('/')[0][:-1] + "1"
        lines = [f"★ Gateway: {gateway}"]
        for dev in devices:
            ip = dev.get('ip', '')
            if ip == gateway or ip == "0.0.0.0":
                continue
            lines.append(f"  └─ {ip}")
        self.topology_text.setText("\n".join(lines))

    def on_progress(self, percent: int, message: str):
        self.status_update.emit(f"{message} ({percent}%)")

    def on_error(self, err: str):
        self.status_update.emit(f"Error: {err}")
        QMessageBox.critical(self, "Scan Error", err)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def show_context_menu(self, pos):
        row = self.device_table.rowAt(pos.y())
        if row < 0:
            return
        ip = self.device_table.item(row, 0).text()
        mac = self.device_table.item(row, 1).text()

        menu = QMenu(self)
        scan_action = QAction("Scan in Network Radar", self)
        scan_action.triggered.connect(lambda: self.send_to_radar.emit(ip))
        notes_action = QAction("Send to Notes", self)
        notes_action.triggered.connect(lambda: self.send_to_notes.emit(f"Device: {ip} ({mac})"))
        copy_ip = QAction("Copy IP", self)
        copy_ip.triggered.connect(lambda: QApplication.clipboard().setText(ip))
        copy_mac = QAction("Copy MAC", self)
        copy_mac.triggered.connect(lambda: QApplication.clipboard().setText(mac))

        menu.addAction(scan_action)
        menu.addAction(notes_action)
        menu.addSeparator()
        menu.addAction(copy_ip)
        menu.addAction(copy_mac)
        menu.exec(self.device_table.viewport().mapToGlobal(pos))

    def get_module_name(self) -> str:
        return "Device Mapper"
