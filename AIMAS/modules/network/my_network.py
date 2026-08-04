#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module: My Network
Displays local network information: interfaces, routing, DNS, ARP, open ports.
"""

import sys
import os
import re
import socket
import struct
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QTableWidget, QTableWidgetItem, QPushButton,
    QHeaderView, QMessageBox, QFileDialog
)

try:
    import netifaces
except ImportError:
    netifaces = None

try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

try:
    from core.project_manager import ProjectManager
except ImportError:
    class ProjectManager:
        @staticmethod
        def save_result(module: str, data: dict) -> bool:
            logging.getLogger(__name__).info(f"Dummy save: {module}")
            return True

logger = logging.getLogger(__name__)


class MyNetworkWorker(QThread):
    interfaces_signal = pyqtSignal(list)
    routing_signal = pyqtSignal(list)
    dns_signal = pyqtSignal(list)
    arp_signal = pyqtSignal(list)
    ports_signal = pyqtSignal(list)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        try:
            ifaces = self.collect_interfaces()
            self.interfaces_signal.emit(ifaces)
            if self._abort: return

            routes = self.collect_routing_table()
            self.routing_signal.emit(routes)
            if self._abort: return

            dns_list = self.collect_dns()
            self.dns_signal.emit(dns_list)
            if self._abort: return

            arp_list = self.collect_arp_table()
            self.arp_signal.emit(arp_list)
            if self._abort: return

            ports = self.collect_open_ports()
            self.ports_signal.emit(ports)
            if self._abort: return

            self.finished_signal.emit()
        except Exception as e:
            self.error_signal.emit(str(e))

    def collect_interfaces(self) -> List[Dict]:
        interfaces = []
        if netifaces is None:
            logger.error("netifaces not installed")
            return interfaces

        rx_tx_data = {}
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        iface = line.split(':')[0].strip()
                        parts = line.split()
                        if len(parts) >= 10:
                            rx_bytes = parts[1]
                            tx_bytes = parts[9]
                            rx_tx_data[iface] = (rx_bytes, tx_bytes)
        except Exception as e:
            logger.error(f"/proc/net/dev error: {e}")

        for iface_name in netifaces.interfaces():
            if self._abort: break
            addrs = netifaces.ifaddresses(iface_name)
            ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', '')
            ipv6 = addrs.get(netifaces.AF_INET6, [{}])[0].get('addr', '').split('%')[0]
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')

            mtu = ''
            status = 'DOWN'
            try:
                with open(f'/sys/class/net/{iface_name}/mtu', 'r') as f:
                    mtu = f.read().strip()
                with open(f'/sys/class/net/{iface_name}/operstate', 'r') as f:
                    status = f.read().strip().upper()
            except:
                pass

            rx, tx = rx_tx_data.get(iface_name, ('0', '0'))

            interfaces.append({
                'interface': iface_name,
                'ipv4': ipv4,
                'ipv6': ipv6,
                'mac': mac,
                'mtu': mtu,
                'status': status,
                'rx_bytes': rx,
                'tx_bytes': tx
            })
        return interfaces

    def collect_routing_table(self) -> List[Dict]:
        routes = []
        try:
            with open('/proc/net/route', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    if self._abort: break
                    parts = line.strip().split()
                    if len(parts) < 8:
                        continue
                    iface = parts[0]
                    dest_hex = parts[1]
                    gateway_hex = parts[2]
                    mask_hex = parts[7]
                    metric = parts[5]

                    dest_ip = self.hex_to_ip(dest_hex)
                    gateway_ip = self.hex_to_ip(gateway_hex)
                    mask_ip = self.hex_to_ip(mask_hex)

                    routes.append({
                        'destination': dest_ip,
                        'gateway': gateway_ip,
                        'mask': mask_ip,
                        'interface': iface,
                        'metric': metric
                    })
        except Exception as e:
            logger.error(f"Routing error: {e}")
        return routes

    @staticmethod
    def hex_to_ip(hex_str: str) -> str:
        if len(hex_str) != 8:
            return '0.0.0.0'
        bytes_rev = bytes.fromhex(hex_str)[::-1]
        return socket.inet_ntoa(bytes_rev)

    def collect_dns(self) -> List[Dict]:
        dns_entries = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if parts[0] == 'nameserver' and len(parts) > 1:
                        dns_entries.append({'type': 'nameserver', 'value': parts[1]})
                    elif parts[0] == 'search' and len(parts) > 1:
                        dns_entries.append({'type': 'search', 'value': ' '.join(parts[1:])})
                    elif parts[0] == 'domain' and len(parts) > 1:
                        dns_entries.append({'type': 'domain', 'value': parts[1]})
        except Exception as e:
            logger.error(f"DNS error: {e}")
        return dns_entries

    def collect_arp_table(self) -> List[Dict]:
        arp_list = []
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    if self._abort: break
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        iface = parts[5]
                        vendor = self.lookup_vendor(mac)
                        arp_list.append({
                            'ip': ip,
                            'mac': mac,
                            'interface': iface,
                            'vendor': vendor
                        })
        except Exception as e:
            logger.error(f"ARP error: {e}")
        return arp_list

    def lookup_vendor(self, mac: str) -> str:
        if not mac or mac == '00:00:00:00:00:00':
            return ''
        try:
            from services.oui_lookup import OUILookup
            return OUILookup().get_vendor(mac)
        except Exception:
            return 'Unknown'

    def collect_open_ports(self) -> List[Dict]:
        ports = []
        ports.extend(self.parse_tcp_file('/proc/net/tcp', 'tcp'))
        ports.extend(self.parse_tcp_file('/proc/net/tcp6', 'tcp6'))
        unique = {}
        for p in ports:
            key = (p['port'], p['protocol'], p['pid'])
            if key not in unique:
                unique[key] = p
        return list(unique.values())

    def parse_tcp_file(self, filepath: str, proto: str) -> List[Dict]:
        entries = []
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    if self._abort: break
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue
                    local_addr = parts[1]
                    state = parts[3]
                    inode = parts[9]
                    if state != '0A':
                        continue
                    addr_part, port_hex = local_addr.split(':')
                    port = int(port_hex, 16)
                    ip_str = self.tcp_hex_to_ip(addr_part)
                    pid, proc_name = self.pid_from_inode(inode)
                    entries.append({
                        'port': port,
                        'protocol': proto,
                        'state': 'LISTEN',
                        'pid': pid,
                        'process_name': proc_name,
                        'ip': ip_str
                    })
        except Exception as e:
            logger.error(f"Parse {filepath} error: {e}")
        return entries

    def tcp_hex_to_ip(self, hex_str: str) -> str:
        if len(hex_str) == 8:
            bytes_rev = bytes.fromhex(hex_str)[::-1]
            return socket.inet_ntoa(bytes_rev)
        return 'IPv6'

    def pid_from_inode(self, inode: str) -> Tuple[int, str]:
        try:
            proc_dir = Path('/proc')
            for pid_dir in proc_dir.iterdir():
                if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                    continue
                fd_dir = pid_dir / 'fd'
                if not fd_dir.exists():
                    continue
                for fd_link in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd_link)
                        if f'socket:[{inode}]' in target:
                            comm_file = pid_dir / 'comm'
                            proc_name = comm_file.read_text().strip() if comm_file.exists() else 'unknown'
                            return int(pid_dir.name), proc_name
                    except:
                        continue
        except:
            pass
        return (0, 'unknown')


class MyNetworkWidget(QWidget):
    status_update = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.current_data = {}
        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.save_btn = QPushButton("Save to Project")
        self.export_html_btn = QPushButton("Export HTML")
        self.export_pdf_btn = QPushButton("Export PDF")
        toolbar.addWidget(self.refresh_btn)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.export_html_btn)
        toolbar.addWidget(self.export_pdf_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.interfaces_group = self._create_table_group(
            "Network Interfaces",
            ["Interface", "IPv4", "IPv6", "MAC", "MTU", "Status", "RX Bytes", "TX Bytes"]
        )
        self.routing_group = self._create_table_group(
            "Routing Table",
            ["Destination", "Gateway", "Mask", "Interface", "Metric"]
        )
        self.dns_group = self._create_table_group(
            "DNS Servers",
            ["Type", "Value"]
        )
        self.arp_group = self._create_table_group(
            "ARP Table",
            ["IP", "MAC", "Interface", "Vendor"]
        )
        self.ports_group = self._create_table_group(
            "Open Ports",
            ["Port", "Protocol", "State", "PID", "Process Name"]
        )

        layout.addWidget(self.interfaces_group)
        layout.addWidget(self.routing_group)
        layout.addWidget(self.dns_group)
        layout.addWidget(self.arp_group)
        layout.addWidget(self.ports_group)
        self.setLayout(layout)

    def _create_table_group(self, title: str, headers: List[str]) -> QGroupBox:
        group = QGroupBox(title)
        layout = QVBoxLayout()
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setAlternatingRowColors(True)
        layout.addWidget(table)
        group.setLayout(layout)
        group.table = table
        return group

    def connect_signals(self):
        self.refresh_btn.clicked.connect(self.start_refresh)
        self.save_btn.clicked.connect(self.save_to_project)
        self.export_html_btn.clicked.connect(self.export_html)
        self.export_pdf_btn.clicked.connect(self.export_pdf)

    def start_refresh(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Busy", "Refresh already in progress.")
            return
        self.status_update.emit("Refreshing network information...")
        self.worker = MyNetworkWorker()
        self.worker.interfaces_signal.connect(self.update_interfaces_table)
        self.worker.routing_signal.connect(self.update_routing_table)
        self.worker.dns_signal.connect(self.update_dns_table)
        self.worker.arp_signal.connect(self.update_arp_table)
        self.worker.ports_signal.connect(self.update_ports_table)
        self.worker.finished_signal.connect(self.on_refresh_finished)
        self.worker.error_signal.connect(self.on_worker_error)
        self.worker.start()

    def update_interfaces_table(self, ifaces):
        table = self.interfaces_group.table
        table.setRowCount(len(ifaces))
        for row, iface in enumerate(ifaces):
            table.setItem(row, 0, QTableWidgetItem(iface.get('interface', '')))
            table.setItem(row, 1, QTableWidgetItem(iface.get('ipv4', '')))
            table.setItem(row, 2, QTableWidgetItem(iface.get('ipv6', '')))
            table.setItem(row, 3, QTableWidgetItem(iface.get('mac', '')))
            table.setItem(row, 4, QTableWidgetItem(iface.get('mtu', '')))
            table.setItem(row, 5, QTableWidgetItem(iface.get('status', '')))
            table.setItem(row, 6, QTableWidgetItem(iface.get('rx_bytes', '0')))
            table.setItem(row, 7, QTableWidgetItem(iface.get('tx_bytes', '0')))
        self.current_data['interfaces'] = ifaces

    def update_routing_table(self, routes):
        table = self.routing_group.table
        table.setRowCount(len(routes))
        for row, r in enumerate(routes):
            table.setItem(row, 0, QTableWidgetItem(r.get('destination', '')))
            table.setItem(row, 1, QTableWidgetItem(r.get('gateway', '')))
            table.setItem(row, 2, QTableWidgetItem(r.get('mask', '')))
            table.setItem(row, 3, QTableWidgetItem(r.get('interface', '')))
            table.setItem(row, 4, QTableWidgetItem(r.get('metric', '')))
        self.current_data['routing'] = routes

    def update_dns_table(self, dns_list):
        table = self.dns_group.table
        table.setRowCount(len(dns_list))
        for row, d in enumerate(dns_list):
            table.setItem(row, 0, QTableWidgetItem(d.get('type', '')))
            table.setItem(row, 1, QTableWidgetItem(d.get('value', '')))
        self.current_data['dns'] = dns_list

    def update_arp_table(self, arp_list):
        table = self.arp_group.table
        table.setRowCount(len(arp_list))
        for row, a in enumerate(arp_list):
            table.setItem(row, 0, QTableWidgetItem(a.get('ip', '')))
            table.setItem(row, 1, QTableWidgetItem(a.get('mac', '')))
            table.setItem(row, 2, QTableWidgetItem(a.get('interface', '')))
            table.setItem(row, 3, QTableWidgetItem(a.get('vendor', '')))
        self.current_data['arp'] = arp_list

    def update_ports_table(self, ports):
        table = self.ports_group.table
        table.setRowCount(len(ports))
        for row, p in enumerate(ports):
            table.setItem(row, 0, QTableWidgetItem(str(p.get('port', ''))))
            table.setItem(row, 1, QTableWidgetItem(p.get('protocol', '')))
            table.setItem(row, 2, QTableWidgetItem(p.get('state', '')))
            table.setItem(row, 3, QTableWidgetItem(str(p.get('pid', ''))))
            table.setItem(row, 4, QTableWidgetItem(p.get('process_name', '')))
        self.current_data['ports'] = ports

    def on_refresh_finished(self):
        self.status_update.emit("Refresh completed.")
        if self.worker:
            self.worker.deleteLater()
            self.worker = None

    def on_worker_error(self, error_msg):
        self.status_update.emit(f"Error: {error_msg}")
        QMessageBox.critical(self, "Refresh Error", error_msg)
        self.worker = None

    def save_to_project(self):
        if not self.current_data:
            QMessageBox.warning(self, "No Data", "No data to save. Please refresh first.")
            return
        ProjectManager.save_result('my_network', self.current_data)
        self.status_update.emit("Saved to project.")

    def export_html(self):
        if not self.current_data:
            QMessageBox.warning(self, "No Data", "No data to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save HTML Report", "network_report.html", "HTML Files (*.html)")
        if not file_path:
            return
        html_content = self.generate_html_report()
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.status_update.emit(f"HTML report saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf(self):
        if not WEASYPRINT_AVAILABLE:
            QMessageBox.critical(self, "Missing Library", "WeasyPrint is not installed.")
            return
        if not self.current_data:
            QMessageBox.warning(self, "No Data", "No data to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save PDF Report", "network_report.pdf", "PDF Files (*.pdf)")
        if not file_path:
            return
        html_content = self.generate_html_report()
        try:
            css = CSS(string='@page { size: A4; margin: 1.5cm; } table { page-break-inside: avoid; }')
            font_config = FontConfiguration()
            HTML(string=html_content).write_pdf(file_path, stylesheets=[css], font_config=font_config)
            self.status_update.emit(f"PDF report saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def generate_html_report(self) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>AIMAS Network Report</title>
        <style>
            body {{ background: white; color: black; font-family: sans-serif; }}
            h1 {{ color: #0066cc; }}
            h2 {{ color: #0066cc; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
            th {{ background: #f2f2f2; }}
        </style>
        </head>
        <body>
        <h1>AIMAS Network Information Report</h1>
        <p>Generated: {timestamp}</p>
        """

        if 'interfaces' in self.current_data:
            html += "<h2>Network Interfaces</h2>"
            html += "<table><tr><th>Interface</th><th>IPv4</th><th>IPv6</th><th>MAC</th><th>MTU</th><th>Status</th><th>RX Bytes</th><th>TX Bytes</th></tr>"
            for iface in self.current_data['interfaces']:
                html += f"<tr><td>{iface.get('interface','')}</td><td>{iface.get('ipv4','')}</td><td>{iface.get('ipv6','')}</td><td>{iface.get('mac','')}</td><td>{iface.get('mtu','')}</td><td>{iface.get('status','')}</td><td>{iface.get('rx_bytes','0')}</td><td>{iface.get('tx_bytes','0')}</td></tr>"
            html += "</table>"

        if 'routing' in self.current_data:
            html += "<h2>Routing Table</h2><table><tr><th>Destination</th><th>Gateway</th><th>Mask</th><th>Interface</th><th>Metric</th></tr>"
            for r in self.current_data['routing']:
                html += f"<tr><td>{r.get('destination','')}</td><td>{r.get('gateway','')}</td><td>{r.get('mask','')}</td><td>{r.get('interface','')}</td><td>{r.get('metric','')}</td></tr>"
            html += "</table>"

        if 'dns' in self.current_data:
            html += "<h2>DNS Servers</h2><table><tr><th>Type</th><th>Value</th></tr>"
            for d in self.current_data['dns']:
                html += f"<tr><td>{d.get('type','')}</td><td>{d.get('value','')}</td></tr>"
            html += "</table>"

        if 'arp' in self.current_data:
            html += "<h2>ARP Table</h2><table><tr><th>IP</th><th>MAC</th><th>Interface</th><th>Vendor</th></tr>"
            for a in self.current_data['arp']:
                html += f"<tr><td>{a.get('ip','')}</td><td>{a.get('mac','')}</td><td>{a.get('interface','')}</td><td>{a.get('vendor','')}</td></tr>"
            html += "</table>"

        if 'ports' in self.current_data:
            html += "<h2>Open Ports</h2><table><tr><th>Port</th><th>Protocol</th><th>State</th><th>PID</th><th>Process Name</th></tr>"
            for p in self.current_data['ports']:
                html += f"<tr><td>{p.get('port','')}</td><td>{p.get('protocol','')}</td><td>{p.get('state','')}</td><td>{p.get('pid','')}</td><td>{p.get('process_name','')}</td></tr>"
            html += "</table>"

        html += "</body></html>"
        return html

    def get_module_name(self) -> str:
        return "My Network"
