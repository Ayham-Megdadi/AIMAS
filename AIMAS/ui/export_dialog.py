#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Export Dialog - HTML/PDF export with format selection.
"""

from pathlib import Path
from datetime import datetime
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QRadioButton,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QProgressBar,
                             QMessageBox)
from services.report_generator import ReportGenerator


class ExportDialog(QDialog):
    def __init__(self, module_name: str, target: str, html_content: str, parent=None):
        super().__init__(parent)
        self.module_name = module_name
        self.target = target
        self.html_content = html_content
        self.setWindowTitle("Export Report")
        self.setModal(True)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Format:"))
        self.html_radio = QRadioButton("HTML")
        self.pdf_radio = QRadioButton("PDF")
        self.html_radio.setChecked(True)
        layout.addWidget(self.html_radio)
        layout.addWidget(self.pdf_radio)

        layout.addWidget(QLabel("Output File:"))
        file_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        default_name = f"{self.module_name}_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        self.path_edit.setText(str(Path.home() / "Desktop" / default_name))
        self.browse_btn = QPushButton("Browse")
        file_layout.addWidget(self.path_edit)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.export_btn = QPushButton("Export")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.browse_btn.clicked.connect(self.browse)
        self.export_btn.clicked.connect(self.export)
        self.cancel_btn.clicked.connect(self.reject)

    def browse(self):
        ext = "html" if self.html_radio.isChecked() else "pdf"
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "", f"{ext.upper()} Files (*.{ext})")
        if path:
            self.path_edit.setText(path)

    def export(self):
        path = Path(self.path_edit.text())
        if self.html_radio.isChecked():
            success = ReportGenerator.save_html(self.html_content, path)
        else:
            self.progress.setVisible(True)
            self.progress.setRange(0, 0)
            self.repaint()
            success = ReportGenerator.save_pdf(self.html_content, path)
            self.progress.setVisible(False)
        if success:
            QMessageBox.information(self, "Export Complete", f"Report saved to {path}")
            self.accept()
        else:
            QMessageBox.critical(self, "Export Failed", "Could not save the report.")
