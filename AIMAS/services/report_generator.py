#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Report Generator - HTML and PDF reports with unified template.
"""

import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Any, List

logger = logging.getLogger(__name__)

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


@dataclass
class Section:
    title: str
    content_type: str  # 'table', 'text', 'key_value', 'code'
    data: Any


class ReportGenerator:
    @staticmethod
    def generate_html(report_title: str, module_name: str, target: str,
                      sections: List[Section], metadata: dict = None) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>{report_title}</title>
<style>
    body {{ background-color: #0D1117; color: #E6EDF3; font-family: 'Inter', sans-serif; margin: 2rem; }}
    h1 {{ color: #00FF9C; border-bottom: 2px solid #30363D; }}
    h2 {{ color: #00B4D8; margin-top: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; background-color: #161B22; }}
    th, td {{ border: 1px solid #30363D; padding: 8px; text-align: left; }}
    th {{ background-color: #1C2128; color: #00B4D8; }}
    tr:nth-child(even) {{ background-color: #1C2128; }}
    .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #8B949E; text-align: center; }}
</style>
</head>
<body>
<h1>{report_title}</h1>
<p><strong>Module:</strong> {module_name} | <strong>Target:</strong> {target} | <strong>Generated:</strong> {timestamp}</p>
"""
        for sec in sections:
            html += f"<h2>{sec.title}</h2>"
            if sec.content_type == 'table':
                # sec.data is list of lists (headers, rows)
                headers = sec.data[0]
                rows = sec.data[1:]
                html += "<table><thead><tr>"
                for h in headers:
                    html += f"<th>{h}</th>"
                html += "</tr></thead><tbody>"
                for row in rows:
                    html += "<tr>"
                    for cell in row:
                        html += f"<td>{cell}</td>"
                    html += "</tr>"
                html += "</tbody></table>"
            elif sec.content_type == 'text':
                html += f"<p>{sec.data}</p>"
            elif sec.content_type == 'key_value':
                html += "<table>"
                for k, v in sec.data.items():
                    html += f"<tr><th>{k}</th><td>{v}</td></tr>"
                html += "</table>"
            elif sec.content_type == 'code':
                html += f"<pre>{sec.data}</pre>"
        html += f'<div class="footer">AIMAS Cybersecurity Toolkit | For authorized use only</div>'
        html += "</body></html>"
        return html

    @staticmethod
    def save_html(html: str, filepath: Path) -> bool:
        try:
            filepath.write_text(html, encoding='utf-8')
            return True
        except Exception as e:
            logger.error(f"Save HTML failed: {e}")
            return False

    @staticmethod
    def save_pdf(html: str, filepath: Path) -> bool:
        if not WEASYPRINT_AVAILABLE:
            logger.warning("WeasyPrint not installed. Saving as HTML instead.")
            return ReportGenerator.save_html(html, filepath.with_suffix('.html'))
        try:
            css = CSS(string='@page { margin: 1.5cm; }')
            HTML(string=html).write_pdf(str(filepath), stylesheets=[css])
            return True
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return False

    @staticmethod
    def generate_scan_report(scan_result: dict) -> str:
        # Simplified conversion
        sections = []
        sections.append(Section("Summary", "text", scan_result.get("summary", "")))
        if "table" in scan_result:
            sections.append(Section("Details", "table", scan_result["table"]))
        return ReportGenerator.generate_html(
            report_title=scan_result.get("title", "Scan Report"),
            module_name=scan_result.get("module", "Unknown"),
            target=scan_result.get("target", ""),
            sections=sections,
            metadata=scan_result.get("metadata")
        )
