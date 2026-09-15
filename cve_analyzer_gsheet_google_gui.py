#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
)
from PySide6.QtCore import Qt

import gspread
from google.oauth2.service_account import Credentials

# Importa tu backend
from cve_analyzer_gsheet_google import (
    CrowdStrikeClient,
    gemini_analyze,
)

# Variables de entorno
CROWDSTRIKE_CLIENT_ID     = os.getenv("CS_CLIENT_ID")
CROWDSTRIKE_CLIENT_SECRET = os.getenv("CS_CLIENT_SECRET")
CROWDSTRIKE_BASE_URL      = os.getenv("CS_BASE_URL")

GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")
GSHEET_URL        = os.getenv("GSHEET_URL")
GSHEET_WORKSHEET  = os.getenv("GSHEET_WORKSHEET")

GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")


class CVEAnalyzerGSheet(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CVE Analyzer — Google Sheets")
        self.resize(1200, 750)

        self.cs_client = CrowdStrikeClient(
            CROWDSTRIKE_CLIENT_ID,
            CROWDSTRIKE_CLIENT_SECRET,
            CROWDSTRIKE_BASE_URL,
        )

        # Lista para almacenar resultados de todas las filas analizadas
        self.results_to_update = {}

        self._build_ui()
        self._load_gsheet()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout()

        # Tabla
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["HOSTNAME", "IP", "CVE", "Resultado"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Botones
        btn_layout = QHBoxLayout()

        analyze_btn = QPushButton("Analizar fila seleccionada")
        analyze_btn.clicked.connect(self.on_analyze_selected)

        analyze_all_btn = QPushButton("Analizar TODAS las filas")
        analyze_all_btn.clicked.connect(self.on_analyze_all)

        update_btn = QPushButton("Actualizar Google Sheets")
        update_btn.clicked.connect(self.update_gsheet_result)

        btn_layout.addWidget(analyze_btn)
        btn_layout.addWidget(analyze_all_btn)
        btn_layout.addWidget(update_btn)

        # Área de salida
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        layout.addWidget(QLabel("Datos cargados desde Google Sheets"))
        layout.addWidget(self.table)
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel("Resultado del análisis"))
        layout.addWidget(self.output)

        self.setLayout(layout)

    # ---------------------------------------------------------
    # Google Sheets: lectura
    # ---------------------------------------------------------
    def _load_gsheet(self):
        try:
            creds = Credentials.from_service_account_file(
                GOOGLE_SERVICE_ACCOUNT_FILE,
                scopes=["https://www.googleapis.com/auth/spreadsheets"]
            )

            self.client = gspread.authorize(creds)
            self.sheet = self.client.open_by_url(GSHEET_URL)
            self.worksheet = self.sheet.worksheet(GSHEET_WORKSHEET)

            rows = self.worksheet.get_all_values()

            headers = rows[0]
            data = rows[1:]

            # Verificar si existe la columna Resultado
            if "Resultado" not in headers:
                headers.append("Resultado")
                self.worksheet.update([headers])
                for i in range(len(data)):
                    data[i].append("")

            self.table.setRowCount(len(data))
            self.table.setColumnCount(len(headers))
            self.table.setHorizontalHeaderLabels(headers)

            for i, row in enumerate(data):
                for j, value in enumerate(row):
                    self.table.setItem(i, j, QTableWidgetItem(value))

        except Exception as e:
            QMessageBox.critical(self, "Error Google Sheets", str(e))

    # ---------------------------------------------------------
    # Log helper
    # ---------------------------------------------------------
    def log(self, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.output.append(f"[{ts}] {msg}")

    # ---------------------------------------------------------
    # Acción: Analizar fila seleccionada
    # ---------------------------------------------------------
    def on_analyze_selected(self):
        selected = self.table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "Sin selección", "Selecciona una fila primero.")
            return

        self._analyze_row(selected)

    # ---------------------------------------------------------
    # Acción: Analizar TODAS las filas
    # ---------------------------------------------------------
    def on_analyze_all(self):
        self.output.clear()
        self.log("Iniciando análisis de todas las filas...")

        total_rows = self.table.rowCount()

        try:
            self.log("Autenticando con CrowdStrike...")
            self.cs_client.authenticate()
            self.log("Autenticación exitosa.")
        except Exception as e:
            self.log(f"Error autenticación: {e}")
            return

        for row in range(total_rows):
            hostname = self.table.item(row, 0).text().strip()
            ip       = self.table.item(row, 1).text().strip()
            cve_id   = self.table.item(row, 2).text().strip()

            self.log(f"\nAnalizando fila {row+1}: Host={hostname}, IP={ip}, CVE={cve_id}")
            self._analyze_row(row, log_only=True)

        self.log("\nAnálisis de todas las filas completado.")

    # ---------------------------------------------------------
    # Función interna para analizar una fila
    # ---------------------------------------------------------
    def _analyze_row(self, row, log_only=False):
        hostname = self.table.item(row, 0).text().strip()
        ip       = self.table.item(row, 1).text().strip()
        cve_id   = self.table.item(row, 2).text().strip()

        self.log(f"Consultando Spotlight para {hostname}...")

        vulns = self.cs_client.get_vulnerabilities_by_cve(cve_id, hostname, ip)

        # ------------------------------
        # NO VULNERABLE
        # ------------------------------
        if not vulns:
            result = "NO ENCONTRADO COMO VULNERABLE ACTIVO"
            self.log(result)
            self.table.setItem(row, 3, QTableWidgetItem(result))

            # Guardar para actualización masiva
            self.results_to_update[row] = result
            return

        # ------------------------------
        # VULNERABLE
        # ------------------------------
        self.log(f"Se encontraron {len(vulns)} vulnerabilidades activas.")
        result = "VULNERABLE"
        self.table.setItem(row, 3, QTableWidgetItem(result))

        # Guardar para actualización masiva
        self.results_to_update[row] = result

        if not log_only and GEMINI_API_KEY:
            analysis = gemini_analyze(cve_id, vulns, GEMINI_API_KEY)
            self.output.append("\n===== ANÁLISIS GEMINI =====\n")
            self.output.append(analysis)

    # ---------------------------------------------------------
    # Acción: Actualizar Google Sheets (TODAS las filas analizadas)
    # ---------------------------------------------------------
    def update_gsheet_result(self):
        if not self.results_to_update:
            QMessageBox.warning(self, "Sin análisis", "Primero analiza una fila o todas.")
            return

        try:
            for row, result in self.results_to_update.items():
                sheet_row = row + 2  # +2 por encabezados
                col = self.table.columnCount()  # Última columna = Resultado
                self.worksheet.update_cell(sheet_row, col, result)

            QMessageBox.information(self, "Actualizado", "Google Sheets actualizado correctamente.")

        except Exception as e:
            QMessageBox.critical(self, "Error al actualizar", str(e))


def main():
    app = QApplication(sys.argv)
    window = CVEAnalyzerGSheet()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
