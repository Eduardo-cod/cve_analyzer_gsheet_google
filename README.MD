# CVE Analyzer GSheet — CrowdStrike + Google Sheets + Gemini
Interfaz técnica para análisis automatizado de vulnerabilidades en activos gestionados mediante CrowdStrike Falcon Spotlight, con integración directa a Google Sheets y análisis opcional con Gemini.

---

## 📌 Descripción técnica
CVE Analyzer GSheet es una herramienta diseñada para automatizar la validación de vulnerabilidades (CVE) en hosts administrados por CrowdStrike. El sistema carga datos desde Google Sheets, consulta Spotlight para determinar si un host es vulnerable y actualiza la hoja con los resultados. La interfaz gráfica en PySide6 permite ejecutar análisis individuales o masivos, y opcionalmente generar análisis técnicos con Gemini.

---

## 🧩 Arquitectura del sistema
/cve_analyzer_gsheet_google.py   # Backend: CrowdStrike + Gemini
/ui_cve_analyzer_gsheet.py       # Interfaz gráfica PySide6
.env                             # Variables de entorno
README.md

### Backend (cve_analyzer_gsheet_google.py)
- Autenticación OAuth2 con CrowdStrike.
- Consulta de Spotlight Vulnerabilities.
- Normalización de resultados.
- Integración opcional con Gemini para análisis técnico.

### Interfaz (ui_cve_analyzer_gsheet.py)
- Lectura de Google Sheets mediante Service Account.
- Renderizado de tabla HOSTNAME/IP/CVE/Resultado.
- Acciones:
  - Analizar fila seleccionada.
  - Analizar todas las filas.
  - Actualizar Google Sheets con todos los resultados.

---

## 🚀 Funcionalidades principales

### ✔ Integración con Google Sheets
- Lectura automática de la hoja especificada.
- Creación automática de la columna **Resultado** si no existe.
- Actualización masiva de resultados.

### ✔ Integración con CrowdStrike Spotlight
- Validación de vulnerabilidades activas por:
  - Hostname
  - IP
  - CVE
- Clasificación automática:
  - `VULNERABLE`
  - `NO ENCONTRADO COMO VULNERABLE ACTIVO`

### ✔ Interfaz gráfica PySide6
- Tabla interactiva con los datos del Sheet.
- Botones de acción:
  - Analizar fila seleccionada
  - Analizar todas las filas
  - Actualizar Google Sheets

### ✔ Integración opcional con Gemini
- Generación de análisis técnico del CVE.
- Resultados mostrados en la interfaz (no escritos en la hoja).

---

## 🔧 Requisitos técnicos

### Python
Python 3.10+

### Dependencias
pip install PySide6 gspread google-auth crowdstrike-falconpy python-dotenv requests


### Variables de entorno
CS_CLIENT_ID=
CS_CLIENT_SECRET=
CS_BASE_URL=
GOOGLE_SERVICE_ACCOUNT_FILE=
GSHEET_URL=
GSHEET_WORKSHEET=
GEMINI_API_KEY=


---

## 📄 Flujo de operación

1. La interfaz carga automáticamente los datos desde Google Sheets.
2. El usuario selecciona:
   - Analizar una fila
   - Analizar todas las filas
3. La herramienta consulta CrowdStrike Spotlight:
   - Si el host tiene vulnerabilidades activas → `VULNERABLE`
   - Si no → `NO ENCONTRADO COMO VULNERABLE ACTIVO`
4. El usuario presiona **Actualizar Google Sheets** para sincronizar los resultados.
5. (Opcional) Gemini genera un análisis técnico del CVE.

---

## 🛠 Extensibilidad
El sistema está diseñado para ampliarse fácilmente:
- Nuevas columnas en Google Sheets (CVSS, severidad, días abiertos).
- Exportación de reportes.
- Integración con bases de datos internas.
- Automatización vía cron o pipelines CI/CD.

---

## 📜 Licencia
MIT License

---

## 🤝 Contribuciones
Pull requests y mejoras son bienvenidas.
