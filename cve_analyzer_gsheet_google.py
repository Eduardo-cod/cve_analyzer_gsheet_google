#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Autor: Eduardo De Jesus Esparza
Empresa: Accenture
Versión: 1.2.0
'''

__author__ = "Eduardo De Jesus Esparza"
__version__ = "1.2.0"
__date__ = "2026-09-14"
__project__ = "Crowdstrike cve_analyzer"

"""
CVE Analyzer - CrowdStrike (FalconPy SDK)
Lee un archivo Excel con HOST, IP y CVE, consulta la API de CrowdStrike
para verificar vulnerabilidades.

Requisitos:
    pip install crowdstrike-falconpy pandas openpyxl requests
"""

import os
import sys
import json
import time
import random
import argparse
import requests
import pandas as pd
import gspread
from dotenv import load_dotenv
from datetime import datetime, UTC
from openpyxl import load_workbook
from google.oauth2.service_account import Credentials
from gspread.utils import rowcol_to_a1
from openpyxl import load_workbook

# ── FalconPy SDK ──────────────────────────────────────────────
try:
    from falconpy import SpotlightVulnerabilities, Hosts, OAuth2
except ImportError:
    print("\n[ERROR] FalconPy no está instalado. Ejecuta:")
    print("  pip install crowdstrike-falconpy\n")
    sys.exit(1)


# ─────────────────────────────────────────────
# CONFIGURACIÓN — variables de entorno
# ─────────────────────────────────────────────
load_dotenv()
CROWDSTRIKE_CLIENT_ID     = os.getenv("CS_CLIENT_ID")
CROWDSTRIKE_CLIENT_SECRET = os.getenv("CS_CLIENT_SECRET")
CROWDSTRIKE_BASE_URL      = os.getenv("CS_BASE_URL")

GSHEET_URL = os.getenv("GSHEET_URL", "")
GSHEET_WORKSHEET = os.getenv("GSHEET_WORKSHEET", "")
GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE", "")

GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
DEBUG_CROWDSTRIKE = False
#GEMINI_MODEL    = "gemini-2.0-flash"
'''GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)
'''


# ─────────────────────────────────────────────
# COLORES PARA CONSOLA
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES PARA CAMPOS DE SPOTLIGHT
# ─────────────────────────────────────────────
def get_nested(data: dict, *keys, default=None):
    """
    Obtiene de forma segura un valor dentro de diccionarios anidados.
    """
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


def first_value(*values, default="N/A"):
    """
    Devuelve el primer valor válido.
    """
    for value in values:
        if value is None:
            continue

        if isinstance(value, str):
            value = value.strip()

            if value and value.lower() not in {
                "none",
                "null",
                "n/a",
            }:
                return value

        elif value != "":
            return value

    return default


def format_complex_value(value, default="N/A") -> str:
    """
    Convierte diccionarios, listas y valores simples a texto.
    """
    if value is None or value == "":
        return default

    if isinstance(value, dict):
        preferred_keys = (
            "recommendation",
            "action",
            "description",
            "remediation",
            "fix",
            "solution",
        )

        extracted = []

        for key in preferred_keys:
            field_value = value.get(key)

            if field_value:
                extracted.append(str(field_value).strip())

        if extracted:
            return " | ".join(dict.fromkeys(extracted))

        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    if isinstance(value, list):
        formatted_items = []

        for item in value:
            if isinstance(item, dict):
                formatted_items.append(
                    json.dumps(
                        item,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
            elif item is not None and str(item).strip():
                formatted_items.append(str(item).strip())

        if formatted_items:
            return " | ".join(formatted_items)

        return default

    return str(value).strip() or default


def calculate_days_open(vulnerability: dict):
    """
    Calcula los días abiertos desde created_timestamp.

    Si la vulnerabilidad está cerrada, utiliza closed_timestamp.
    Si continúa activa, utiliza la fecha actual UTC.
    """
    direct_days = first_value(
        vulnerability.get("days_open"),
        vulnerability.get("daysOpen"),
        default=None,
    )

    if direct_days is not None:
        try:
            return int(float(direct_days))
        except (TypeError, ValueError):
            return str(direct_days)

    created_value = first_value(
        vulnerability.get("created_timestamp"),
        vulnerability.get("created_on"),
        vulnerability.get("created_date"),
        default=None,
    )

    if not created_value:
        return "N/A"

    status = str(
        vulnerability.get("status", "")
    ).strip().lower()

    closed_value = first_value(
        vulnerability.get("closed_timestamp"),
        vulnerability.get("closed_on"),
        vulnerability.get("resolved_timestamp"),
        default=None,
    )

    try:
        created_text = str(created_value).replace("Z", "+00:00")
        created_date = datetime.fromisoformat(created_text)

        if created_date.tzinfo is None:
            created_date = created_date.replace(tzinfo=UTC)

        closed_statuses = {
            "closed",
            "fixed",
            "resolved",
        }

        if status in closed_statuses and closed_value:
            closed_text = str(closed_value).replace("Z", "+00:00")
            end_date = datetime.fromisoformat(closed_text)

            if end_date.tzinfo is None:
                end_date = end_date.replace(tzinfo=UTC)
        else:
            end_date = datetime.now(UTC)

        return max((end_date - created_date).days, 0)

    except (ValueError, TypeError, AttributeError):
        return "N/A"


def extract_vulnerable_product_versions(
    vulnerability: dict,
) -> str:
    """
    Obtiene producto y versión vulnerable desde la respuesta de Spotlight.
    """
    versions = first_value(
        vulnerability.get("vulnerable_product_versions"),
        vulnerability.get("vulnerable_versions"),
        get_nested(
            vulnerability,
            "cve",
            "vulnerable_product_versions",
            default=None,
        ),
        get_nested(
            vulnerability,
            "app",
            "version",
            default=None,
        ),
        default=None,
    )

    if versions is not None:
        return format_complex_value(versions)

    applications = vulnerability.get("apps", [])

    if not applications:
        single_app = vulnerability.get("app")

        if single_app:
            applications = [single_app]

    product_versions = []

    for app in applications:
        if not isinstance(app, dict):
            if str(app).strip():
                product_versions.append(str(app).strip())
            continue

        product_name = first_value(
            app.get("product_name"),
            app.get("product"),
            app.get("name"),
            app.get("application_name"),
            app.get("vendor"),
            default="",
        )

        version = first_value(
            app.get("version"),
            app.get("product_version"),
            app.get("current_version"),
            app.get("installed_version"),
            default="",
        )

        product_text = " ".join(
            str(value).strip()
            for value in (product_name, version)
            if value and str(value).strip()
        )

        if product_text:
            product_versions.append(product_text)

    if not product_versions:
        return "N/A"

    return " | ".join(dict.fromkeys(product_versions))


def extract_vulnerability_fields(
    vulnerability: dict,
    fallback_cve: str = "",
) -> dict:
    """
    Normaliza los campos de CrowdStrike Spotlight.
    """
    cve_data = vulnerability.get("cve", {})
    remediation_data = vulnerability.get("remediation", {})

    vulnerability_id = first_value(
        get_nested(vulnerability, "cve", "id", default=None),
        vulnerability.get("cve_id"),
        fallback_cve,
        vulnerability.get("id"),
    )

    exprt_rating = first_value(
        vulnerability.get("exprt_rating"),
        vulnerability.get("exprtRating"),
        vulnerability.get("exploitability"),
        get_nested(cve_data, "exprt_rating", default=None),
        get_nested(cve_data, "exploitability", default=None),
    )

    cvss_severity = first_value(
        cve_data.get("severity"),
        vulnerability.get("severity"),
    )

    cvss_score = first_value(
        cve_data.get("base_score"),
        cve_data.get("cvss_score"),
        vulnerability.get("base_score"),
        vulnerability.get("cvss_score"),
    )

    exploit_status = first_value(
        vulnerability.get("exploit_status"),
        vulnerability.get("exploitStatus"),
        cve_data.get("exploit_status"),
        cve_data.get("exploitability_status"),
        vulnerability.get("exploitability_status"),
    )

    if isinstance(remediation_data, dict):
        remediation = first_value(
            remediation_data.get("recommendation"),
            remediation_data.get("action"),
            remediation_data.get("description"),
            vulnerability.get("remediation_text"),
            remediation_data,
        )
    else:
        remediation = first_value(
            vulnerability.get("remediation_text"),
            remediation_data,
        )

    status = first_value(
        vulnerability.get("status"),
    )

    return {
        "vulnerability_id": str(vulnerability_id),
        "exprt_rating": str(exprt_rating),
        "cvss_severity": str(cvss_severity),
        "cvss_score": str(cvss_score),
        "exploit_status": str(exploit_status),
        "remediation": format_complex_value(remediation),
        "vulnerable_product_versions":
            extract_vulnerable_product_versions(vulnerability),
        "status": str(status),
        "days_open": calculate_days_open(vulnerability),
    }

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════╗
║        CVE ANALYZER  —  CrowdStrike                  ║
║              Powered by FalconPy SDK                 ║
╚══════════════════════════════════════════════════════╝
{C.RESET}""")


# ─────────────────────────────────────────────
# CROWDSTRIKE — FalconPy SDK
# ─────────────────────────────────────────────
class CrowdStrikeClient:
    def __init__(self, client_id: str, client_secret: str, base_url: str):
        # OAuth2 compartido entre Service Classes
        self._auth = OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )
        self.spotlight = SpotlightVulnerabilities(auth_object=self._auth)
        self.hosts     = Hosts(auth_object=self._auth)

    def authenticate(self) -> bool:
        """Valida que las credenciales sean correctas."""
        resp = self._auth.token()
        if resp["status_code"] == 201:
            return True
        errors = resp.get("body", {}).get("errors", [])
        msg    = errors[0].get("message", "Error desconocido") if errors else str(resp)
        raise PermissionError(f"Autenticación fallida: {msg}")

    def get_aid_by_hostname_ip(self, hostname: str, ip: str):

        q_resp = self.hosts.query_devices_by_filter(
            filter=f"hostname:'{hostname}'",
            limit=20
        )

        if q_resp["status_code"] != 200:
            return None

        device_ids = q_resp["body"].get("resources", [])

        if not device_ids:
            return None

        d_resp = self.hosts.get_device_details(
            ids=device_ids
        )

        if d_resp["status_code"] != 200:
            return None

        devices = d_resp["body"].get("resources", [])

        print("\n========== HOSTS ENCONTRADOS ==========\n")

        for device in devices:

            local_ip = str(
                device.get("local_ip", "")
            )

            print(
                f"HOST={device.get('hostname')} "
                f"IP={local_ip} "
                f"AID={device.get('device_id')}"
            )

            if local_ip == ip:
                return device["device_id"]

        return None

    ''' solo se obtiene informacion validando solamente hostname -- de esta manera daba falsos positivos
    def get_aid_by_hostname(self, hostname: str) -> str | None:
        """
        Obtiene el AID (Agent ID) utilizando el hostname.
        """

        try:
            q_resp = self.hosts.query_devices_by_filter(
                filter=f"hostname:'{hostname}'",
                limit=1
            )

            if q_resp["status_code"] != 200:
                return None

            resources = q_resp["body"].get("resources", [])

            if not resources:
                return None

            return resources[0]

        except Exception as e:
            print(f"  {C.YELLOW}[WARN] Error obteniendo AID: {e}{C.RESET}")
            return None
        '''

    def get_vulnerabilities_by_cve(self, cve_id: str, hostname: str,ip: str) -> list[dict]:
        """
        Busca vulnerabilidades mediante:
        hostname -> AID -> Spotlight
        """

        aid = self.get_aid_by_hostname_ip(hostname, ip)
        print()

        print("========== HOST SELECCIONADO ==========")
        print("Hostname :", hostname)
        print("IP       :", ip)
        print("AID      :", aid)
        print("=======================================")

        print()

        if not aid:
            print(
                f"  {C.YELLOW}[WARN] No se encontró AID para {hostname}{C.RESET}"
            )
            return []

        print(f"    [DEBUG] Hostname : {hostname}")
        print(f"    [DEBUG] AID      : {aid}")
        print(f"    [DEBUG] CVE      : {cve_id}")

        filter_str = f"cve.id:'{cve_id}'+aid:'{aid}'"

        q_resp = self.spotlight.query_vulnerabilities_combined(
            filter=filter_str,
            facet=[
                "cve",
                "host_info",
                "remediation",
                "evaluation_logic",
            ],
            limit=100)

        if q_resp["status_code"] != 200:
            errors = q_resp.get("body", {}).get("errors", [])

            print(
                f"  {C.YELLOW}[WARN] Spotlight query error: "
                f"{errors}{C.RESET}"
            )

            return []

        details = q_resp.get("body", {}).get("resources", [])

        if not details:
            return []

        filtered = []

        for v in details:

            status = str(
                v.get("status", "")
            ).lower()

            print(
                f"[DEBUG] STATUS={status}"
            )

            if status in (
                "closed",
                "fixed",
                "resolved"
            ):

                print(
                    f"[DEBUG] CVE descartado. "
                    f"Status={status}"
                )

                continue

            suppression_info = v.get(
                "suppression_info",
                {}
            )

            is_suppressed = bool(
                suppression_info.get(
                    "is_suppressed",
                    False,
                )
            )

            if is_suppressed:
                print(
                    "[DEBUG] CVE descartado porque está suprimido."
                )
                continue

            filtered.append(v)

            if DEBUG_CROWDSTRIKE:
                print(
                    json.dumps(
                        v,
                        indent=2,
                        ensure_ascii=False
                    )
                )

        return filtered
    '''
    # ── Spotlight ─────────────────────────────────────────────
    def get_vulnerabilities_by_cve(self, cve_id: str, hostname: str) -> list[dict]:
        """
        Usa SpotlightVulnerabilities para buscar un CVE en un host específico.
        Devuelve lista de vulnerability detail dicts.
        """
        filter_str = f"cve.id:'{cve_id}'+aid.hostname:'{hostname}'"

        # 1. Query IDs
        q_resp = self.spotlight.query_vulnerabilities(
            filter=filter_str,
            limit=400,
        )
        if q_resp["status_code"] != 200:
            errors = q_resp.get("body", {}).get("errors", [])
            print(f"  {C.YELLOW}[WARN] Spotlight query error: {errors}{C.RESET}")
            return []

        ids = q_resp["body"].get("resources", [])
        if not ids:
            return []

        # 2. Fetch details
        d_resp = self.spotlight.get_vulnerabilities(ids=ids)
        if d_resp["status_code"] != 200:
            errors = d_resp.get("body", {}).get("errors", [])
            print(f"  {C.YELLOW}[WARN] Spotlight details error: {errors}{C.RESET}")
            return []

        return d_resp["body"].get("resources", [])
    '''
    # ── Hosts ──────────────────────────────────────────────────
    def get_host_info(self, hostname: str) -> dict | None:
        """Busca información del host usando la Service Class Hosts."""
        q_resp = self.hosts.query_devices_by_filter(
            filter=f"hostname:'{hostname}'",
            limit=1,
        )
        if q_resp["status_code"] != 200:
            return None

        device_ids = q_resp["body"].get("resources", [])
        if not device_ids:
            return None

        d_resp = self.hosts.get_device_details(ids=device_ids)
        if d_resp["status_code"] != 200:
            return None

        resources = d_resp["body"].get("resources", [])
        return resources[0] if resources else None

# ─────────────────────────────────────────────
# GEMINI — análisis y soluciones
# ─────────────────────────────────────────────

GEMINI_MODELS_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models"
)

GEMINI_BASE_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
)


def get_available_gemini_models(api_key: str) -> list[str]:
    """
    Consulta los modelos disponibles de Gemini y devuelve únicamente
    modelos compatibles con generateContent.

    Excluye modelos TTS, audio, imagen, embedding y preview.
    """

    preferred_models = [
        "gemini-2.5-flash",
        "gemini-2.5-pro",
    ]

    try:
        response = requests.get(
            GEMINI_MODELS_URL,
            params={"key": api_key},
            timeout=30,
        )

        if response.status_code != 200:
            print(
                f"{C.YELLOW}[WARN] No fue posible consultar los modelos "
                f"de Gemini. HTTP {response.status_code}{C.RESET}"
            )
            print(response.text)
            return []

        data = response.json()
        available_models = []

        for model_data in data.get("models", []):
            full_name = str(model_data.get("name", ""))
            short_name = full_name.removeprefix("models/")

            supported_methods = model_data.get(
                "supportedGenerationMethods",
                [],
            )

            excluded_terms = (
                "tts",
                "audio",
                "image",
                "embedding",
                "aqa",
                "preview-tts",
            )

            if any(
                term in short_name.lower()
                for term in excluded_terms
            ):
                continue

            if "generateContent" in supported_methods:
                available_models.append(short_name)

        # Ordenar primero los modelos preferidos.
        ordered_models = [
            model
            for model in preferred_models
            if model in available_models
        ]

        # Agregar otros modelos válidos como fallback.
        ordered_models.extend(
            model
            for model in available_models
            if model not in ordered_models
        )

        print("\n==============================")
        print("MODELOS GEMINI PARA ANÁLISIS")
        print("==============================")

        if ordered_models:
            for model in ordered_models:
                print(f"  -> {model}")
        else:
            print("  No se encontraron modelos compatibles.")

        print("==============================\n")

        return ordered_models

    except requests.RequestException as error:
        print(
            f"{C.YELLOW}[WARN] Error de conexión al consultar "
            f"modelos Gemini: {error}{C.RESET}"
        )
        return []

    except (ValueError, KeyError, TypeError) as error:
        print(
            f"{C.YELLOW}[WARN] Respuesta de modelos Gemini "
            f"no válida: {error}{C.RESET}"
        )
        return []


def extract_gemini_text(data: dict) -> str | None:
    """
    Extrae de forma segura el texto de la respuesta de Gemini.
    """

    candidates = data.get("candidates", [])

    if not candidates:
        return None

    content = candidates[0].get("content", {})
    parts = content.get("parts", [])

    text_parts = [
        str(part.get("text", ""))
        for part in parts
        if part.get("text")
    ]

    final_text = "\n".join(text_parts).strip()

    return final_text or None


def gemini_analyze(
    cve_id: str,
    vuln_details: list[dict],
    api_key: str,
) -> str:
    """
    Analiza una vulnerabilidad usando Gemini.

    Implementa:
    - Detección dinámica de modelos.
    - Exclusión de modelos TTS.
    - Fallback entre modelos.
    - Reintentos con backoff exponencial y jitter.
    """

    vuln_summary = json.dumps(
        vuln_details,
        ensure_ascii=False,
        indent=2,
    )[:6000]

    prompt = (
        "Eres un experto en ciberseguridad. Analiza la siguiente "
        "vulnerabilidad y proporciona una respuesta estructurada "
        "en español.\n\n"
        f"CVE ID: {cve_id}\n\n"
        "Detalles obtenidos de CrowdStrike Spotlight:\n"
        f"{vuln_summary}\n\n"
        "Proporciona:\n"
        "1. Descripción breve del CVE, máximo 3 oraciones.\n"
        "2. Severidad y CVSS si está disponible.\n"
        "3. Impacto potencial en el activo.\n"
        "4. Pasos de remediación concretos y ordenados.\n"
        "5. Referencias útiles.\n\n"
        "Sé conciso y práctico. No inventes datos que no estén "
        "disponibles en la evidencia."
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 1024,
        },
    }

    available_models = get_available_gemini_models(api_key)

    if not available_models:
        return (
            "No fue posible encontrar un modelo Gemini disponible "
            "compatible con generateContent."
        )

    retryable_status_codes = {
        408,
        429,
        500,
        502,
        503,
        504,
    }

    max_attempts_per_model = 3
    last_error = "Error desconocido"

    for model in available_models:
        endpoint = (
            f"{GEMINI_BASE_URL}"
            f"{model}:generateContent"
        )

        print(f"{C.BLUE}[INFO] Probando modelo: {model}{C.RESET}")
        print(f"[DEBUG] Endpoint: {endpoint}")

        for attempt in range(1, max_attempts_per_model + 1):
            try:
                print(
                    f"[INFO] Intento {attempt}/"
                    f"{max_attempts_per_model} con {model}"
                )

                response = requests.post(
                    endpoint,
                    headers={
                        "Content-Type": "application/json"
                    },
                    params={
                        "key": api_key
                    },
                    json=payload,
                    timeout=120,
                )

                print(
                    f"[DEBUG] Modelo={model} "
                    f"HTTP={response.status_code}"
                )

                if response.status_code == 200:
                    response_data = response.json()
                    generated_text = extract_gemini_text(
                        response_data
                    )

                    if generated_text:
                        print(
                            f"{C.GREEN}[INFO] Análisis generado "
                            f"con {model}.{C.RESET}"
                        )
                        return generated_text

                    last_error = (
                        f"El modelo {model} devolvió HTTP 200, "
                        "pero no incluyó texto en candidates."
                    )
                    print(
                        f"{C.YELLOW}[WARN] "
                        f"{last_error}{C.RESET}"
                    )
                    break

                last_error = response.text

                if (
                    response.status_code
                    in retryable_status_codes
                ):
                    if attempt < max_attempts_per_model:
                        base_delay = 2 ** (attempt - 1)
                        jitter = random.uniform(0.5, 1.5)
                        wait_seconds = base_delay + jitter

                        print(
                            f"{C.YELLOW}[WARN] Error transitorio "
                            f"HTTP {response.status_code} con "
                            f"{model}.{C.RESET}"
                        )
                        print(
                            f"[INFO] Nuevo intento después de "
                            f"{wait_seconds:.1f} segundos."
                        )

                        time.sleep(wait_seconds)
                        continue

                    print(
                        f"{C.YELLOW}[WARN] Se agotaron los "
                        f"reintentos para {model}. Se probará "
                        f"otro modelo.{C.RESET}"
                    )
                    break

                print(
                    f"{C.RED}[ERROR] Gemini respondió HTTP "
                    f"{response.status_code} con {model}.{C.RESET}"
                )
                print(response.text)

                # 400, 401 y 403 normalmente no se solucionan
                # intentando exactamente la misma solicitud.
                if response.status_code in {400, 401, 403}:
                    return (
                        f"Gemini rechazó la solicitud. "
                        f"HTTP {response.status_code}:\n"
                        f"{response.text}"
                    )

                break

            except requests.Timeout:
                last_error = (
                    f"Timeout al consultar el modelo {model}"
                )

                if attempt < max_attempts_per_model:
                    base_delay = 2 ** (attempt - 1)
                    jitter = random.uniform(0.5, 1.5)
                    wait_seconds = base_delay + jitter

                    print(
                        f"{C.YELLOW}[WARN] Timeout con {model}. "
                        f"Reintentando después de "
                        f"{wait_seconds:.1f} segundos.{C.RESET}"
                    )

                    time.sleep(wait_seconds)
                    continue

                break

            except requests.RequestException as error:
                last_error = (
                    f"Error de conexión con {model}: {error}"
                )
                print(
                    f"{C.YELLOW}[WARN] "
                    f"{last_error}{C.RESET}"
                )
                break

            except (ValueError, KeyError, TypeError) as error:
                last_error = (
                    f"Respuesta no válida de {model}: {error}"
                )
                print(
                    f"{C.YELLOW}[WARN] "
                    f"{last_error}{C.RESET}"
                )
                break

    return (
        "No fue posible obtener el análisis de Gemini después "
        "de probar los modelos disponibles.\n"
        f"Último error: {last_error}"
    )
def normalize_excel_value(value) -> str:
    """
    Normaliza valores leídos desde Excel para poder compararlos
    correctamente con los resultados obtenidos de CrowdStrike.
    """
    if value is None:
        return ""

    text = str(value).strip()

    # Evita que una IP o identificador termine como 10.1.1.1.0
    # en ciertos casos de lectura desde Excel.
    if text.endswith(".0"):
        possible_number = text[:-2]

        if possible_number.isdigit():
            text = possible_number

    return text.upper()


def connect_google_sheet(
    spreadsheet_url: str,
    worksheet_name: str,
    credentials_file: str,
):
    """
    Se autentica mediante una cuenta de servicio y abre
    un Google Sheet y una pestaña específica.
    """

    if not credentials_file:
        raise ValueError(
            "No se configuró GOOGLE_SERVICE_ACCOUNT_FILE."
        )

    if os.path.isdir(credentials_file):
        credentials_file = os.path.join(
            credentials_file,
            "google-service-account.json",
        )

    if not os.path.isfile(credentials_file):
        raise FileNotFoundError(
            "No se encontró el archivo de credenciales: "
            f"{credentials_file}"
        )

    if not spreadsheet_url:
        raise ValueError(
            "No se configuró GSHEET_URL."
        )

    if not worksheet_name:
        raise ValueError(
            "No se especificó el nombre de la pestaña."
        )

    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
    ]

    credentials = Credentials.from_service_account_file(
        credentials_file,
        scopes=scopes,
    )

    client = gspread.authorize(credentials)

    try:
        spreadsheet = client.open_by_url(spreadsheet_url)
    except gspread.exceptions.APIError as error:
        if getattr(error, "response", None) is not None:
            status_code = getattr(error.response, "status_code", None)
            body = getattr(error.response, "text", "")
        else:
            status_code = None
            body = str(error)

        if status_code == 403 or "does not have permission" in body:
            raise PermissionError(
                "La cuenta de servicio no tiene acceso al Google Sheet. "
                "Comparte el archivo con la cuenta de servicio: "
                f"{credentials.service_account_email}"
            ) from error

        raise

    try:
        worksheet = spreadsheet.worksheet(worksheet_name)
    except gspread.exceptions.WorksheetNotFound as error:
        available_worksheets = [
            item.title
            for item in spreadsheet.worksheets()
        ]
        raise ValueError(
            f"No se encontró la pestaña '{worksheet_name}'. "
            f"Pestañas disponibles: {available_worksheets}"
        ) from error

    return spreadsheet, worksheet


def load_google_sheet(worksheet) -> pd.DataFrame:
    """
    Lee los datos de Google Sheets y devuelve un DataFrame.

    La primera fila se utiliza como encabezado.
    """

    values = worksheet.get_all_values()

    if not values:
        raise ValueError(
            "La pestaña de Google Sheets está vacía."
        )

    raw_headers = [
        str(value).strip()
        for value in values[0]
    ]

    if not any(raw_headers):
        raise ValueError(
            "La primera fila no contiene encabezados."
        )

    headers = []
    used_headers = set()

    for index, header in enumerate(raw_headers, start=1):
        final_header = str(header).strip() or f"COLUMNA_{index}"
        original_header = final_header
        suffix = 2

        while final_header in used_headers:
            final_header = f"{original_header}_{suffix}"
            suffix += 1

        headers.append(final_header)
        used_headers.add(final_header)

    normalized_rows = []

    for row in values[1:]:
        adjusted_row = list(row[:len(headers)])

        if len(adjusted_row) < len(headers):
            missing_values = len(headers) - len(adjusted_row)
            adjusted_row.extend([""] * missing_values)

        normalized_rows.append(adjusted_row)

    df = pd.DataFrame(
        normalized_rows,
        columns=headers,
    )

    # Guardar la fila real de Google Sheets.
    # La fila 1 corresponde a los encabezados.
    df["GSHEET_ROW"] = list(range(2, len(df) + 2))

    df.columns = [
        str(column).strip().upper()
        for column in df.columns
    ]

    mapping = {}

    for column in df.columns:
        normalized_column = normalize_excel_value(column)

        if normalized_column in (
            "CVE_UNICO",
            "CVE_ID",
            "CVE",
        ):
            mapping[column] = "CVE_ID"
        elif normalized_column in (
            "IP",
            "IP_ADDRESS",
            "IPADDRESS",
        ):
            mapping[column] = "IP"
        elif normalized_column in (
            "HOSTNAME",
            "HOST",
            "HOST_NAME",
        ):
            mapping[column] = "HOSTNAME"

    df.rename(
        columns=mapping,
        inplace=True,
    )

    required_columns = {
        "CVE_ID",
        "IP",
        "HOSTNAME",
    }
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            "Faltan columnas requeridas en Google Sheets: "
            f"{sorted(missing_columns)}"
        )

    # Convertir valores nulos a texto vacío.
    for column in (
        "CVE_ID",
        "IP",
        "HOSTNAME",
    ):
        df[column] = (
            df[column]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    # Ignorar las filas completamente vacías.
    df = df[
        ~(
            df["CVE_ID"].eq("")
            & df["IP"].eq("")
            & df["HOSTNAME"].eq("")
        )
    ].copy()

    # CrowdStrike necesita los tres valores.
    invalid_rows = df[
        df["CVE_ID"].eq("")
        | df["IP"].eq("")
        | df["HOSTNAME"].eq("")
    ]

    if not invalid_rows.empty:
        invalid_gsheet_rows = (
            invalid_rows["GSHEET_ROW"]
            .astype(int)
            .tolist()
        )

        raise ValueError(
            "Existen filas incompletas en Google Sheets. "
            "Cada registro necesita CVE, IP y Hostname. "
            f"Filas: {invalid_gsheet_rows}"
        )

    df.reset_index(
        drop=True,
        inplace=True,
    )

    return df


def update_google_sheet_results(
    worksheet,
    results: list[dict],
):
    """
    Crea o reutiliza la columna Resultado y actualiza
    las filas procesadas en Google Sheets.
    """

    header_values = worksheet.row_values(1)
    normalized_headers = [
        normalize_excel_value(value)
        for value in header_values
    ]

    if "RESULTADO" in normalized_headers:
        result_column = normalized_headers.index("RESULTADO") + 1
    else:
        result_column = len(header_values) + 1
        worksheet.update_cell(1, result_column, "Resultado")

    header_address = rowcol_to_a1(1, result_column)
    worksheet.format(
        header_address,
        {
            "textFormat": {"bold": True},
            "horizontalAlignment": "CENTER",
            "verticalAlignment": "MIDDLE",
        },
    )

    if not results:
        print(
            f"{C.YELLOW}[WARN] No hay resultados "
            f"para actualizar en Google Sheets."
            f"{C.RESET}"
        )
        return

    for result in results:
        row_number = result.get("gsheet_row")

        if row_number is None:
            continue

        if result.get("found", False):
            result_text = "VULNERABLE, encontrado en CrowdStrike"
        else:
            result_text = "NO ENCONTRADO COMO VULNERABLE ACTIVO"

        worksheet.update_cell(
            int(row_number),
            result_column,
            result_text,
        )

    result_column_letter = rowcol_to_a1(1, result_column).replace("1", "")
    worksheet.format(
        f"{result_column_letter}2:{result_column_letter}{worksheet.row_count}",
        {
            "wrapStrategy": "WRAP",
            "verticalAlignment": "MIDDLE",
        },
    )

    print()
    print(
        f"{C.GREEN}✓ Google Sheets actualizado."
        f"{C.RESET}"
    )
    print(
        f"  Pestaña           : {worksheet.title}"
    )
    print(
        f"  Columna Resultado : {result_column_letter}"
    )
    print()

# ─────────────────────────────────────────────
# FORMATEAR RESULTADO EN CONSOLA
# ─────────────────────────────────────────────

def print_result(record: dict):
    host = record["hostname"]
    ip = record["ip"]
    cve_id = record["cve_id"]
    found = record["found"]
    vulns = record["vulnerabilities"]

    sep = "─" * 100

    print(f"\n{C.BOLD}{sep}{C.RESET}")
    print(f"  {C.BOLD}Host                   :{C.RESET} {host}")
    print(f"  {C.BOLD}IP                     :{C.RESET} {ip}")
    print(f"  {C.BOLD}CVE consultado          :{C.RESET} {cve_id}")

    if not found:
        print(
            f"  {C.BOLD}Resultado              :{C.RESET} "
            f"{C.GREEN}✅ NO ENCONTRADO COMO "
            f"VULNERABLE ACTIVO{C.RESET}"
        )
    else:
        print(
            f"  {C.BOLD}Resultado              :{C.RESET} "
            f"{C.RED}⚠️ VULNERABLE, encontrado "
            f"en CrowdStrike{C.RESET}"
        )

        for index, vulnerability in enumerate(vulns, 1):
            fields = extract_vulnerability_fields(
                vulnerability,
                fallback_cve=cve_id,
            )

            print(
                f"\n  {C.CYAN}{C.BOLD}"
                f"Vulnerabilidad #{index}"
                f"{C.RESET}"
            )
            print(
                f"    Vulnerability ID            : "
                f"{fields['vulnerability_id']}"
            )
            print(
                f"    ExPRT rating                : "
                f"{fields['exprt_rating']}"
            )
            print(
                f"    CVSS severity               : "
                f"{fields['cvss_severity']}"
            )
            print(
                f"    CVSS score                  : "
                f"{fields['cvss_score']}"
            )
            print(
                f"    Exploit status              : "
                f"{fields['exploit_status']}"
            )
            print(
                f"    Remediation                 : "
                f"{fields['remediation']}"
            )
            print(
                f"    Vulnerable product versions : "
                f"{fields['vulnerable_product_versions']}"
            )
            print(
                f"    Status                      : "
                f"{fields['status']}"
            )
            print(
                f"    Days open                   : "
                f"{fields['days_open']}"
            )

    print(f"{C.BOLD}{sep}{C.RESET}")


# ─────────────────────────────────────────────
# GUARDAR REPORTE EXCEL
# ─────────────────────────────────────────────
def save_report(results: list[dict], output_path: str):
    rows = []

    for result in results:
        vulnerabilities = result.get(
            "vulnerabilities",
            [],
        )

        if vulnerabilities:
            for vulnerability in vulnerabilities:
                fields = extract_vulnerability_fields(
                    vulnerability,
                    fallback_cve=result["cve_id"],
                )

                rows.append({
                    "Hostname":
                        result["hostname"],
                    "IP":
                        result["ip"],
                    "CVE_Consultado":
                        result["cve_id"],
                    "Vulnerability_ID":
                        fields["vulnerability_id"],
                    "ExPRT_Rating":
                        fields["exprt_rating"],
                    "CVSS_Severity":
                        fields["cvss_severity"],
                    "CVSS_Score":
                        fields["cvss_score"],
                    "Exploit_Status":
                        fields["exploit_status"],
                    "Remediation":
                        fields["remediation"],
                    "Vulnerable_Product_Versions":
                        fields[
                            "vulnerable_product_versions"
                        ],
                    "Status":
                        fields["status"],
                    "Days_Open":
                        fields["days_open"],
                    "Resultado_Analisis":
                        "VULNERABLE",
                    "Timestamp":
                        result.get("timestamp", ""),
                })

        else:
            rows.append({
                "Hostname":
                    result["hostname"],
                "IP":
                    result["ip"],
                "CVE_Consultado":
                    result["cve_id"],
                "Vulnerability_ID":
                    result["cve_id"],
                "ExPRT_Rating":
                    "N/A",
                "CVSS_Severity":
                    "N/A",
                "CVSS_Score":
                    "N/A",
                "Exploit_Status":
                    "N/A",
                "Remediation":
                    "N/A",
                "Vulnerable_Product_Versions":
                    "N/A",
                "Status":
                    "NOT_FOUND",
                "Days_Open":
                    "N/A",
                "Resultado_Analisis":
                    "NO ENCONTRADO COMO VULNERABLE ACTIVO",
                "Timestamp":
                    result.get("timestamp", ""),
            })

    report_df = pd.DataFrame(rows)

    if output_path.lower().endswith(".xlsx"):
        report_df.to_excel(
            output_path,
            index=False,
            engine="openpyxl",
        )


        workbook = load_workbook(output_path)
        worksheet = workbook.active
        worksheet.title = "Resultados CVE"

        for column_cells in worksheet.columns:
            max_length = 0
            column_letter = column_cells[0].column_letter

            for cell in column_cells:
                cell_value = (
                    ""
                    if cell.value is None
                    else str(cell.value)
                )

                max_length = max(
                    max_length,
                    len(cell_value),
                )

            worksheet.column_dimensions[
                column_letter
            ].width = min(
                max(max_length + 2, 12),
                60,
            )

        worksheet.freeze_panes = "A2"
        worksheet.auto_filter.ref = worksheet.dimensions

        workbook.save(output_path)

    else:
        report_df.to_csv(
            output_path,
            index=False,
            encoding="utf-8-sig",
        )

    print(
        f"\n{C.GREEN}📄 Reporte guardado en: "
        f"{output_path}{C.RESET}"
    )

# ─────────────────────────────────────────────
# ARGUMENTOS CLI
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "CVE Analyzer: CrowdStrike FalconPy "
            "+ Google Sheets"
        )
    )

    parser.add_argument(
        "--gsheet-url",
        default=GSHEET_URL,
        help=(
            "URL completa del Google Sheet "
            "(o variable GSHEET_URL)"
        ),
    )

    parser.add_argument(
        "--worksheet",
        default=GSHEET_WORKSHEET,
        help=(
            "Nombre de la pestaña de Google Sheets "
            "(o variable GSHEET_WORKSHEET)"
        ),
    )

    parser.add_argument(
        "--google-credentials",
        default=GOOGLE_SERVICE_ACCOUNT_FILE,
        help=(
            "Ruta al JSON de la cuenta de servicio "
            "(o variable GOOGLE_SERVICE_ACCOUNT_FILE)"
        ),
    )

    parser.add_argument(
        "--cs-client-id",
        default=CROWDSTRIKE_CLIENT_ID,
        help=(
            "CrowdStrike Client ID "
            "(o variable CS_CLIENT_ID)"
        ),
    )

    parser.add_argument(
        "--cs-client-secret",
        default=CROWDSTRIKE_CLIENT_SECRET,
        help=(
            "CrowdStrike Client Secret "
            "(o variable CS_CLIENT_SECRET)"
        ),
    )

    parser.add_argument(
        "--cs-base-url",
        default=CROWDSTRIKE_BASE_URL,
        help=(
            "CrowdStrike base URL. "
            "Ejemplo: api.crowdstrike.com"
        ),
    )

    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help=(
            "Reporte técnico local .xlsx o .csv. "
            "Es opcional."
        ),
    )

    parser.add_argument(
        "--no-local-report",
        action="store_true",
        help=(
            "No generar el reporte técnico local."
        ),
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    banner()
    args = parse_args()

    # Validar credenciales CrowdStrike desde variables de entorno
    if not args.cs_client_id or not args.cs_client_secret:
        print(f"{C.RED}ERROR: Faltan credenciales de CrowdStrike.{C.RESET}")
        print()
        print("  Define las siguientes variables de entorno antes de ejecutar:")
        print()
        print("  Windows CMD:")
        print("    set CS_CLIENT_ID=tu_client_id")
        print("    set CS_CLIENT_SECRET=tu_client_secret")
        print("    set GEMINI_API_KEY=tu_gemini_key")
        print()
        print("  Windows PowerShell:")
        print('    $env:CS_CLIENT_ID="tu_client_id"')
        print('    $env:CS_CLIENT_SECRET="tu_client_secret"')
        print('    $env:GEMINI_API_KEY="tu_gemini_key"')
        print()
        print("  Mac/Linux:")
        print("    export CS_CLIENT_ID=tu_client_id")
        print("    export CS_CLIENT_SECRET=tu_client_secret")
        print("    export GEMINI_API_KEY=tu_gemini_key")
        print()
        print("  Donde obtener las credenciales:")
        print("    CrowdStrike : Falcon Console > Support > API Clients & Keys")
        print("    Gemini      : Google AI Studio > API Keys")
        sys.exit(1)

    # ── Conectar y leer Google Sheets ────────────
    print(
        f"{C.CYAN}📄 Conectando con Google Sheets..."
        f"{C.RESET}"
    )

    try:
        spreadsheet, worksheet = (
            connect_google_sheet(
                spreadsheet_url=args.gsheet_url,
                worksheet_name=args.worksheet,
                credentials_file=args.google_credentials,
            )
        )

        df = load_google_sheet(
            worksheet
        )

    except gspread.exceptions.APIError as error:
        print(
            f"{C.RED}ERROR de Google Sheets API: "
            f"{error}{C.RESET}"
        )
        sys.exit(1)

    except Exception as error:
        print(
            f"{C.RED}ERROR al leer Google Sheets: "
            f"{error}{C.RESET}"
        )
        sys.exit(1)

    print(
        f"  {C.GREEN}✓ Documento:"
        f"{C.RESET} {spreadsheet.title}"
    )

    print(
        f"  {C.GREEN}✓ Pestaña:"
        f"{C.RESET} {worksheet.title}"
    )

    print(
        f"  {C.GREEN}✓ Registros cargados:"
        f"{C.RESET} {len(df)}\n"
    )

    # ── Inicializar FalconPy ──────────────────
    cs = CrowdStrikeClient(args.cs_client_id, args.cs_client_secret, args.cs_base_url)

    print(f"{C.CYAN}🔐 Autenticando con CrowdStrike (FalconPy)...{C.RESET}")
    try:
        cs.authenticate()
        print(f"  {C.GREEN}✓ Autenticación exitosa{C.RESET}\n")
    except Exception as e:
        print(f"{C.RED}ERROR: {e}{C.RESET}")
        sys.exit(1)

    # ── Procesar cada activo ──────────────────
    results = []
    total   = len(df)

    for position, row in df.iterrows():
        cve_id = str(
            row["CVE_ID"]
        ).strip()

        ip = str(
            row["IP"]
        ).strip()

        hostname = str(
            row["HOSTNAME"]
        ).strip()

        gsheet_row = int(
            row["GSHEET_ROW"]
        )

        print(
            f"{C.BOLD}"
            f"[{position + 1}/{total}]"
            f"{C.RESET} "
            f"{hostname} ({ip}) — {cve_id} ..."
        )

        vulns = cs.get_vulnerabilities_by_cve(cve_id, hostname, ip)

        active_vulns = []

        for v in vulns:

            status = str(
                v.get("status", "")
            ).lower()

            normalized_status = (
                status
                .replace("-", "_")
                .replace(" ", "_")
            )

            if normalized_status in (
                "open",
                "reopened",
                "reopen",
                "new",
                "in_progress",
                "pending",
            ):
                active_vulns.append(v)

        vulns = active_vulns
        found = len(vulns) > 0

        record = {
        "hostname": hostname,
        "ip": ip,
        "cve_id": cve_id,
        "found": found,
        "vulnerabilities": vulns,
        "timestamp": datetime.now(
            UTC
        ).isoformat(),
        "gsheet_row": gsheet_row,
    }
        results.append(record)
        print_result(record)

    # ── Resumen final ─────────────────────────
    vulnerable   = sum(1 for r in results if r["found"])
    no_vulnerables_activos = total - vulnerable

    print(f"\n{C.BOLD}{'═' * 60}")
    print(f"  RESUMEN FINAL")
    print(f"{'═' * 60}{C.RESET}")
    print(f"  Total activos analizados  : {total}")
    print(f"  {C.RED}Vulnerables               : {vulnerable}{C.RESET}")
    print(f"  {C.GREEN}No vulnerables activos : {no_vulnerables_activos}{C.RESET}")
    print(f"{'═' * 60}\n")

    # ── Actualizar Google Sheets ─────────────────
    print(
        f"{C.CYAN}📝 Actualizando Google Sheets..."
        f"{C.RESET}"
    )

    try:
        update_google_sheet_results(
            worksheet=worksheet,
            results=results,
        )

    except gspread.exceptions.APIError as error:
        print(
            f"{C.RED}ERROR de Google Sheets API "
            f"al escribir resultados: "
            f"{error}{C.RESET}"
        )
        sys.exit(1)

    except Exception as error:
        print(
            f"{C.RED}ERROR al actualizar "
            f"Google Sheets: {error}{C.RESET}"
        )
        sys.exit(1)

    # ── Guardar reporte ───────────────────────
    # out = args.output or f"reporte_cve_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    # save_report(results, out)

    # ── Guardar reporte técnico detallado ─────────────────────
    if not args.no_local_report:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        out = (
            args.output
            or f"reporte_cve_{timestamp}.xlsx"
        )

        save_report(
            results,
            out,
        )


if __name__ == "__main__":
    main()