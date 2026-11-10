"""Configurações centrais do framework."""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Paths
BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Gemini
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL = "gemini-2.5-flash-lite"

# Timeouts (segundos)
HTTP_TIMEOUT = 5
MQTT_TIMEOUT = 5
NMAP_TIMEOUT = 120
XSS_TIMEOUT = 300

# Severidades padronizadas
SEVERIDADES = ("Critica", "Alta", "Media", "Baixa", "Informativa")
