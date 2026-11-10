"""Scanner XSS usando Katana (descoberta) + Dalfox (teste)."""
import subprocess
import json
import re
import requests
from urllib.parse import urljoin, urlparse
from scanners.base_scanner import BaseScanner
from config import XSS_TIMEOUT, HTTP_TIMEOUT


ENDPOINTS_COMUNS = [
    "/", "/search", "/api", "/api/v1", "/rest", "/login",
    "/users", "/admin", "/products", "/items", "/posts",
    "/comments", "/profile", "/dashboard",
]

PARAMETROS_COMUNS = ["q", "query", "search", "id", "page", "name", "user"]


class XSSScanner(BaseScanner):
    nome = "XSS"

    def __init__(self, alvo, max_endpoints=20):
        super().__init__(alvo)
        self.max_endpoints = max_endpoints

    def executar(self):
        print(f"[*] Iniciando scan XSS em {self.alvo}")

        endpoints = self._descobrir_endpoints_katana()
        if not endpoints:
            print("[!] Katana nao retornou resultados, usando fallback")
            endpoints = self._descobrir_endpoints_fallback()

        print(f"[+] {len(endpoints)} endpoint(s) descoberto(s)")
        self.dados_brutos["endpoints_descobertos"] = endpoints

        # Registra a lista de endpoints descobertos no log
        log_endpoints = (
            f"Total descoberto: {len(endpoints)}\n"
            f"Limite testado: {self.max_endpoints}\n\n"
            f"Endpoints:\n" + "\n".join(endpoints)
        )
        self.registrar_log("endpoints_descobertos", log_endpoints)

        for url in endpoints[:self.max_endpoints]:
            self._testar_url(url)

        return self.vulnerabilidades

    def _descobrir_endpoints_katana(self):
        cmd = [
            "katana",
            "-u", self.alvo,
            "-d", "2",
            "-jc",
            "-silent",
            "-timeout", "10",
        ]

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
        except FileNotFoundError:
            print("[!] katana nao instalado.")
            self.registrar_log("katana", "ERRO: katana nao instalado.")
            return []
        except subprocess.TimeoutExpired:
            print("[!] katana excedeu o tempo limite.")
            self.registrar_log("katana", "ERRO: timeout atingido.")
            return []

        # Registra log do Katana
        log = (
            f"Comando: {' '.join(cmd)}\n\n"
            f"--- STDOUT ---\n{r.stdout}\n"
            f"--- STDERR ---\n{r.stderr}"
        )
        self.registrar_log("katana", log)

        urls = [linha.strip() for linha in r.stdout.splitlines() if linha.strip()]
        return urls

    def _descobrir_endpoints_fallback(self):
        encontrados = set()
        log_linhas = ["--- Fallback Crawler ---"]

        try:
            r = requests.get(self.alvo, timeout=HTTP_TIMEOUT)
            urls_no_html = re.findall(
                r'(?:href|src|action)=["\']([^"\']+)["\']',
                r.text
            )
            log_linhas.append(f"URLs extraidas do HTML: {len(urls_no_html)}")
            for u in urls_no_html:
                full_url = urljoin(self.alvo, u)
                if urlparse(full_url).netloc == urlparse(self.alvo).netloc:
                    encontrados.add(full_url)
        except Exception as e:
            log_linhas.append(f"Erro no crawl HTML: {e}")

        for endpoint in ENDPOINTS_COMUNS:
            url = self.alvo.rstrip("/") + endpoint
            try:
                r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=False)
                if r.status_code != 404:
                    encontrados.add(url)
                    for param in PARAMETROS_COMUNS:
                        encontrados.add(f"{url}?{param}=test")
            except Exception:
                pass
        
        log_linhas.append(f"Total apos probing: {len(encontrados)}")
        self.registrar_log("crawler_fallback", "\n".join(log_linhas))

        return sorted(encontrados)

    def _testar_url(self, url):
        try:
            r = subprocess.run(
                ["dalfox", "url", url, "--format", "json", "--silence"],
                capture_output=True, text=True, timeout=XSS_TIMEOUT
            )
        except FileNotFoundError:
            print("[!] dalfox nao instalado.")
            self.registrar_log("dalfox", "ERRO: dalfox nao instalado.")
            return
        except subprocess.TimeoutExpired:
            self.registrar_log("dalfox", f"TIMEOUT em {url}")
            return

        # Acumula log de cada chamada do Dalfox
        log_chunk = (
            f"\n--- Dalfox em {url} ---\n"
            f"STDOUT: {r.stdout}\n"
            f"STDERR: {r.stderr}\n"
        )
        self.registrar_log("dalfox", log_chunk)

        if not r.stdout.strip():
            return

        for linha in r.stdout.strip().split("\n"):
            try:
                achado = json.loads(linha)
            except json.JSONDecodeError:
                continue

            # CORRIGIDO: usa 'detectado' como fallback explicito
            tipo_achado = achado.get('type') or 'detectado'

            self.add_vuln(
                tipo=f"XSS {tipo_achado}",
                descricao=f"Parametro vulneravel: {achado.get('param', '?')} em {url}",
                severidade="Alta",
                categoria="Web/API",
                evidencia=achado.get('payload', '')[:500],
            )
