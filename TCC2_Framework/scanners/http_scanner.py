"""Scanner de headers e configuracoes de seguranca HTTP."""
import re
import json
import warnings
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from scanners.base_scanner import BaseScanner
from config import HTTP_TIMEOUT


# Suprime warning de TLS nao verificado (intencional em lab)
warnings.simplefilter('ignore', InsecureRequestWarning)


HEADERS_NECESSARIOS = {
    "Content-Security-Policy": {
        "descricao": "Ausencia de CSP (protecao contra XSS e injection)",
        "severidade": "Alta",
    },
    "X-Frame-Options": {
        "descricao": "Ausencia de protecao contra clickjacking",
        "severidade": "Media",
    },
    "Strict-Transport-Security": {
        "descricao": "Ausencia de HSTS (vulneravel a downgrade attack)",
        "severidade": "Media",
    },
    "X-Content-Type-Options": {
        "descricao": "Possivel MIME sniffing",
        "severidade": "Baixa",
    },
    "Referrer-Policy": {
        "descricao": "Ausencia de Referrer-Policy",
        "severidade": "Baixa",
    },
    "Permissions-Policy": {
        "descricao": "Ausencia de Permissions-Policy (ex-Feature-Policy)",
        "severidade": "Baixa",
    },
}

HEADERS_EXPOSICAO = {
    "Server":              "Versao do servidor web",
    "X-Powered-By":        "Tecnologia/framework backend",
    "X-AspNet-Version":    "Versao do ASP.NET",
    "X-AspNetMvc-Version": "Versao do ASP.NET MVC",
    "X-Generator":         "Sistema gerador",
}


class HTTPScanner(BaseScanner):
    nome = "HTTP"

    def executar(self):
        print(f"[*] Iniciando scan HTTP em {self.alvo}")
        try:
            response = requests.get(self.alvo, timeout=HTTP_TIMEOUT, verify=False)
        except Exception as e:
            erro = f"Falha ao acessar {self.alvo}: {e}"
            print(f"[!] {erro}")
            self.dados_brutos["erro"] = str(e)
            self.registrar_log("requests_get", f"ERRO: {erro}")
            return self.vulnerabilidades

        headers = response.headers
        self.dados_brutos = {
            "status_code": response.status_code,
            "headers": dict(headers),
        }

        # Registra log da requisicao GET principal
        log_get = self._formatar_log_response("GET", self.alvo, response)
        self.registrar_log("requests_get", log_get)

        self._verificar_headers_ausentes(headers)
        self._validar_valores_headers(headers)
        self._analisar_cookies(response)
        self._verificar_exposicao(headers)
        self._analisar_cors(headers)
        self._analisar_metodos()

        return self.vulnerabilidades

    def _formatar_log_response(self, metodo, url, response):
        """Formata uma resposta HTTP de forma legivel para log."""
        linhas = [
            f"--- Requisicao: {metodo} {url} ---",
            f"Status: {response.status_code} {response.reason}",
            "",
            "Headers de resposta:",
        ]
        for k, v in response.headers.items():
            linhas.append(f"  {k}: {v}")
        return "\n".join(linhas)

    def _verificar_headers_ausentes(self, headers):
        for header, info in HEADERS_NECESSARIOS.items():
            if header not in headers:
                self.add_vuln(
                    tipo=f"Header ausente: {header}",
                    descricao=info["descricao"],
                    severidade=info["severidade"],
                    categoria="Web/API",
                )

    def _validar_valores_headers(self, headers):
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            problemas = []
            if "unsafe-inline" in csp:
                problemas.append("permite 'unsafe-inline'")
            if "unsafe-eval" in csp:
                problemas.append("permite 'unsafe-eval'")
            if "default-src *" in csp:
                problemas.append("usa default-src com wildcard")

            if problemas:
                self.add_vuln(
                    tipo="CSP mal configurado",
                    descricao=f"CSP presente mas com diretivas permissivas: {', '.join(problemas)}",
                    severidade="Media",
                    categoria="Web/API",
                    evidencia=csp[:300],
                )

        if "Strict-Transport-Security" in headers:
            hsts = headers["Strict-Transport-Security"]
            match = re.search(r"max-age=(\d+)", hsts)
            if match:
                max_age = int(match.group(1))
                if max_age == 0:
                    self.add_vuln(
                        tipo="HSTS desabilitado",
                        descricao="HSTS presente mas com max-age=0",
                        severidade="Media",
                        categoria="Transporte",
                        evidencia=hsts,
                    )
                elif max_age < 31536000:
                    self.add_vuln(
                        tipo="HSTS com max-age curto",
                        descricao=f"HSTS com max-age={max_age}s (recomendado >= 1 ano)",
                        severidade="Baixa",
                        categoria="Transporte",
                        evidencia=hsts,
                    )

        if "X-Frame-Options" in headers:
            valor = headers["X-Frame-Options"].upper()
            if valor not in ("DENY", "SAMEORIGIN") and not valor.startswith("ALLOW-FROM"):
                self.add_vuln(
                    tipo="X-Frame-Options com valor invalido",
                    descricao=f"Valor incomum/invalido: {valor}",
                    severidade="Media",
                    categoria="Web/API",
                    evidencia=valor,
                )

    def _analisar_cookies(self, response):
        """
        CORRIGIDO: usa response.headers diretamente sem depender de .raw.headers.
        O header Set-Cookie pode aparecer multiplas vezes; em requests, vem
        concatenado com virgula em response.headers ou separado em response.raw.
        """
        # Tenta a forma mais robusta primeiro
        try:
            # urllib3 retorna uma lista quando ha multiplos Set-Cookie
            raw_headers = response.raw.headers
            if hasattr(raw_headers, "getlist"):
                set_cookies = raw_headers.getlist("Set-Cookie")
            elif hasattr(raw_headers, "get_all"):
                set_cookies = raw_headers.get_all("Set-Cookie") or []
            else:
                set_cookies = []
        except (AttributeError, Exception):
            set_cookies = []
        
        # Fallback: pega do header normal e divide por virgula 
        # (cuidado: virgula pode aparecer dentro de Expires=...)
        if not set_cookies:
            raw = response.headers.get("Set-Cookie", "")
            if raw:
                # Split simples; suficiente pra detectar flags
                set_cookies = [raw]

        for cookie_str in set_cookies:
            if not cookie_str or not cookie_str.strip():
                continue

            nome = cookie_str.split("=")[0].strip()
            cookie_lower = cookie_str.lower()

            if "secure" not in cookie_lower:
                self.add_vuln(
                    tipo=f"Cookie sem flag Secure: {nome}",
                    descricao="Cookie pode trafegar em HTTP nao criptografado",
                    severidade="Media",
                    categoria="Web/API",
                    evidencia=cookie_str[:200],
                )

            if "httponly" not in cookie_lower:
                self.add_vuln(
                    tipo=f"Cookie sem HttpOnly: {nome}",
                    descricao="Cookie acessivel via JavaScript (XSS pode roubar)",
                    severidade="Media",
                    categoria="Web/API",
                    evidencia=cookie_str[:200],
                )

            if "samesite" not in cookie_lower:
                self.add_vuln(
                    tipo=f"Cookie sem SameSite: {nome}",
                    descricao="Cookie sem protecao SameSite (vulneravel a CSRF)",
                    severidade="Baixa",
                    categoria="Web/API",
                    evidencia=cookie_str[:200],
                )

    def _verificar_exposicao(self, headers):
        for header, descricao in HEADERS_EXPOSICAO.items():
            if header in headers:
                self.add_vuln(
                    tipo=f"Exposicao de banner: {header}",
                    descricao=f"{descricao}: {headers[header]}",
                    severidade="Informativa",
                    categoria="Web/API",
                    evidencia=f"{header}: {headers[header]}",
                )

    def _analisar_cors(self, headers):
        acao = headers.get("Access-Control-Allow-Origin", "")
        creds = headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*" and creds == "true":
            self.add_vuln(
                tipo="CORS perigoso",
                descricao="'Allow-Origin: *' + 'Allow-Credentials: true'",
                severidade="Alta",
                categoria="Web/API",
            )
        elif acao == "*":
            self.add_vuln(
                tipo="CORS permissivo",
                descricao="'Allow-Origin: *' permite acesso de qualquer origem",
                severidade="Media",
                categoria="Web/API",
            )

    def _analisar_metodos(self):
        try:
            r = requests.options(self.alvo, timeout=HTTP_TIMEOUT, verify=False)
            allow = (r.headers.get("Allow", "") + "," +
                     r.headers.get("Access-Control-Allow-Methods", "")).upper()
            
            # Log da requisicao OPTIONS
            log_options = self._formatar_log_response("OPTIONS", self.alvo, r)
            self.registrar_log("requests_options", log_options)

            metodos_perigosos = {
                "TRACE":  ("Media", "Vulneravel a Cross-Site Tracing"),
                "PUT":    ("Media", "Pode permitir upload arbitrario"),
                "DELETE": ("Media", "Pode permitir remocao de recursos"),
            }

            for metodo, (sev, desc) in metodos_perigosos.items():
                if metodo in allow:
                    self.add_vuln(
                        tipo=f"Metodo HTTP habilitado: {metodo}",
                        descricao=desc,
                        severidade=sev,
                        categoria="Web/API",
                        evidencia=f"Allow: {allow[:200]}",
                    )
        except Exception as e:
            self.registrar_log("requests_options", f"ERRO: {e}")
