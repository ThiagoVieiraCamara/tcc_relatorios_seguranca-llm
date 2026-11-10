"""Scanner Nmap (descoberta de servicos + scripts NSE)."""
import subprocess
import re
from scanners.base_scanner import BaseScanner
from config import NMAP_TIMEOUT


class NmapScanner(BaseScanner):
    nome = "Nmap"

    def __init__(self, alvo, profundo=False):
        super().__init__(alvo)
        self.profundo = profundo

    def executar(self):
        print(f"[*] Iniciando scan Nmap em {self.alvo}")

        cmd = self._montar_comando()
        output = ""

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT
            )
            output = r.stdout + ("\n--- STDERR ---\n" + r.stderr if r.stderr else "")
        except FileNotFoundError:
            print("[!] nmap nao instalado.")
            self.registrar_log("nmap", "ERRO: nmap nao instalado no sistema.")
            return self.vulnerabilidades
        except subprocess.TimeoutExpired as e:
            print("[!] Nmap excedeu o tempo limite.")
            output = (e.stdout or "") + "\n--- TIMEOUT ATINGIDO ---"
            self.registrar_log("nmap", output)
            return self.vulnerabilidades

        # Registra log bruto da ferramenta
        self.registrar_log("nmap", "Comando: " + " ".join(cmd) + "\n\n" + output)
        
        self.dados_brutos["raw"] = output

        servicos = self._parse_servicos(output)
        sistema = self._parse_so(output)
        scripts_achados = self._parse_scripts(output)

        self.dados_brutos["servicos"] = servicos
        self.dados_brutos["sistema_operacional"] = sistema
        self.dados_brutos["scripts_achados"] = scripts_achados

        # Servicos inseguros conhecidos
        servicos_inseguros = {
            "telnet": "Alta",
            "ftp": "Media",
            "rsh": "Alta",
            "rlogin": "Alta",
            "tftp": "Media",
        }
        for svc in servicos:
            if svc["servico"] in servicos_inseguros:
                self.add_vuln(
                    tipo=f"Servico inseguro exposto: {svc['servico']}",
                    descricao=(
                        f"Servico {svc['servico']} em texto claro detectado "
                        f"na porta {svc['porta']}. Protocolos legados sem "
                        f"criptografia expoem credenciais e dados em transito."
                    ),
                    severidade=servicos_inseguros[svc["servico"]],
                    categoria="Rede",
                    evidencia=f"{svc['porta']} - {svc['versao']}",
                )

        # Achados dos scripts NSE
        for achado in scripts_achados:
            self.add_vuln(
                tipo=f"NSE: {achado['script']}",
                descricao=achado["mensagem"],
                severidade="Media",
                categoria="Rede",
                evidencia=achado.get("evidencia", ""),
            )

        return self.vulnerabilidades

    def _montar_comando(self):
        if self.profundo:
            return [
                "nmap", "-sV", "-sC", "-Pn", "-T4", "--open",
                "-p-",
                "--script", "vuln,mqtt-*,http-*,ssl-*",
                self.alvo
            ]
        return [
            "nmap", "-sV", "-sC", "-Pn", "-T4", "--open",
            "-p", "1-10000",
            self.alvo
        ]

    @staticmethod
    def _parse_servicos(output):
        # CORRIGIDO: aceita TCP e UDP
        linhas = re.findall(r"(\d+/(?:tcp|udp)\s+open\s+[\w\-]+.*)", output)
        servicos = []
        for linha in linhas:
            partes = linha.split()
            if len(partes) >= 3:
                servicos.append({
                    "porta": partes[0],
                    "servico": partes[2],
                    "versao": " ".join(partes[3:]) if len(partes) > 3 else "",
                })
        return servicos

    @staticmethod
    def _parse_so(output):
        match = re.search(r"OS details: (.+)", output)
        if match:
            return match.group(1).strip()
        match = re.search(r"Running: (.+)", output)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _parse_scripts(output):
        """Extrai achados de scripts NSE, com filtro mais rigoroso."""
        achados = []
        # CORRIGIDO: filtra termos genericos que nao sao achados reais
        ruido = {
            "State", "Reason", "Service Info", "Device", "Running",
            "OS details", "OS CPE", "Aggressive OS guesses",
            "Network Distance", "TCP Sequence Prediction",
            "IP ID Sequence Generation",
        }
        
        padrao = re.compile(r"\|[\s_]+([\w\-]+):\s*(.+)")
        for match in padrao.finditer(output):
            script_nome, mensagem = match.groups()
            mensagem = mensagem.strip()
            
            # Filtros
            if not mensagem or mensagem.startswith("ERROR"):
                continue
            if script_nome in ruido:
                continue
            # Scripts NSE legitimos usam hyphen (http-title, ssh-hostkey)
            if "-" not in script_nome and "_" not in script_nome:
                continue
            
            achados.append({
                "script": script_nome,
                "mensagem": mensagem[:200],
            })
        return achados
    @staticmethod
    def _parse_so(output):
        match = re.search(r"OS details: (.+)", output)
        if match:
            return match.group(1).strip()
        match = re.search(r"Running: (.+)", output)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _parse_scripts(output):
        """Extrai achados de scripts NSE."""
        achados = []
        # Scripts NSE aparecem como "| script-name: mensagem"
        padrao = re.compile(r"\|[\s_]+([\w\-]+):\s*(.+)")
        for match in padrao.finditer(output):
            script_nome, mensagem = match.groups()
            # Filtra ruido obvio (tabelas vazias, etc)
            if mensagem.strip() and not mensagem.strip().startswith("ERROR"):
                achados.append({
                    "script": script_nome,
                    "mensagem": mensagem.strip()[:200],
                })
        return achados
