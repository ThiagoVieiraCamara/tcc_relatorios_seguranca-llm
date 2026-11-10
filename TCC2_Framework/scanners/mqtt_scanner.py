"""Scanner de vulnerabilidades em brokers MQTT."""
import subprocess
from scanners.base_scanner import BaseScanner
from config import MQTT_TIMEOUT


class MQTTScanner(BaseScanner):
    nome = "MQTT"

    def __init__(self, host: str = "localhost", port: str = "1883"):
        super().__init__(alvo=f"{host}:{port}")
        self.host = host
        self.port = port
        self._sub_result = None

    def _sub_anonimo(self, qtd: int = 10):
        if self._sub_result is not None:
            return self._sub_result
        try:
            r = subprocess.run(
                ["mosquitto_sub", "-h", self.host, "-p", self.port,
                 "-t", "#", "-C", str(qtd)],
                capture_output=True, text=True, timeout=MQTT_TIMEOUT
            )
            # Registra log da execucao do mosquitto_sub
            log = (
                f"Comando: mosquitto_sub -h {self.host} -p {self.port} -t # -C {qtd}\n"
                f"Return code: {r.returncode}\n"
                f"--- STDOUT ---\n{r.stdout}\n"
                f"--- STDERR ---\n{r.stderr}"
            )
            self.registrar_log("mosquitto_sub", log)
            self._sub_result = r
            return r
        except FileNotFoundError:
            print("[!] mosquitto_sub nao instalado.")
            self.registrar_log("mosquitto_sub", "ERRO: nao instalado.")
            return None
        except subprocess.TimeoutExpired:
            self.registrar_log("mosquitto_sub", "TIMEOUT atingido.")
            return None
        except Exception as e:
            print(f"[!] Erro: {e}")
            self.registrar_log("mosquitto_sub", f"ERRO: {e}")
            return None

    def testar_conexao_anonima(self):
        r = self._sub_anonimo(qtd=1)
        if r and r.returncode == 0:
            self.add_vuln(
                tipo="MQTT Sem Autenticacao",
                descricao="Broker aceita conexoes anonimas (sem credenciais)",
                severidade="Alta",
                categoria="IoT/MQTT",
            )
            self.dados_brutos["sub_anonimo"] = r.stdout[:500]

    def testar_wildcard_e_enum(self):
        r = self._sub_anonimo(qtd=10)
        if r and r.stdout.strip():
            self.add_vuln(
                tipo="Wildcard Subscription / Enumeracao",
                descricao=(
                    "Broker permite subscrever em '#', expondo topicos internos "
                    "e mensagens trafegadas"
                ),
                severidade="Alta",
                categoria="IoT/MQTT",
                evidencia=r.stdout[:500],
            )

    def testar_publicacao_anonima(self):
        try:
            r = subprocess.run(
                ["mosquitto_pub", "-h", self.host, "-p", self.port,
                 "-t", "iot_scanner/test", "-m", "scan_probe"],
                capture_output=True, text=True, timeout=MQTT_TIMEOUT
            )
            log = (
                f"Comando: mosquitto_pub -h {self.host} -p {self.port} -t iot_scanner/test -m scan_probe\n"
                f"Return code: {r.returncode}\n"
                f"--- STDOUT ---\n{r.stdout}\n"
                f"--- STDERR ---\n{r.stderr}"
            )
            self.registrar_log("mosquitto_pub", log)
            
            if r.returncode == 0:
                self.add_vuln(
                    tipo="Publicacao Anonima",
                    descricao="Broker aceita publicacoes sem autenticacao",
                    severidade="Alta",
                    categoria="IoT/MQTT",
                )
        except FileNotFoundError:
            self.registrar_log("mosquitto_pub", "ERRO: nao instalado.")
        except Exception as e:
            self.registrar_log("mosquitto_pub", f"ERRO: {e}")

    def testar_tls(self):
        if self.port == "1883":
            self.add_vuln(
                tipo="MQTT sem TLS",
                descricao="Broker em porta padrao 1883 (sem criptografia). MQTT seguro usa 8883.",
                severidade="Media",
                categoria="Transporte",
            )

    def executar(self):
        print(f"[*] Iniciando scan MQTT em {self.alvo}")
        self.testar_conexao_anonima()
        self.testar_wildcard_e_enum()
        self.testar_publicacao_anonima()
        self.testar_tls()
        return self.vulnerabilidades
