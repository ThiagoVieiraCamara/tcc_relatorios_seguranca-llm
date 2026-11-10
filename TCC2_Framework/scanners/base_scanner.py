"""Classe base abstrata para todos os scanners."""
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from config import REPORTS_DIR


class BaseScanner(ABC):
    nome = "BaseScanner"

    def __init__(self, alvo: str):
        self.alvo = alvo
        self.vulnerabilidades = []
        self.dados_brutos = {}
        self.logs_brutos = {}   # NOVO: dict de {nome_ferramenta: output_bruto}

    @abstractmethod
    def executar(self) -> list:
        """Executa o scan e popula self.vulnerabilidades. Retorna a lista."""
        pass

    def add_vuln(self, **kwargs):
        from core.vulnerability import Vulnerabilidade
        kwargs.setdefault("scanner", self.nome)
        self.vulnerabilidades.append(Vulnerabilidade(**kwargs))

    def registrar_log(self, ferramenta: str, output: str):
        """Registra output bruto de uma ferramenta externa para posterior gravacao."""
        # Acumula em caso de multiplas chamadas a mesma ferramenta
        if ferramenta in self.logs_brutos:
            self.logs_brutos[ferramenta] += "\n\n" + output
        else:
            self.logs_brutos[ferramenta] = output

    def salvar_logs(self, prefixo_arquivo: str) -> list:
        """
        Salva todos os logs registrados em arquivos .txt no REPORTS_DIR.
        Retorna lista dos paths gerados.
        """
        paths_gerados = []
        for ferramenta, conteudo in self.logs_brutos.items():
            if not conteudo or not conteudo.strip():
                continue
            
            nome_arquivo = f"{prefixo_arquivo}_{self.nome}_{ferramenta}.txt"
            path = REPORTS_DIR / nome_arquivo
            
            cabecalho = (
                f"# Log bruto de execucao\n"
                f"# Scanner: {self.nome}\n"
                f"# Ferramenta: {ferramenta}\n"
                f"# Alvo: {self.alvo}\n"
                f"# Data: {datetime.now().isoformat()}\n"
                f"{'=' * 70}\n\n"
            )
            
            try:
                path.write_text(cabecalho + conteudo, encoding="utf-8")
                paths_gerados.append(path)
            except Exception as e:
                print(f"[!] Erro ao salvar log {nome_arquivo}: {e}")
        
        return paths_gerados
