"""Framework de scan de vulnerabilidades IoT."""

import sys
from datetime import datetime

from config import GOOGLE_API_KEY
from core.reporter import Reporter

from scanners.nmap_scanner import NmapScanner
from scanners.http_scanner import HTTPScanner
from scanners.mqtt_scanner import MQTTScanner
from scanners.xss_scanner import XSSScanner


def banner():
    print("=" * 50)
    print(" IoT Vulnerability Scanner Framework")
    print("=" * 50)


SCANNERS_DISPONIVEIS = {
    "nmap": ("Nmap (descoberta de servicos)", NmapScanner),
    "http": ("HTTP (headers de seguranca)", HTTPScanner),
    "mqtt": ("MQTT (broker IoT)", MQTTScanner),
    "xss": ("XSS (Katana + Dalfox)", XSSScanner),
}


PRESETS = {
    "todos": list(SCANNERS_DISPONIVEIS.keys()),
    "sem-mqtt": ["nmap", "http", "xss"],
    "so-web": ["http", "xss"],
    "so-rede": ["nmap", "mqtt"],
}


def menu():
    print("\n=== ESCOLHA OS SCANNERS ===")
    print("Voce pode digitar:")
    print("  - Numeros separados por virgula (ex: 1,2,4)")
    print("  - Um preset:", ", ".join(PRESETS.keys()))
    print()

    chaves = list(SCANNERS_DISPONIVEIS.keys())

    for i, chave in enumerate(chaves, start=1):
        descricao, _ = SCANNERS_DISPONIVEIS[chave]
        print(f"  [{i}] {descricao}")

    print("\nPresets disponiveis:")

    for preset, lista in PRESETS.items():
        print(f"  '{preset}' -> {', '.join(lista)}")

    entrada = input("\nOpcao: ").strip().lower()

    return _resolver_selecao(entrada, chaves)


def _resolver_selecao(entrada, chaves):
    if not entrada:
        return []

    if entrada in PRESETS:
        return PRESETS[entrada]

    selecionados = []

    for token in entrada.split(","):
        token = token.strip()

        if token.isdigit():
            idx = int(token) - 1

            if 0 <= idx < len(chaves):
                selecionados.append(chaves[idx])
            else:
                print(f"[!] Numero invalido: {token}")

        elif token in SCANNERS_DISPONIVEIS:
            selecionados.append(token)

        else:
            print(f"[!] Opcao desconhecida: {token}")

    return selecionados


def _instanciar_scanner(chave, alvo):
    _, classe = SCANNERS_DISPONIVEIS[chave]

    if chave == "http" or chave == "xss":
        url = (
            alvo
            if alvo.startswith("http")
            else f"http://{alvo}"
        )

        return classe(url)

    elif chave == "mqtt":
        host = alvo.split(":")[0]

        port = (
            alvo.split(":")[1]
            if ":" in alvo
            else "1883"
        )

        return classe(
            host=host,
            port=port
        )

    else:
        return classe(alvo)


def _gerar_prefixo_arquivo(alvo):
    """Gera prefixo unico para todos os arquivos desta execucao."""

    nome_seguro = (
        alvo.replace("http://", "")
            .replace("https://", "")
            .replace("/", "_")
            .replace(":", "_")
            .replace(".", "_")
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    return f"{nome_seguro}_{timestamp}"


def main():
    banner()

    if not GOOGLE_API_KEY:
        print("[!] GOOGLE_API_KEY nao definida no .env")
        sys.exit(1)

    alvo = input("Alvo (host ou URL): ").strip()

    if not alvo:
        print("[!] Alvo vazio.")
        sys.exit(1)

    chaves_selecionadas = menu()

    if not chaves_selecionadas:
        print("[!] Nenhum scanner selecionado. Saindo.")
        sys.exit(1)

    print(
        f"\n[*] Scanners selecionados: "
        f"{', '.join(chaves_selecionadas)}\n"
    )

    # Prefixo unico desta execucao
    prefixo = _gerar_prefixo_arquivo(alvo)

    scanners = [
        _instanciar_scanner(chave, alvo)
        for chave in chaves_selecionadas
    ]

    todas_vulns = []
    dados_brutos = {}
    paths_logs = []

    # ==========================================
    # EXECUCAO DOS SCANNERS
    # ==========================================

    for scanner in scanners:
        vulns = scanner.executar()

        todas_vulns.extend(vulns)

        dados_brutos[
            scanner.nome
        ] = scanner.dados_brutos

        print(
            f"[+] {scanner.nome}: "
            f"{len(vulns)} achado(s)"
        )

        # Salva logs brutos da ferramenta
        logs_gerados = scanner.salvar_logs(
            prefixo
        )

        paths_logs.extend(logs_gerados)

        if logs_gerados:
            print(
                f"    Logs salvos: "
                f"{len(logs_gerados)} arquivo(s)"
            )

        print()

    # ==========================================
    # RESULTADOS
    # ==========================================

    print(
        f"[*] Total: "
        f"{len(todas_vulns)} vulnerabilidade(s)"
    )

    # ==========================================
    # GERACAO DO RELATORIO
    # ==========================================

    print(
        "[*] Gerando relatorio com Gemini..."
    )

    reporter = Reporter()

    relatorio = reporter.gerar(
        alvo,
        todas_vulns,
        dados_brutos
    )

    # ==========================================
    # AVALIACAO DO RELATORIO
    # ==========================================

    print(
        "[*] Avaliando conformidade do "
        "relatorio com Gemini..."
    )

    avaliacao = reporter.avaliar_relatorio(
        alvo,
        dados_brutos,
        relatorio
    )

    # ==========================================
    # SALVAMENTO
    # ==========================================

    path = reporter.salvar(
        alvo,
        relatorio,
        todas_vulns,
        avaliacao
    )

    print(
        f"\n[+] Relatorio principal: {path}"
    )

    if paths_logs:
        print(
            f"[+] Logs brutos das ferramentas "
            f"({len(paths_logs)} arquivo(s)):"
        )

        for p in paths_logs:
            print(f"    - {p.name}")

    print(
        "[+] Avaliacao automatizada do "
        "relatorio salva."
    )


if __name__ == "__main__":
    main()
