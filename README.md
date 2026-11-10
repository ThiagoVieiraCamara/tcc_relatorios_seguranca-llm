# Relatórios de segurança com modelos de linguagem

Código e dados do Trabalho de Conclusão de Curso **"Relatórios de segurança com modelos de linguagem: análise da correspondência entre afirmações e evidências em ambientes controlados"**, de Thiago Vieira Camara, com orientação do Prof. Dr. Herbert Rocha. Bacharelado em Ciência da Computação, Universidade Federal de Roraima (UFRR), 2026.

O repositório contém o protótipo, os *prompts*, a configuração dos ambientes de teste, as saídas brutas das ferramentas, os relatórios gerados, as avaliações de fidelidade factual e os conjuntos de referência (*ground truth*) usados nos experimentos.

> **Versão do TCC:** os resultados apresentados no trabalho correspondem à release [`v1.0-tcc`](../../releases/tag/v1.0-tcc).

## Visão geral

O protótipo executa um conjunto de ferramentas de verificação de segurança contra um alvo, consolida os resultados e os envia a um modelo de linguagem, que redige um relatório técnico. Um segundo modelo atua como auditor (*LLM-as-a-Judge*) e verifica se cada afirmação do relatório é sustentada pelos dados brutos coletados.

```
Alvo ──► Módulos de verificação ──► Achados + dados brutos ──► LLM Redator ──► Relatório
          (Nmap, HTTP, MQTT,                │                                    │
           Katana + Dalfox)                 └──────────► LLM Auditor ◄───────────┘
                                                              │
                                                     Fidelidade factual
```

| Módulo | Ferramenta | O que verifica |
|---|---|---|
| Rede | Nmap | Portas, serviços e versões |
| HTTP | Python (`requests`) | Cabeçalhos de segurança, CORS e métodos HTTP |
| MQTT | `mosquitto_pub` / `mosquitto_sub` | Acesso ao *broker* sem autenticação e sem criptografia |
| XSS | Katana + Dalfox | Descoberta de URLs e testes de *Cross-Site Scripting* |

## Estrutura do repositório

```
├── src/                  Código do protótipo
├── prompts/              Prompts do Redator e do Auditor
├── ambientes/            Configuração do broker MQTT inseguro
├── ground_truth/         Conjuntos de referência do IoTGoat e do OWASP Juice Shop
├── resultados/
│   ├── iotgoat/          Logs brutos, achados, relatórios e avaliações
│   └── juice_shop/       Logs brutos, achados, relatórios e avaliações
└── scripts/              Script de recálculo da fidelidade factual
```

## Requisitos

| Componente | Versão usada nos experimentos |
|---|---|
| Python | 3.14.4 |
| Nmap | 7.99 |
| Katana | <!-- AJUSTAR --> |
| Dalfox | <!-- AJUSTAR --> |
| Mosquitto (clientes e broker) | 2.1.2 |
| Docker | <!-- AJUSTAR --> |

As bibliotecas Python estão em `requirements.txt`.

## Instalação

```bash
git clone https://github.com/<usuario>/<repositorio>.git
cd <repositorio>
python -m venv .venv
source .venv/bin/activate        # no Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Instale também o Nmap, o Katana, o Dalfox e os clientes do Mosquitto, e confira que estão no `PATH`.

## Configuração

Copie o arquivo de exemplo e preencha a sua chave da API do Google Gemini:

```bash
cp .env.example .env
```

```
GOOGLE_API_KEY=sua_chave_aqui
```

O modelo usado e a pasta onde os relatórios são salvos estão definidos em `src/config.py` (`GEMINI_MODEL` e `REPORTS_DIR`).

> O arquivo `.env` não deve ser enviado ao repositório.

## Como executar

<!-- AJUSTAR: troque pelo comando real de execução do protótipo -->
```bash
python src/main.py --alvo <endereco_do_alvo>
```

A execução gera, na pasta definida em `REPORTS_DIR`:

- `relatorio_<alvo>_<data>.txt`: o relatório técnico gerado pelo LLM;
- `vulns_<alvo>_<data>.json`: os achados consolidados dos módulos;
- `avaliacao_<alvo>_<data>.json`: a avaliação de fidelidade factual do relatório.

### Broker MQTT inseguro

O cenário complementar usa um *broker* Mosquitto configurado sem autenticação e sem TLS:

```bash
cd ambientes/broker_mqtt
docker compose up -d
```

> Execute as ferramentas apenas contra ambientes próprios ou com autorização expressa. Os alvos usados neste trabalho são intencionalmente vulneráveis e foram executados em ambiente controlado.

## Ambientes avaliados

| Ambiente | Versão | Execução | Acesso |
|---|---|---|---|
| OWASP IoTGoat | v1.0 | Docker e QEMU | `https://localhost:4443/cgi-bin/luci/` |
| OWASP Juice Shop | v20.3.0 | Contêiner Docker, exposto por túnel TCP do ngrok | `http://0.tcp.sa.ngrok.io:12356` |
| Broker MQTT | Mosquitto 2.1.2 | Contêiner Docker, sem autenticação e sem TLS | <!-- AJUSTAR: host e porta --> |

Os conjuntos de referência em `ground_truth/` foram elaborados a partir da documentação oficial de cada projeto ([IoTGoat](https://github.com/OWASP/IoTGoat) e [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)). Cada arquivo indica as fontes, o escopo de detecção e a evidência esperada de cada registro.

## Modelos de linguagem

| Modelo | Identificador | Acesso | Avaliador do relatório |
|---|---|---|---|
| Gemini | <!-- AJUSTAR: valor de GEMINI_MODEL --> | API Google GenAI, pelo protótipo | O próprio Gemini |
| Claude | `claude-opus-5-5` | Interface do Claude | O próprio Claude |
| DeepSeek | V4.1-Flash-1017 | Interface do DeepSeek | Claude |

Os três modelos receberam o mesmo *prompt* e os mesmos dados de entrada. Apenas os relatórios do Gemini foram gerados pelo protótipo; os do Claude e do DeepSeek foram gerados nas plataformas de cada serviço e estão salvos em `resultados/`. Os parâmetros de geração foram os padrões de cada serviço.

## Reproduzindo os resultados

A fidelidade factual é calculada como:

```
Fidelidade = suportadas / (suportadas + não suportadas + contraditas)
```

As afirmações não verificáveis ficam fora do denominador. Para recalcular as taxas diretamente das listas de afirmações dos arquivos de avaliação:

```bash
python scripts/recalcular_fidelidade.py resultados/*/avaliacoes/*.json
```

O script conta os itens da lista `afirmacoes` de cada arquivo, em vez de usar o resumo calculado pelo próprio modelo avaliador.

| Cenário | Modelo | Suportadas | Não suportadas | Contraditas | Não verificáveis | Fidelidade |
|---|---|---|---|---|---|---|
| IoTGoat | Claude | 31 | 2 | 0 | 12 | 93,94% |
| IoTGoat | Gemini | 72 | 1 | 0 | 1 | 98,63% |
| IoTGoat | DeepSeek | 8 | 10 | 0 | 2 | 44,44% |
| Juice Shop | Claude | 39 | 4 | 0 | 18 | 90,70% |
| Juice Shop | Gemini | 60 | 0 | 0 | 8 | 100,00% |
| Juice Shop | DeepSeek | 22 | 0 | 0 | 0 | 100,00% |

## Limitações conhecidas

- **Nmap:** nas execuções do TCC, o alvo foi passado como URL completa ou no formato `host:porta`, que o Nmap não aceita. Por isso nenhum host foi escaneado nos dois ambientes principais. <!-- AJUSTAR se corrigir e rodar de novo -->
- **MQTT:** o módulo funcionou no *broker* dedicado, mas não chegou aos alvos principais, porque o endereço foi dividido de forma incorreta.
- **IoTGoat:** a interface web responde `403 Forbidden` com a página de login a requisições sem sessão autenticada. Os cabeçalhos analisados correspondem a essa página.
- **Avaliadores:** os relatórios não foram avaliados por um único modelo. O Gemini avaliou o próprio relatório, e o Claude avaliou o seu e o do DeepSeek, o que limita a comparação direta entre os modelos.

## Citação

```
CAMARA, Thiago Vieira. Relatórios de segurança com modelos de linguagem: análise da correspondência entre afirmações e evidências em ambientes controlados. 2026. Trabalho de Conclusão de Curso (Bacharelado em Ciência da Computação) – Universidade Federal de Roraima, Boa Vista, 2026.
```

## Licença

<!-- AJUSTAR: ex. MIT, conforme escolhido ao criar o repositório -->
