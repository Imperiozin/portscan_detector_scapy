# Port Scan Detector com Scapy

Projeto em Python para detectar indicios de port scan usando Scapy e salvar os eventos encontrados em um banco SQLite.

O detector observa pacotes TCP e UDP. Quando encontra muitas tentativas relacionadas dentro de uma janela curta de tempo, o evento e registrado como possivel port scan.
Cada evento recebe uma `criticality` de 0 a 100. Eventos com criticidade igual ou maior que o threshold de alerta sao impressos em vermelho na CLI.

## Tipos Detectados

- `syn_scan`: TCP SYN scan / half-open scan
- `tcp_connect_scan`: tentativa compativel com TCP connect scan
- `fin_scan`: TCP FIN scan
- `null_scan`: TCP NULL scan
- `xmas_scan`: TCP Xmas scan
- `ack_scan`: TCP ACK scan
- `udp_scan`: UDP scan
- `horizontal_scan`: mesmo IP de origem testando a mesma porta em muitos destinos
- `distributed_scan`: muitos IPs de origem testando a mesma porta no mesmo destino

Um evento pode ter mais de um tipo em `scan_types`. Por exemplo, um SYN scan horizontal pode ser salvo como `["horizontal_scan", "syn_scan"]`.

## Requisitos

- Python 3.10+
- Permissao de administrador/root para captura ao vivo
- Scapy
- Npcap no Windows, ou libpcap em Linux/macOS
- Nmap, para gerar scans reais de teste

No Windows, instale o Npcap e marque a opcao de compatibilidade com WinPcap durante a instalacao. O download manual oficial fica em:

https://npcap.com/#download

Instale as dependencias Python:

```bash
python -m pip install -r requirements.txt
```

Se o comando `python` abrir o alias da Microsoft Store ou falhar, instale o Python pelo site oficial e marque a opcao de adicionar ao `PATH`.

## Uso

Listar interfaces conhecidas pelo Scapy:

```bash
python -m portscan_detector --list-interfaces
```

Capturar ao vivo em uma interface:

```bash
python -m portscan_detector --interface "Ethernet"
```

Use exatamente o valor exibido no campo `name` da listagem de interfaces. No Windows, muitas vezes o nome usado pelo Scapy nao e `Ethernet`, mas algo como `\Device\NPF_{...}`.

Na captura ao vivo, o padrao e analisar apenas pacotes de entrada (`--direction inbound`). O detector tenta descobrir os IPs da interface escolhida para diferenciar entrada e saida.

Para voltar ao comportamento anterior e analisar entrada e saida:

```bash
python -m portscan_detector --interface "Ethernet" --direction both
```

Para analisar apenas saida:

```bash
python -m portscan_detector --interface "Ethernet" --direction outbound
```

Analisar um arquivo `.pcap` existente:

```bash
python -m portscan_detector --pcap captura.pcap
```

Em PCAP, o padrao continua `--direction both`, porque o arquivo nao informa qual interface local deve ser usada como referencia.

```bash
python -m portscan_detector --pcap captura.pcap --direction both
```

Salvar em outro banco:

```bash
python -m portscan_detector --interface "Ethernet" --database eventos.db
```

Configurar limite e janela:

```bash
python -m portscan_detector --interface "Ethernet" --threshold 10 --window 120
```

Neste exemplo, um evento sera registrado quando forem observadas pelo menos 10 tentativas relacionadas em ate 120 segundos.

Configurar threshold de alerta e cooldown:

```bash
python -m portscan_detector --interface "Ethernet" --alert-threshold 60 --cooldown 30
```

Padroes atuais:

- `--window 120`: janela de validacao em segundos
- `--cooldown 30`: tempo minimo entre alertas repetidos
- `--alert-threshold 60`: criticidade minima para alerta vermelho

## Criticidade, Whitelist e Blacklist

Por padrao, o detector procura `whitelist.json` e `blacklist.json` no diretorio atual. Voce pode informar outros arquivos:

```bash
python -m portscan_detector --interface "Ethernet" --whitelist minha_whitelist.json --blacklist minha_blacklist.json
```

Formato aceito:

```json
{
  "ips": ["203.0.113.10", "198.51.100.0/24"],
  "source_ips": ["10.0.0.0/8"],
  "target_ips": ["192.168.1.10"],
  "countries": ["BR", "CN"],
  "asns": ["AS13335", 15169],
  "organizations": ["cloudflare", "google"],
  "ports": [22, 3389],
  "scan_types": ["syn_scan", "horizontal_scan"]
}
```

Regras em `blacklist.json` levam a criticidade automaticamente para `100`. Regras em `whitelist.json` reduzem a criticidade calculada. Quando houver conflito, a blacklist prevalece.

A criticidade combina o comportamento observado com reputacao externa:

- AbuseIPDB via `--abuseipdb-key` ou variavel `ABUSEIPDB_KEY`
- GreyNoise via `--greynoise-key` ou variavel `GREYNOISE_KEY`; sem chave, tenta o endpoint community
- CrowdSec via comando local `cscli`, quando instalado
- WHOIS via comando local `whois`, quando instalado

As consultas externas sao best-effort: falhas de rede, falta de chave ou ferramentas ausentes nao bloqueiam a deteccao local.

## Teste Com Nmap

Rode o detector em um terminal:

```bash
python -m portscan_detector --interface "NOME_DA_INTERFACE"
```

Em outro terminal, execute scans com Nmap contra um host que voce tem autorizacao para testar. Para teste local:

```bash
nmap -sT 127.0.0.1
```

Exemplos para validar tipos diferentes:

```bash
nmap -sS scanme.nmap.org
nmap -sT scanme.nmap.org
nmap -sF scanme.nmap.org
nmap -sN scanme.nmap.org
nmap -sX scanme.nmap.org
nmap -sA scanme.nmap.org
nmap -sU -p 53,67,68,123 scanme.nmap.org
```

Use scans apenas em hosts e redes onde voce tem autorizacao.

## Saida

Os eventos ficam salvos na tabela `port_scan_events` do SQLite. Por padrao, o arquivo e `port_scans.db`.

Campos salvos:

- `detected_at`: quando o detector registrou o evento
- `first_seen`: primeiro pacote observado na janela
- `last_seen`: ultimo pacote observado na janela
- `source_ip`: IP suspeito
- `target_ip`: IP de destino
- `ports`: lista de portas acessadas
- `scan_types`: lista com um ou mais tipos identificados
- `criticality`: criticidade de 0 a 100
- `criticality_reasons`: motivos usados no calculo da criticidade
- `port_count`: quantidade de portas diferentes
- `packet_count`: quantidade de pacotes observados no evento

Para consultar:

```bash
sqlite3 port_scans.db "select detected_at, source_ip, target_ip, criticality, ports, scan_types from port_scan_events;"
```

## Observacao

Este detector identifica comportamento compativel com port scan, nao uma prova absoluta de ataque. Ajuste `--threshold`, `--window` e `--alert-threshold` conforme o volume normal da sua rede.
