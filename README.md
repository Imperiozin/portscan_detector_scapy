# Recon Intelligence com Scapy

Projeto em Python para detectar comportamento compativel com reconhecimento de rede usando Scapy, enriquecer eventos com contexto tecnico e salvar evidencias em SQLite.

A ferramenta nao se limita a contar portas. Ela correlaciona tentativas, respostas do alvo, familia de servicos, risco tecnico, criticidade, reputacao, direcao do trafego e campanhas de reconhecimento para indicar o que a origem provavelmente estava tentando atacar ou mapear.

## Capacidades Principais

- Analise offline de arquivos `.pcap` e `.pcapng`.
- Captura ao vivo em interface de rede com Scapy.
- Deteccao de varredura vertical, horizontal, distribuida e de baixa velocidade.
- Classificacao de SYN, TCP connect, FIN, NULL, XMAS, ACK e UDP scan.
- Correlacao de respostas TCP para inferir servicos possivelmente abertos ou fechados.
- Correlacao de ICMP Port Unreachable para enriquecer tentativas UDP.
- Enriquecimento de portas para servicos, familias tecnicas, impacto e acoes defensivas.
- Score de risco tecnico, confianca, criticidade operacional e evidencias.
- Regras locais de whitelist e blacklist.
- Enriquecimento best-effort por AbuseIPDB, GreyNoise, CrowdSec e WHOIS.
- Agrupamento de eventos em casos com identificadores `ID-0001`, `ID-0002` etc.
- Interface operacional local no terminal.
- Dashboard web local para apresentacao visual e triagem defensiva.

## Categorias Tecnicas Inferidas

O catalogo interno identifica a familia provavel do servico a partir da porta e do protocolo:

- Acesso remoto: SSH, RDP, Telnet, VNC, WinRM.
- Administracao Windows e movimento lateral: SMB, RPC, NetBIOS, WinRM, RDP.
- Servicos de dados: MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, SQL Server.
- Superficie web: HTTP, HTTPS e portas web alternativas.
- Infraestrutura e plataformas: Docker API, Kubernetes API, Kubelet, etcd, registries e metricas.
- Dispositivos de rede: SNMP, BGP, Syslog, VPN e servicos de gerenciamento.
- Email: SMTP, IMAP e POP3.
- Industrial ou IoT: Modbus, MQTT, BACnet e EtherNet/IP.
- Resolucao de nomes: DNS, mDNS e servicos relacionados.

## Requisitos

- Python 3.10+
- Permissao de administrador/root para captura ao vivo
- Scapy
- Rich, para a interface operacional no terminal
- Npcap no Windows, ou libpcap em Linux/macOS
- Nmap, apenas para gerar trafego de teste autorizado

No Windows, instale o Npcap e marque a opcao de compatibilidade com WinPcap durante a instalacao:

https://npcap.com/#download

Instale as dependencias Python:

```bash
python -m pip install -r requirements.txt
```

## Uso

Listar interfaces conhecidas pelo Scapy:

```bash
python -m portscan_detector --list-interfaces
```

Capturar ao vivo em uma interface:

```bash
python -m portscan_detector --interface "Ethernet"
```

Por padrao, a captura usa o filtro BPF `tcp or udp or icmp`, pois o ICMP pode indicar respostas relevantes para scans UDP.

Na captura ao vivo, o padrao e analisar apenas pacotes de entrada (`--direction inbound`). O detector tenta descobrir os IPs da interface escolhida para diferenciar entrada e saida.

Para analisar entrada e saida:

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

Salvar em outro banco:

```bash
python -m portscan_detector --pcap captura.pcap --database eventos.db
```

Configurar limite, janela, cooldown e threshold de alerta:

```bash
python -m portscan_detector --interface "Ethernet" --threshold 10 --window 120 --cooldown 30 --alert-threshold 60
```

Padroes atuais:

- `--window 120`: janela de validacao em segundos.
- `--cooldown 30`: tempo minimo entre alertas repetidos.
- `--alert-threshold 60`: criticidade minima para alerta em destaque.

## Interfaces

Abrir a interface operacional local:

```bash
python -m portscan_detector --ui
```

Abrir o dashboard web local:

```bash
python -m portscan_detector --web-ui
```

Usar outro banco na interface:

```bash
python -m portscan_detector --ui --database eventos.db
python -m portscan_detector --web-ui --database eventos.db
```

## Cenario Demonstrativo

Gerar um cenario demonstrativo com trafego sintetico e abrir a interface:

```bash
python -m portscan_detector --demo-scenario --database demo_port_scans.db
```

O cenario demonstrativo cria casos com:

- validacao de acesso inicial por RDP/SSH;
- caca horizontal por Redis exposto;
- validacao distribuida de API Kubernetes;
- inventario lento de superficie DevOps/Web;
- sondagem UDP de rede/OT.

A demo usa pacotes sinteticos criados localmente com Scapy, passa pelo mesmo detector, salva no SQLite e calcula risco tecnico e criticidade. Para manter a demo deterministica, ela nao depende de consultas externas de reputacao.

Para abrir o dashboard web com esse banco:

```bash
python -m portscan_detector --web-ui --database demo_port_scans.db
```

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

A criticidade combina:

- risco tecnico inferido pela ferramenta;
- comportamento observado, como volume, distribuicao, varredura horizontal e scan furtivo;
- reputacao externa da origem, quando disponivel;
- whitelist e blacklist locais.

As consultas externas sao best-effort: falhas de rede, falta de chave ou ferramentas ausentes nao bloqueiam a deteccao local.

## Exemplo de Alerta

```text
[ALERTA] Reconhecimento de acesso remoto seguido de possivel uso do servico | risco=99/100 | criticidade=99/100 | confianca=91%
  Campanha: ID-0001 | Origem: 192.168.56.20 | Destino: 10.10.10.25 | Protocolo: TCP
  Intencao provavel: A origem parece buscar pontos de entrada administrativos, como SSH, RDP, Telnet, WinRM ou VNC.
  Servicos avaliados: 22/TCP SSH (possivelmente aberto), 3389/TCP RDP (possivelmente aberto)
  Evidencia principal: Foram observadas 4 porta(s) distinta(s) em 6.0s.
  Criticidade: comportamento:16; risco_tecnico:99
  MITRE: T1046 - Network Service Discovery
```

## Campos Salvos

Os eventos ficam salvos na tabela `port_scan_events` do SQLite. Por padrao, o arquivo e `port_scans.db`.

Campos principais:

- `detected_at`: horario de registro do alerta.
- `first_seen` e `last_seen`: intervalo observado.
- `source_ip` e `target_ip`: origem e destino do alerta.
- `sources` e `targets`: origens e destinos envolvidos no caso.
- `ports`: portas envolvidas.
- `scan_types`: classificacoes tecnicas aplicadas.
- `services`: servicos inferidos, categoria, criticidade tecnica e estado observado.
- `hypothesis`: hipotese tecnica do comportamento.
- `intent`: interpretacao formal da intencao provavel.
- `severity`, `confidence`, `risk_score`: priorizacao tecnica.
- `criticality`, `criticality_reasons`: criticidade operacional e motivos.
- `evidence`: evidencias que sustentam o alerta.
- `recommendations`: acoes defensivas sugeridas.
- `campaign_id`: identificador do caso correlacionado.
- `mitre_technique`: tecnica MITRE ATT&CK associada.

Consulta simples:

```bash
sqlite3 port_scans.db "select detected_at, source_ip, target_ip, criticality, risk_score, ports, scan_types from port_scan_events;"
```

## Teste Com Nmap

Rode o detector em um terminal:

```bash
python -m portscan_detector --interface "NOME_DA_INTERFACE"
```

Em outro terminal, execute scans apenas contra hosts onde voce tem autorizacao:

```bash
nmap -sS scanme.nmap.org
nmap -sT scanme.nmap.org
nmap -sF scanme.nmap.org
nmap -sN scanme.nmap.org
nmap -sX scanme.nmap.org
nmap -sA scanme.nmap.org
nmap -sU -p 53,67,68,123 scanme.nmap.org
```

## Observacao Tecnica

O detector identifica comportamento compativel com reconhecimento ou varredura. Ele nao prova invasao e nao substitui validacao humana, IDS corporativo ou correlacao com logs de autenticacao, firewall e aplicacao.

O valor da ferramenta esta em transformar pacotes capturados pelo Scapy em eventos explicaveis: o que foi testado, qual superficie parece ter sido mapeada, o que possivelmente respondeu, qual reputacao ou regra afetou a criticidade e qual prioridade defensiva deve receber.
