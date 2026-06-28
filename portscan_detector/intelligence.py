from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Mapping, Sequence


EXPOSURE_ATTEMPTED = "attempted"
EXPOSURE_OPEN = "open"
EXPOSURE_CLOSED = "closed"
EXPOSURE_FILTERED = "filtered_or_inconclusive"
EXPOSURE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ServiceDefinition:
    port: int
    protocol: str
    service: str
    category: str
    risk: int
    description: str


@dataclass(frozen=True)
class ServiceFinding:
    port: int
    protocol: str
    service: str
    category: str
    exposure: str
    risk: int
    description: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CategoryProfile:
    title: str
    intent: str
    impact: str
    recommendations: tuple[str, ...]


@dataclass(frozen=True)
class AttackHypothesis:
    title: str
    intent: str
    severity: str
    confidence: float
    risk_score: int
    mitre_technique: str
    evidence: tuple[str, ...]
    recommendations: tuple[str, ...]
    service_categories: tuple[str, ...]


CATEGORY_PROFILES: dict[str, CategoryProfile] = {
    "remote_access": CategoryProfile(
        title="Reconhecimento de acesso remoto",
        intent=(
            "A origem parece buscar pontos de entrada administrativos, como SSH, "
            "RDP, Telnet, WinRM ou VNC."
        ),
        impact=(
            "Serviços de acesso remoto expostos podem ser usados em tentativa de "
            "autenticação indevida, exploração de credenciais fracas ou acesso inicial."
        ),
        recommendations=(
            "Validar se a origem do tráfego é autorizada para sondagem de acesso remoto.",
            "Conferir logs de autenticação nos serviços remotos possivelmente expostos.",
            "Revisar exposição de serviços administrativos fora de redes confiáveis.",
        ),
    ),
    "windows_admin": CategoryProfile(
        title="Reconhecimento de administração Windows e movimento lateral",
        intent=(
            "A origem parece mapear serviços comuns em ambientes Windows, como SMB, "
            "RPC, NetBIOS, RDP ou WinRM."
        ),
        impact=(
            "Esse perfil pode indicar preparação para enumeração de compartilhamentos, "
            "movimento lateral ou abuso de serviços administrativos."
        ),
        recommendations=(
            "Revisar exposição de SMB, RPC, WinRM e RDP no ativo de destino.",
            "Correlacionar o horário com logs de autenticação e eventos do Windows.",
            "Confirmar se a origem pertence a uma ferramenta interna autorizada.",
        ),
    ),
    "database": CategoryProfile(
        title="Reconhecimento de serviços de dados",
        intent=(
            "A origem parece procurar bancos de dados ou mecanismos de armazenamento "
            "expostos."
        ),
        impact=(
            "Serviços de dados expostos podem ampliar risco de vazamento, alteração "
            "indevida ou enumeração de informações sensíveis."
        ),
        recommendations=(
            "Verificar se os serviços de dados aceitam conexões apenas de redes esperadas.",
            "Revisar autenticação, controle de acesso e logs dos bancos identificados.",
            "Confirmar se há exposição pública ou lateral indevida desses serviços.",
        ),
    ),
    "web": CategoryProfile(
        title="Reconhecimento de superfície web",
        intent=(
            "A origem parece mapear portas associadas a aplicações HTTP, HTTPS ou "
            "interfaces web alternativas."
        ),
        impact=(
            "Esse comportamento pode anteceder enumeração de aplicações, painéis "
            "administrativos ou testes de vulnerabilidade em serviços web."
        ),
        recommendations=(
            "Revisar logs HTTP e tentativas subsequentes da mesma origem.",
            "Validar se interfaces administrativas web estão restritas.",
            "Confirmar se os serviços expostos possuem atualização e endurecimento adequados.",
        ),
    ),
    "devops_infra": CategoryProfile(
        title="Reconhecimento de infraestrutura e plataformas de execução",
        intent=(
            "A origem parece buscar APIs ou componentes de infraestrutura, como Docker, "
            "Kubernetes, etcd, registries ou métricas."
        ),
        impact=(
            "A exposição desses serviços pode permitir enumeração de infraestrutura, "
            "controle de workloads ou acesso a configurações sensíveis."
        ),
        recommendations=(
            "Verificar se APIs de infraestrutura estão restritas a redes administrativas.",
            "Revisar autenticação, TLS e regras de firewall dos componentes identificados.",
            "Investigar tentativas posteriores contra os serviços possivelmente abertos.",
        ),
    ),
    "network_device": CategoryProfile(
        title="Reconhecimento de dispositivos e gerenciamento de rede",
        intent=(
            "A origem parece mapear serviços de gerenciamento de rede, roteamento, "
            "monitoramento ou administração de dispositivos."
        ),
        impact=(
            "A exposição desses serviços pode revelar topologia, configuração de rede "
            "ou interfaces administrativas sensíveis."
        ),
        recommendations=(
            "Validar se SNMP, SSH, Telnet e interfaces de gerenciamento estão segmentados.",
            "Conferir logs de equipamentos de rede no período observado.",
            "Revisar comunidade SNMP, autenticação e listas de controle de acesso.",
        ),
    ),
    "mail": CategoryProfile(
        title="Reconhecimento de serviços de email",
        intent=(
            "A origem parece identificar serviços SMTP, IMAP ou POP3 expostos."
        ),
        impact=(
            "Esse reconhecimento pode anteceder enumeração de usuários, abuso de relay "
            "ou tentativa de autenticação contra caixas postais."
        ),
        recommendations=(
            "Revisar logs de autenticação e relay nos serviços de email.",
            "Confirmar política de TLS, autenticação e restrição de origem.",
            "Verificar tentativas subsequentes de login ou envio anômalo.",
        ),
    ),
    "industrial_iot": CategoryProfile(
        title="Reconhecimento de serviços industriais ou IoT",
        intent=(
            "A origem parece sondar protocolos usados em automação, IoT ou ambientes OT."
        ),
        impact=(
            "Esse perfil deve receber atenção elevada quando envolve ambientes "
            "operacionais, pois pode expor controle ou telemetria sensível."
        ),
        recommendations=(
            "Confirmar se os ativos fazem parte de ambiente operacional ou IoT.",
            "Validar segmentação de rede e exposição dos protocolos identificados.",
            "Correlacionar com logs de gateway, firewall ou equipamento industrial.",
        ),
    ),
    "name_resolution": CategoryProfile(
        title="Reconhecimento de resolução de nomes",
        intent=(
            "A origem parece sondar serviços DNS, mDNS, LLMNR ou descoberta de nomes."
        ),
        impact=(
            "A exposição desses serviços pode apoiar enumeração de ativos, domínios "
            "internos ou infraestrutura de nomes."
        ),
        recommendations=(
            "Verificar consultas ou respostas DNS anormais no período observado.",
            "Confirmar se serviços de resolução estão expostos apenas onde necessário.",
            "Correlacionar com outras tentativas de enumeração da mesma origem.",
        ),
    ),
    "generic": CategoryProfile(
        title="Reconhecimento de superfície de rede",
        intent=(
            "A origem apresenta comportamento compatível com mapeamento de superfície "
            "de ataque, sem predominância clara de uma família de serviços."
        ),
        impact=(
            "O comportamento pode indicar levantamento inicial de portas e serviços "
            "para seleção posterior de alvos."
        ),
        recommendations=(
            "Validar se a origem possui justificativa operacional para a varredura.",
            "Correlacionar eventos posteriores contra as portas que responderam.",
            "Revisar exposição dos serviços mais sensíveis observados.",
        ),
    ),
}


SERVICE_CATALOG: tuple[ServiceDefinition, ...] = (
    ServiceDefinition(20, "tcp", "FTP data", "remote_access", 45, "Canal de dados FTP."),
    ServiceDefinition(21, "tcp", "FTP", "remote_access", 55, "Transferência de arquivos e administração legada."),
    ServiceDefinition(22, "tcp", "SSH", "remote_access", 80, "Acesso remoto administrativo."),
    ServiceDefinition(23, "tcp", "Telnet", "remote_access", 85, "Acesso remoto sem criptografia moderna."),
    ServiceDefinition(25, "tcp", "SMTP", "mail", 55, "Envio de email."),
    ServiceDefinition(53, "tcp", "DNS", "name_resolution", 45, "Resolucao de nomes."),
    ServiceDefinition(53, "udp", "DNS", "name_resolution", 45, "Resolucao de nomes."),
    ServiceDefinition(67, "udp", "DHCP server", "network_device", 35, "Atribuicao de enderecos de rede."),
    ServiceDefinition(68, "udp", "DHCP client", "network_device", 25, "Cliente DHCP."),
    ServiceDefinition(69, "udp", "TFTP", "network_device", 60, "Transferencia simples de arquivos."),
    ServiceDefinition(80, "tcp", "HTTP", "web", 45, "Aplicação web sem TLS."),
    ServiceDefinition(110, "tcp", "POP3", "mail", 45, "Acesso a caixa postal."),
    ServiceDefinition(111, "tcp", "RPCbind", "network_device", 60, "Mapeamento RPC."),
    ServiceDefinition(111, "udp", "RPCbind", "network_device", 60, "Mapeamento RPC."),
    ServiceDefinition(123, "udp", "NTP", "network_device", 35, "Sincronização de tempo."),
    ServiceDefinition(135, "tcp", "MS RPC", "windows_admin", 75, "RPC usado em administração Windows."),
    ServiceDefinition(137, "udp", "NetBIOS Name Service", "windows_admin", 60, "Resolucao NetBIOS."),
    ServiceDefinition(138, "udp", "NetBIOS Datagram", "windows_admin", 55, "Datagramas NetBIOS."),
    ServiceDefinition(139, "tcp", "NetBIOS Session", "windows_admin", 70, "Sessao NetBIOS."),
    ServiceDefinition(143, "tcp", "IMAP", "mail", 45, "Acesso a caixa postal."),
    ServiceDefinition(161, "udp", "SNMP", "network_device", 75, "Gerenciamento e inventario de rede."),
    ServiceDefinition(162, "udp", "SNMP trap", "network_device", 55, "Notificacoes SNMP."),
    ServiceDefinition(179, "tcp", "BGP", "network_device", 80, "Roteamento interdominio."),
    ServiceDefinition(389, "tcp", "LDAP", "windows_admin", 65, "Diretório e autenticação."),
    ServiceDefinition(443, "tcp", "HTTPS", "web", 50, "Aplicação web com TLS."),
    ServiceDefinition(445, "tcp", "SMB", "windows_admin", 90, "Compartilhamento e administração Windows."),
    ServiceDefinition(465, "tcp", "SMTPS", "mail", 45, "SMTP com TLS implicito."),
    ServiceDefinition(500, "udp", "IKE", "network_device", 65, "Negociação VPN IPsec."),
    ServiceDefinition(502, "tcp", "Modbus", "industrial_iot", 95, "Protocolo industrial."),
    ServiceDefinition(514, "udp", "Syslog", "network_device", 45, "Registro remoto de eventos."),
    ServiceDefinition(587, "tcp", "SMTP submission", "mail", 45, "Envio autenticado de email."),
    ServiceDefinition(636, "tcp", "LDAPS", "windows_admin", 65, "LDAP sobre TLS."),
    ServiceDefinition(993, "tcp", "IMAPS", "mail", 40, "IMAP com TLS."),
    ServiceDefinition(995, "tcp", "POP3S", "mail", 40, "POP3 com TLS."),
    ServiceDefinition(1433, "tcp", "Microsoft SQL Server", "database", 85, "Banco de dados Microsoft."),
    ServiceDefinition(1521, "tcp", "Oracle Database", "database", 85, "Banco de dados Oracle."),
    ServiceDefinition(1883, "tcp", "MQTT", "industrial_iot", 70, "Mensageria IoT."),
    ServiceDefinition(1900, "udp", "SSDP", "industrial_iot", 55, "Descoberta de dispositivos."),
    ServiceDefinition(2049, "tcp", "NFS", "network_device", 70, "Compartilhamento de arquivos Unix."),
    ServiceDefinition(2375, "tcp", "Docker API", "devops_infra", 100, "API Docker sem TLS por padrão."),
    ServiceDefinition(2376, "tcp", "Docker API TLS", "devops_infra", 90, "API Docker com TLS."),
    ServiceDefinition(2379, "tcp", "etcd client", "devops_infra", 95, "Banco de configuração distribuída."),
    ServiceDefinition(2380, "tcp", "etcd peer", "devops_infra", 90, "Comunicação entre membros etcd."),
    ServiceDefinition(3306, "tcp", "MySQL", "database", 85, "Banco de dados MySQL ou MariaDB."),
    ServiceDefinition(3389, "tcp", "RDP", "remote_access", 95, "Acesso remoto grafico Windows."),
    ServiceDefinition(5432, "tcp", "PostgreSQL", "database", 85, "Banco de dados PostgreSQL."),
    ServiceDefinition(5601, "tcp", "Kibana", "devops_infra", 75, "Interface de observabilidade."),
    ServiceDefinition(5672, "tcp", "RabbitMQ", "devops_infra", 70, "Mensageria AMQP."),
    ServiceDefinition(5900, "tcp", "VNC", "remote_access", 80, "Acesso remoto grafico."),
    ServiceDefinition(5985, "tcp", "WinRM HTTP", "windows_admin", 90, "Administração remota Windows."),
    ServiceDefinition(5986, "tcp", "WinRM HTTPS", "windows_admin", 85, "Administração remota Windows com TLS."),
    ServiceDefinition(6379, "tcp", "Redis", "database", 95, "Banco em memoria."),
    ServiceDefinition(6443, "tcp", "Kubernetes API", "devops_infra", 100, "API do plano de controle Kubernetes."),
    ServiceDefinition(8000, "tcp", "HTTP alternate", "web", 45, "Aplicação web alternativa."),
    ServiceDefinition(8080, "tcp", "HTTP alternate", "web", 50, "Aplicação web ou proxy."),
    ServiceDefinition(8443, "tcp", "HTTPS alternate", "web", 55, "Aplicação web administrativa com TLS."),
    ServiceDefinition(8888, "tcp", "HTTP alternate", "web", 45, "Aplicação web alternativa."),
    ServiceDefinition(9200, "tcp", "Elasticsearch", "database", 90, "Mecanismo de busca e dados."),
    ServiceDefinition(9300, "tcp", "Elasticsearch transport", "database", 80, "Transporte de cluster Elasticsearch."),
    ServiceDefinition(10250, "tcp", "Kubelet API", "devops_infra", 95, "API do agente Kubernetes."),
    ServiceDefinition(10255, "tcp", "Kubelet read-only", "devops_infra", 90, "Endpoint legado de leitura Kubernetes."),
    ServiceDefinition(11211, "tcp", "Memcached", "database", 80, "Cache em memoria."),
    ServiceDefinition(11211, "udp", "Memcached", "database", 80, "Cache em memoria."),
    ServiceDefinition(27017, "tcp", "MongoDB", "database", 85, "Banco de dados MongoDB."),
    ServiceDefinition(44818, "tcp", "EtherNet/IP", "industrial_iot", 95, "Protocolo industrial."),
    ServiceDefinition(47808, "udp", "BACnet", "industrial_iot", 95, "Automação predial."),
)

_CATALOG_BY_KEY = {
    (item.protocol.lower(), item.port): item
    for item in SERVICE_CATALOG
}


def describe_service(port: int, protocol: str) -> ServiceDefinition:
    normalized_protocol = protocol.lower()
    exact = _CATALOG_BY_KEY.get((normalized_protocol, port))
    if exact is not None:
        return exact

    tcp_fallback = _CATALOG_BY_KEY.get(("tcp", port))
    if tcp_fallback is not None:
        return ServiceDefinition(
            port=port,
            protocol=normalized_protocol,
            service=tcp_fallback.service,
            category=tcp_fallback.category,
            risk=max(25, tcp_fallback.risk - 10),
            description=tcp_fallback.description,
        )

    return ServiceDefinition(
        port=port,
        protocol=normalized_protocol,
        service="serviço não catalogado",
        category="generic",
        risk=30,
        description="Porta sem mapeamento interno no catálogo técnico.",
    )


def build_service_findings(
    ports: Iterable[int],
    protocol: str,
    exposure_by_port: Mapping[int, str],
) -> tuple[ServiceFinding, ...]:
    findings = []
    for port in sorted(set(ports)):
        definition = describe_service(port, protocol)
        exposure = exposure_by_port.get(port, EXPOSURE_ATTEMPTED)
        findings.append(
            ServiceFinding(
                port=definition.port,
                protocol=definition.protocol,
                service=definition.service,
                category=definition.category,
                exposure=exposure,
                risk=definition.risk,
                description=definition.description,
            )
        )
    return tuple(findings)


def infer_hypothesis(
    scan_types: Sequence[str],
    services: Sequence[ServiceFinding],
    source_count: int,
    target_count: int,
    packet_count: int,
    duration_seconds: float,
    threshold: int,
    post_scan_connection_observed: bool,
) -> AttackHypothesis:
    categories = _rank_categories(services)
    primary_category = categories[0] if categories else "generic"
    profile = CATEGORY_PROFILES.get(primary_category, CATEGORY_PROFILES["generic"])
    service_names = _format_service_names(services)
    open_services = [service for service in services if service.exposure == EXPOSURE_OPEN]
    critical_services = [service for service in services if service.risk >= 90]

    risk_score = _risk_score(
        scan_types=scan_types,
        services=services,
        source_count=source_count,
        target_count=target_count,
        packet_count=packet_count,
        post_scan_connection_observed=post_scan_connection_observed,
    )
    severity = _severity_from_score(risk_score)
    confidence = _confidence(
        services=services,
        threshold=threshold,
        open_services=open_services,
        post_scan_connection_observed=post_scan_connection_observed,
    )

    title = profile.title
    if "distributed_scan" in scan_types:
        title = f"{title} com origem distribuída"
    elif "horizontal_scan" in scan_types:
        title = f"{title} em varredura horizontal"
    elif "slow_scan" in scan_types:
        title = f"{title} de baixa velocidade"
    if post_scan_connection_observed:
        title = f"{title} seguido de possível uso do serviço"

    evidence = list(
        _base_evidence(
            scan_types=scan_types,
            services=services,
            source_count=source_count,
            target_count=target_count,
            packet_count=packet_count,
            duration_seconds=duration_seconds,
        )
    )
    if service_names:
        evidence.append(f"Serviços inferidos a partir das portas: {service_names}.")
    if open_services:
        evidence.append(
            "Foram observadas respostas compatíveis com serviço aberto em: "
            f"{_format_service_names(open_services)}."
        )
    if critical_services:
        evidence.append(
            "O conjunto inclui serviços de criticidade elevada: "
            f"{_format_service_names(critical_services)}."
        )
    if post_scan_connection_observed:
        evidence.append(
            "A origem realizou tráfego de conexão para serviço previamente identificado "
            "como possivelmente aberto."
        )

    recommendations = tuple(dict.fromkeys(profile.recommendations + (
        "Priorizar revisão dos serviços classificados como possivelmente abertos.",
        "Monitorar conexões subsequentes da mesma origem para identificar progressão após o reconhecimento.",
    )))

    return AttackHypothesis(
        title=title,
        intent=profile.intent,
        severity=severity,
        confidence=confidence,
        risk_score=risk_score,
        mitre_technique="T1046 - Network Service Discovery",
        evidence=tuple(evidence),
        recommendations=recommendations,
        service_categories=tuple(categories),
    )


def service_status_label(exposure: str) -> str:
    labels = {
        EXPOSURE_ATTEMPTED: "testado",
        EXPOSURE_OPEN: "possivelmente aberto",
        EXPOSURE_CLOSED: "fechado",
        EXPOSURE_FILTERED: "filtrado ou inconclusivo",
        EXPOSURE_UNKNOWN: "desconhecido",
    }
    return labels.get(exposure, exposure)


def service_to_label(service: ServiceFinding) -> str:
    return (
        f"{service.port}/{service.protocol.upper()} {service.service} "
        f"({service_status_label(service.exposure)})"
    )


def _rank_categories(services: Sequence[ServiceFinding]) -> list[str]:
    scores: dict[str, int] = {}
    for service in services:
        scores[service.category] = scores.get(service.category, 0) + service.risk + 10
        if service.exposure == EXPOSURE_OPEN:
            scores[service.category] += 15
    if not scores:
        return ["generic"]
    return [
        category
        for category, _score in sorted(
            scores.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]


def _risk_score(
    scan_types: Sequence[str],
    services: Sequence[ServiceFinding],
    source_count: int,
    target_count: int,
    packet_count: int,
    post_scan_connection_observed: bool,
) -> int:
    max_service_risk = max((service.risk for service in services), default=30)
    open_count = sum(1 for service in services if service.exposure == EXPOSURE_OPEN)
    critical_count = sum(1 for service in services if service.risk >= 90)
    stealth_scan = any(scan_type in {"fin_scan", "null_scan", "xmas_scan", "ack_scan"} for scan_type in scan_types)

    score = 25
    score += min(20, len(services) * 2)
    score += min(20, max(0, max_service_risk - 50) // 2)
    score += min(16, open_count * 8)
    score += min(12, critical_count * 6)
    score += min(10, max(0, target_count - 1) * 2)
    score += min(8, max(0, source_count - 1) * 2)
    score += min(8, packet_count // 10)

    if "horizontal_scan" in scan_types:
        score += 8
    if "distributed_scan" in scan_types:
        score += 12
    if "slow_scan" in scan_types:
        score += 6
    if stealth_scan:
        score += 8
    if post_scan_connection_observed:
        score += 18

    return min(100, score)


def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _confidence(
    services: Sequence[ServiceFinding],
    threshold: int,
    open_services: Sequence[ServiceFinding],
    post_scan_connection_observed: bool,
) -> float:
    if not services:
        return 0.5

    categories = _rank_categories(services)
    primary_category = categories[0]
    primary_count = sum(1 for service in services if service.category == primary_category)
    cohesion = primary_count / len(services)

    confidence = 0.52
    confidence += min(0.16, len(services) / max(threshold, 1) * 0.08)
    confidence += min(0.18, cohesion * 0.18)
    confidence += min(0.10, len(open_services) * 0.04)
    if any(service.risk >= 90 for service in services):
        confidence += 0.04
    if post_scan_connection_observed:
        confidence += 0.10

    return min(0.99, round(confidence, 2))


def _base_evidence(
    scan_types: Sequence[str],
    services: Sequence[ServiceFinding],
    source_count: int,
    target_count: int,
    packet_count: int,
    duration_seconds: float,
) -> tuple[str, ...]:
    distinct_ports = len({service.port for service in services})
    packet_rate = packet_count / duration_seconds if duration_seconds > 0 else float(packet_count)
    evidence = [
        f"Foram observadas {distinct_ports} porta(s) distinta(s) em {duration_seconds:.1f}s.",
        f"Volume técnico observado: {packet_count} pacote(s), taxa aproximada de {packet_rate:.2f} pacote(s)/s.",
    ]
    if source_count > 1:
        evidence.append(f"O padrão envolve {source_count} origem(ns), indicando coordenação ou origem distribuída.")
    if target_count > 1:
        evidence.append(f"O padrão envolve {target_count} destino(s), caracterizando varredura horizontal.")
    if scan_types:
        evidence.append(f"Classificações técnicas aplicadas: {', '.join(sorted(scan_types))}.")
    return tuple(evidence)


def _format_service_names(services: Sequence[ServiceFinding]) -> str:
    labels = [service_to_label(service) for service in services]
    return ", ".join(labels)
