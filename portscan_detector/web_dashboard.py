from __future__ import annotations

import json
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socket import socket
from typing import Any
from urllib.parse import urlparse

from .storage import SQLiteEventStore


DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8765

SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

CATEGORY_LABELS = {
    "remote_access": "Acesso remoto",
    "windows_admin": "Administração Windows",
    "database": "Serviços de dados",
    "web": "Superfície web",
    "devops_infra": "Infraestrutura e plataformas",
    "network_device": "Gerenciamento de rede",
    "mail": "Serviços de email",
    "industrial_iot": "Industrial ou IoT",
    "name_resolution": "Resolução de nomes",
    "generic": "Superfície genérica",
}

OBJECTIVE_LABELS = {
    "remote_access": "acesso remoto",
    "windows_admin": "administração Windows",
    "database": "serviços de dados",
    "web": "superfície web",
    "devops_infra": "infraestrutura e plataformas",
    "network_device": "gerenciamento de rede",
    "mail": "serviços de email",
    "industrial_iot": "industrial ou IoT",
    "name_resolution": "resolução de nomes",
    "generic": "superfície genérica",
}

EXPOSURE_LABELS = {
    "open": "Possivelmente aberto",
    "closed": "Fechado",
    "attempted": "Testado",
    "filtered_or_inconclusive": "Filtrado ou inconclusivo",
    "unknown": "Desconhecido",
}


def run_web_dashboard(
    database_path: Path,
    host: str = DEFAULT_WEB_HOST,
    port: int = DEFAULT_WEB_PORT,
) -> None:
    selected_port = _available_port(host, port)
    store = SQLiteEventStore(database_path)
    handler = _handler_for(store)
    server = ThreadingHTTPServer((host, selected_port), handler)
    url = f"http://{host}:{selected_port}/"
    print(f"Interface web operacional disponivel em {url}")
    print("Pressione Ctrl+C para encerrar.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nInterface web encerrada.")
    finally:
        server.server_close()


def _available_port(host: str, preferred_port: int) -> int:
    for port in range(preferred_port, preferred_port + 25):
        with socket() as probe:
            try:
                probe.bind((host, port))
            except OSError:
                continue
            return port
    raise RuntimeError("Nenhuma porta local disponivel para iniciar a interface web.")


def _handler_for(store: SQLiteEventStore) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(_HTML)
                return
            if parsed.path == "/api/dashboard":
                self._send_json(_dashboard_payload(store))
                return
            if parsed.path == "/health":
                self._send_json({"status": "ok"})
                return
            self.send_error(404, "Recurso não encontrado")

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_html(self, value: str) -> None:
            body = value.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, value: dict[str, Any]) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def _dashboard_payload(store: SQLiteEventStore) -> dict[str, Any]:
    events = store.fetch_recent_events(limit=1000)
    campaigns = store.fetch_campaigns(limit=1000)
    exposure = store.fetch_exposure(limit=1000)
    highest_risk = store.fetch_highest_risk_event()
    campaign_dossiers = _campaign_dossiers(events, campaigns, exposure)

    return {
        "overview": _overview(events, campaigns, exposure),
        "briefing": _briefing(campaign_dossiers),
        "events": events[:12],
        "campaigns": campaign_dossiers,
        "exposure": _exposure_rows(exposure),
        "highestRisk": _event_dossier(highest_risk) if highest_risk else None,
    }


def _overview(
    events: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    exposure: list[dict[str, Any]],
) -> dict[str, Any]:
    severity_counts = Counter(str(event.get("severity", "low")) for event in events)
    open_services = sum(1 for item in exposure if item.get("exposure") == "open")
    critical_assets = len({
        item.get("target_ip")
        for item in exposure
        if int(item.get("risk") or 0) >= 90
    })
    max_risk = max((_priority_score(event) for event in events), default=0)
    return {
        "total_events": len(events),
        "campaigns": len(campaigns),
        "high_or_critical": severity_counts["high"] + severity_counts["critical"],
        "open_services": open_services,
        "critical_assets": critical_assets,
        "max_risk_score": max_risk,
        "severity_counts": dict(severity_counts),
    }


def _campaign_dossiers(
    events: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    exposure: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events_by_campaign: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exposure_by_campaign: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        events_by_campaign[str(event.get("campaign_id") or "")].append(event)
    for item in exposure:
        exposure_by_campaign[str(item.get("campaign_id") or "")].append(item)

    dossiers = []
    for campaign in campaigns:
        campaign_id = str(campaign.get("campaign_id") or "")
        campaign_events = sorted(
            events_by_campaign.get(campaign_id, []),
            key=_priority_score,
            reverse=True,
        )
        representative = campaign_events[0] if campaign_events else None
        campaign_exposure = exposure_by_campaign.get(campaign_id, [])
        if representative is None:
            continue
        dossier = _event_dossier(representative)
        dossier.update(
            {
                "campaign_id": campaign_id,
                "case_id": _case_id_label(campaign_id),
                "event_count": campaign.get("event_count", 0),
                "sources": campaign.get("sources", []),
                "targets": campaign.get("targets", []),
                "ports": campaign.get("ports", []),
                "exposure": _exposure_rows(campaign_exposure),
                "scope": _scope_label(campaign),
                "primary_objective": _primary_objective(representative),
                "discovery": _discovery_summary(representative, campaign_exposure),
            }
        )
        dossier["triage"] = _campaign_triage(dossier, campaign_exposure, campaign_events)
        dossiers.append(dossier)

    return sorted(
        dossiers,
        key=lambda item: (
            -SEVERITY_WEIGHT.get(str(item.get("severity", "low")), 0),
            -int(item.get("priority_score") or 0),
            str(item.get("campaign_id", "")),
        ),
    )


def _priority_score(event: dict[str, Any]) -> int:
    return max(int(event.get("risk_score") or 0), int(event.get("criticality") or 0))


def _event_dossier(event: dict[str, Any]) -> dict[str, Any]:
    services = event.get("services") or []
    categories = event.get("service_categories") or []
    return {
        "id": event.get("id"),
        "campaign_id": event.get("campaign_id"),
        "case_id": _case_id_label(str(event.get("campaign_id") or "")),
        "severity": event.get("severity", "low"),
        "risk_score": int(event.get("risk_score") or 0),
        "criticality": int(event.get("criticality") or 0),
        "criticality_reasons": event.get("criticality_reasons") or [],
        "priority_score": _priority_score(event),
        "confidence": float(event.get("confidence") or 0),
        "hypothesis": event.get("hypothesis", "Reconhecimento de superfície de rede"),
        "intent": event.get("intent", ""),
        "source_ip": event.get("source_ip", ""),
        "target_ip": event.get("target_ip", ""),
        "sources": event.get("sources") or [],
        "targets": event.get("targets") or [],
        "ports": event.get("ports") or [],
        "protocol": event.get("protocol", "unknown"),
        "scan_types": event.get("scan_types") or [],
        "mitre_technique": event.get("mitre_technique", ""),
        "services": services,
        "service_categories": categories,
        "service_family_labels": [CATEGORY_LABELS.get(item, item) for item in categories],
        "attack_surface": _attack_surface_summary(categories, services),
        "impact_summary": _impact_summary(categories),
        "evidence": event.get("evidence") or [],
        "recommendations": event.get("recommendations") or [],
        "duration_seconds": event.get("duration_seconds", 0),
        "packets_per_second": event.get("packets_per_second", 0),
        "packet_count": event.get("packet_count", 0),
        "first_seen": event.get("first_seen"),
        "last_seen": event.get("last_seen"),
    }


def _exposure_rows(exposure: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in exposure:
        rows.append(
            {
                "target_ip": item.get("target_ip", ""),
                "service": item.get("service", "serviço não catalogado"),
                "port": int(item.get("port") or 0),
                "protocol": item.get("protocol", "unknown"),
                "category": item.get("category", "generic"),
                "category_label": CATEGORY_LABELS.get(str(item.get("category")), str(item.get("category"))),
                "exposure": item.get("exposure", "unknown"),
                "exposure_label": EXPOSURE_LABELS.get(str(item.get("exposure")), str(item.get("exposure"))),
                "risk": int(item.get("risk") or 0),
                "source_ip": item.get("source_ip", ""),
                "campaign_id": item.get("campaign_id", ""),
            }
        )
    return rows


def _scope_label(campaign: dict[str, Any]) -> str:
    source_count = len(campaign.get("sources") or [])
    target_count = len(campaign.get("targets") or [])
    port_count = len(campaign.get("ports") or [])
    return f"{source_count} origem(ns), {target_count} destino(s), {port_count} porta(s)"


def _case_id_label(campaign_id: str) -> str:
    if campaign_id.startswith("CMP-"):
        return f"ID-{campaign_id.removeprefix('CMP-')}"
    return campaign_id or "ID-0000"


def _primary_objective(event: dict[str, Any]) -> str:
    categories = event.get("service_categories") or []
    if not categories:
        return "Mapear superfície de rede sem família predominante."
    labels = [OBJECTIVE_LABELS.get(str(item), str(item)) for item in categories[:3]]
    return f"Mapear {', '.join(labels)}."


def _discovery_summary(event: dict[str, Any], exposure: list[dict[str, Any]]) -> str:
    open_services = [
        f"{item.get('port')}/{str(item.get('protocol')).upper()} {item.get('service')}"
        for item in exposure
        if item.get("exposure") == "open"
    ]
    closed_services = [
        f"{item.get('port')}/{str(item.get('protocol')).upper()} {item.get('service')}"
        for item in exposure
        if item.get("exposure") == "closed"
    ]
    if open_services:
        return f"Possivelmente encontrou serviço exposto: {', '.join(open_services[:3])}."
    if closed_services:
        return f"Confirmou resposta negativa em: {', '.join(closed_services[:3])}."
    ports = event.get("ports") or []
    return f"Avaliou {len(ports)} porta(s), sem confirmação de abertura no tráfego observado."


def _briefing(campaigns: list[dict[str, Any]]) -> dict[str, Any]:
    if not campaigns:
        return {
            "priority": "Nenhuma hipótese de ataque priorizada.",
            "decision": "Aguardar eventos de reconhecimento para análise.",
            "reason": "Não há campanhas persistidas no banco informado.",
        }
    top = campaigns[0]
    triage = top.get("triage") or {}
    return {
        "priority": triage.get("attack_label", top.get("hypothesis", "Ataque provável não classificado.")),
        "decision": triage.get("primary_action", triage.get("decision", "Validar o caso de maior risco.")),
        "reason": triage.get("finding", top.get("discovery", "")),
    }


def _campaign_triage(
    dossier: dict[str, Any],
    exposure: list[dict[str, Any]],
    campaign_events: list[dict[str, Any]],
) -> dict[str, Any]:
    categories = {str(item) for item in dossier.get("service_categories") or []}
    scan_types = {str(item) for item in dossier.get("scan_types") or []}
    services = list(dossier.get("services") or [])
    open_services = [item for item in exposure if item.get("exposure") == "open"]
    closed_services = [item for item in exposure if item.get("exposure") == "closed"]
    critical_services = sorted(
        services,
        key=lambda item: int(item.get("risk") or 0),
        reverse=True,
    )
    post_scan = _contains_any(dossier.get("evidence") or [], ("tráfego de conexão", "trafego de conexao"))
    target = _triage_target_label(dossier)
    source = _triage_source_label(dossier)
    service_focus = _join_limited([_service_ref(item) for item in critical_services], 4)
    open_focus = _join_limited([_service_ref(item) for item in open_services], 3)
    closed_focus = _join_limited([_service_ref(item) for item in closed_services], 2)
    pattern = _pattern_label(scan_types)
    case_type = _case_type(categories, scan_types, services, open_services, post_scan)

    verdict, finding = _case_verdict(
        case_type=case_type,
        dossier=dossier,
        target=target,
        source=source,
        service_focus=service_focus,
        open_focus=open_focus,
        closed_focus=closed_focus,
        open_services=open_services,
        closed_services=closed_services,
        scan_types=scan_types,
        pattern=pattern,
        post_scan=post_scan,
    )

    attempted = _attempted_surface(categories, service_focus, target)
    impact = _impact_summary(list(categories))
    decision = _decision_text(case_type, categories, open_services, scan_types, post_scan)
    evidence = _triage_evidence(dossier, exposure, pattern, open_focus)
    next_steps = _next_steps(case_type, categories, open_services, scan_types, post_scan)
    signal = _short_signal(dossier, exposure, campaign_events)
    attack_label = _attack_label(case_type, categories, scan_types, open_services, services, post_scan)
    attack_hypothesis = _attack_hypothesis_sentence(case_type, categories, target, service_focus, source)
    confirmation_level, confirmation_reason = _confirmation(case_type, scan_types, open_services, post_scan)
    learned = _attacker_learned(case_type, categories, target, open_services, closed_services, scan_types, service_focus)
    limitation = _conclusion_limit(case_type, open_services, post_scan, closed_services)
    primary_action = next_steps[0] if next_steps else decision
    targeted_services = [_service_display(item) for item in services[:8]]
    phase = _attack_phase(case_type, categories, scan_types, open_services, post_scan)
    severity_reason = _severity_reason(case_type, dossier, categories, open_services, scan_types, post_scan)
    missing_confirmation = _missing_confirmation(case_type, categories, open_services, post_scan)
    next_query = _next_query(case_type, categories, dossier, scan_types)
    pivot_queries = _pivot_queries(case_type, dossier, services, scan_types)
    decisive_signal = _decisive_signal(case_type, open_services, post_scan, pattern, open_focus, target, source)
    supporting_context = _supporting_context(case_type, services, closed_services, scan_types, target)
    investigation_checklist = _investigation_checklist(case_type, next_steps, missing_confirmation, pivot_queries)
    service_roles = _service_roles(services)
    operator_focus = _operator_focus(case_type, target, source)
    attacker_objective = _attacker_objective(case_type, target, service_focus, open_focus)
    attacker_next_step = _attacker_next_step(case_type, open_services, post_scan)
    defensive_value = _defensive_value(case_type, source, target)
    business_impact = _business_impact(case_type, impact)
    criticality_context = _criticality_context(dossier)

    return {
        "case_type": case_type,
        "attack_label": attack_label,
        "attack_hypothesis": attack_hypothesis,
        "phase": phase,
        "verdict": verdict,
        "confirmation_level": confirmation_level,
        "confirmation_reason": confirmation_reason,
        "attempted": attempted,
        "finding": finding,
        "decisive_signal": decisive_signal,
        "supporting_context": supporting_context,
        "learned": learned,
        "limitation": limitation,
        "missing_confirmation": missing_confirmation,
        "impact": impact,
        "severity_reason": severity_reason,
        "decision": decision,
        "primary_action": primary_action,
        "next_query": next_query,
        "pivot_queries": pivot_queries,
        "investigation_checklist": investigation_checklist,
        "operator_focus": operator_focus,
        "attacker_objective": attacker_objective,
        "attacker_next_step": attacker_next_step,
        "defensive_value": defensive_value,
        "business_impact": business_impact,
        "criticality_context": criticality_context,
        "evidence": evidence,
        "next_steps": next_steps,
        "signal": signal,
        "pattern": pattern,
        "target": target,
        "source": source,
        "targeted_services": targeted_services,
        "service_roles": service_roles,
    }


def _case_type(
    categories: set[str],
    scan_types: set[str],
    services: list[dict[str, Any]],
    open_services: list[dict[str, Any]],
    post_scan: bool,
) -> str:
    service_names = {str(service.get("service", "")).lower() for service in services}
    if {"remote_access", "windows_admin"} & categories and (open_services or post_scan):
        return "remote_access_validation"
    if "database" in categories and "horizontal_scan" in scan_types and "redis" in service_names:
        return "redis_horizontal_sweep"
    if "devops_infra" in categories and "distributed_scan" in scan_types and any("kubernetes" in name for name in service_names):
        return "kubernetes_api_distributed"
    if "slow_scan" in scan_types and {"devops_infra", "database", "web"} & categories:
        return "slow_platform_inventory"
    if "industrial_iot" in categories and "udp_scan" in scan_types:
        return "udp_ot_probe"
    if "network_device" in categories and "udp_scan" in scan_types:
        return "udp_network_probe"
    if open_services:
        return "open_service_validation"
    if "horizontal_scan" in scan_types:
        return "horizontal_service_hunt"
    if "distributed_scan" in scan_types:
        return "distributed_recon"
    if "slow_scan" in scan_types:
        return "slow_recon"
    return "generic_recon"


def _case_verdict(
    case_type: str,
    dossier: dict[str, Any],
    target: str,
    source: str,
    service_focus: str,
    open_focus: str,
    closed_focus: str,
    open_services: list[dict[str, Any]],
    closed_services: list[dict[str, Any]],
    scan_types: set[str],
    pattern: str,
    post_scan: bool,
) -> tuple[str, str]:
    duration = float(dossier.get("duration_seconds") or 0)
    if case_type == "remote_access_validation":
        return (
            "Ataque de acesso remoto com validação técnica.",
            f"{open_focus} aceitaram conexão; {closed_focus or 'outros serviços administrativos'} também foi testado; houve conexão posterior da origem {source}.",
        )
    if case_type == "redis_horizontal_sweep":
        return (
            "Caça horizontal por Redis exposto.",
            f"A origem {source} testou 6379/TCP Redis em {target}; a captura não confirmou abertura, mas revelou o escopo dos ativos procurados.",
        )
    if case_type == "kubernetes_api_distributed":
        return (
            "API Kubernetes exposta com sondagem distribuída.",
            f"Múltiplas origens testaram 6443/TCP e {open_focus or 'a API Kubernetes'} respondeu como acessível em {target}.",
        )
    if case_type == "slow_platform_inventory":
        return (
            "Inventário lento de superfície DevOps, dados e web.",
            f"A origem {source} distribuiu {len(dossier.get('ports') or [])} testes ao longo de {duration:.0f}s para mapear painéis, APIs e componentes de plataforma.",
        )
    if case_type in {"udp_ot_probe", "udp_network_probe"}:
        return (
            "Sondagem UDP de infraestrutura e protocolo operacional.",
            f"O atacante testou serviços UDP em {target}; {closed_focus or 'ao menos um serviço'} gerou resposta negativa útil para confirmar alcance do ativo.",
        )
    if open_services and post_scan:
        return (
            "Serviço validado com indício de progressão.",
            f"Serviços responderam como abertos ({open_focus}) e houve conexão posterior da mesma origem.",
        )
    if open_services:
        return (
            "Serviço sensível respondeu como aberto.",
            f"O scan confirmou superfície acessível em {target}: {open_focus}.",
        )
    if "horizontal_scan" in scan_types:
        return (
            "Busca por um serviço específico em múltiplos ativos.",
            f"Não confirmou abertura, mas testou {service_focus} em {target}.",
        )
    if "distributed_scan" in scan_types:
        return (
            "Reconhecimento coordenado contra um ponto sensível.",
            f"Múltiplas origens sondaram {service_focus} em {target}.",
        )
    if "slow_scan" in scan_types:
        return (
            "Varredura lenta para reduzir ruído operacional.",
            f"Avaliou serviços críticos ao longo de {duration:.0f}s.",
        )
    if closed_services:
        return (
            "Sondagem com resposta negativa útil para o atacante.",
            f"O alvo respondeu como fechado em {closed_focus}, confirmando que o ativo está alcançável.",
        )
    return (
        "Sondagem relevante sem abertura confirmada.",
        f"O valor está no padrão observado: {pattern} contra {target}.",
    )


def _attack_label(
    case_type: str,
    categories: set[str],
    scan_types: set[str],
    open_services: list[dict[str, Any]],
    services: list[dict[str, Any]],
    post_scan: bool,
) -> str:
    service_names = {str(service.get("service", "")).lower() for service in services}
    if case_type == "remote_access_validation":
        return "Ataque provável: validação de acesso inicial por RDP/SSH"
    if case_type == "redis_horizontal_sweep":
        return "Ataque provável: caça horizontal por Redis exposto"
    if case_type == "kubernetes_api_distributed":
        return "Ataque provável: validação distribuída de API Kubernetes"
    if case_type == "slow_platform_inventory":
        return "Ataque provável: inventário lento de superfície DevOps/Web"
    if case_type == "udp_ot_probe":
        return "Ataque provável: sondagem UDP de rede/OT"
    if {"remote_access", "windows_admin"} & categories:
        if {"rdp", "ssh"} & service_names and (open_services or post_scan):
            return "Ataque provável: acesso inicial por RDP/SSH"
        return "Ataque provável: validação de acesso remoto"
    if "devops_infra" in categories:
        if any("kubernetes" in name for name in service_names):
            return "Ataque provável: enumeração de API Kubernetes"
        if "slow_scan" in scan_types:
            return "Ataque provável: enumeração lenta de infraestrutura"
        return "Ataque provável: busca por APIs de infraestrutura"
    if "database" in categories:
        if any("redis" in name for name in service_names):
            return "Ataque provável: busca por Redis exposto"
        return "Ataque provável: busca por serviços de dados expostos"
    if "industrial_iot" in categories:
        return "Ataque provável: reconhecimento industrial ou IoT"
    if "network_device" in categories:
        return "Ataque provável: reconhecimento de gestão de rede"
    if "web" in categories:
        return "Ataque provável: enumeração de aplicações web"
    return "Ataque provável: descoberta de serviços de rede"


def _attack_hypothesis_sentence(
    case_type: str,
    categories: set[str],
    target: str,
    service_focus: str,
    source: str,
) -> str:
    focus = service_focus or "serviços observados"
    if case_type == "remote_access_validation":
        return f"O atacante tentou separar canais administrativos realmente acessíveis no ativo {target}; RDP/SSH responderam e a origem {source} voltou a conectar depois da descoberta."
    if case_type == "redis_horizontal_sweep":
        return f"O atacante procurou um Redis exposto testando a mesma porta em vários ativos; a utilidade do ataque está em descobrir qual host aceita 6379/TCP."
    if case_type == "kubernetes_api_distributed":
        return f"O atacante tentou validar se a API Kubernetes de {target} está alcançável, distribuindo a sondagem entre origens diferentes para reduzir concentração de ruído."
    if case_type == "slow_platform_inventory":
        return f"O atacante montou um inventário lento de painéis web, APIs de plataforma e serviços de dados no ativo {target}, com foco em {focus}."
    if case_type in {"udp_ot_probe", "udp_network_probe"}:
        return f"O atacante testou serviços UDP de infraestrutura e operação em {target} para descobrir alcance, filtragem e possíveis protocolos expostos."
    if {"remote_access", "windows_admin"} & categories:
        return f"O atacante tentou identificar e validar serviços de acesso remoto e administração no ativo {target}, com foco em {focus}."
    if "devops_infra" in categories:
        return f"O atacante tentou mapear APIs e componentes de infraestrutura no alvo {target}, com foco em {focus}."
    if "database" in categories:
        return f"O atacante tentou localizar serviços de dados expostos em {target}, com foco em {focus}."
    if "industrial_iot" in categories:
        return f"O atacante tentou reconhecer protocolos industriais ou IoT em {target}, com foco em {focus}."
    if "network_device" in categories:
        return f"O atacante tentou mapear serviços de gerenciamento e descoberta de rede em {target}, com foco em {focus}."
    if "web" in categories:
        return f"O atacante tentou enumerar aplicações web, painéis ou portas HTTP alternativas em {target}, com foco em {focus}."
    return f"O atacante tentou descobrir serviços de rede em {target}, com foco em {focus}."


def _attack_phase(
    case_type: str,
    categories: set[str],
    scan_types: set[str],
    open_services: list[dict[str, Any]],
    post_scan: bool,
) -> str:
    if case_type == "remote_access_validation":
        return "Descoberta com validação de acesso inicial"
    if case_type == "redis_horizontal_sweep":
        return "Descoberta horizontal de serviço de dados"
    if case_type == "kubernetes_api_distributed":
        return "Descoberta distribuída de plano de controle"
    if case_type == "slow_platform_inventory":
        return "Reconhecimento lento de plataforma e aplicações"
    if case_type == "udp_ot_probe":
        return "Descoberta UDP de infraestrutura e OT"
    if {"remote_access", "windows_admin"} & categories and (open_services or post_scan):
        return "Descoberta e validação de acesso inicial"
    if "devops_infra" in categories and "distributed_scan" in scan_types:
        return "Reconhecimento distribuído de plano de controle"
    if "devops_infra" in categories and "slow_scan" in scan_types:
        return "Reconhecimento furtivo de infraestrutura"
    if "database" in categories and "horizontal_scan" in scan_types:
        return "Busca horizontal por serviço de dados exposto"
    if "industrial_iot" in categories:
        return "Descoberta de protocolo operacional"
    if "network_device" in categories:
        return "Descoberta de gestão e alcance de rede"
    if "web" in categories:
        return "Enumeração de aplicações e painéis"
    return "Descoberta de serviços"


def _severity_reason(
    case_type: str,
    dossier: dict[str, Any],
    categories: set[str],
    open_services: list[dict[str, Any]],
    scan_types: set[str],
    post_scan: bool,
) -> str:
    severity = str(dossier.get("severity") or "low")
    if case_type == "remote_access_validation":
        return "É crítico porque o ataque validou RDP/SSH como acessíveis e houve conexão posterior da mesma origem, o que muda o caso de simples descoberta para possível preparação de acesso inicial."
    if case_type == "redis_horizontal_sweep":
        return "É médio porque não houve abertura confirmada, mas a varredura horizontal indica procura objetiva por um serviço de dados que costuma ter alto impacto quando exposto."
    if case_type == "kubernetes_api_distributed":
        return "É alto porque uma API de plano de controle respondeu como acessível e a sondagem veio de múltiplas origens, padrão compatível com validação coordenada de exposição."
    if case_type == "slow_platform_inventory":
        return "É alto porque o ataque combina baixa velocidade com portas de Kubernetes, etcd, Kubelet, Elasticsearch e painéis web, reduzindo ruído enquanto mapeia componentes críticos."
    if case_type == "udp_ot_probe":
        return "É médio porque o scan UDP incluiu SNMP e BACnet; mesmo respostas negativas ajudam o atacante a entender alcance, filtragem e presença de superfície operacional."
    reasons = []
    if open_services:
        reasons.append("serviço sensível respondeu como aberto")
    if post_scan:
        reasons.append("houve conexão posterior ao reconhecimento")
    if {"remote_access", "windows_admin"} & categories:
        reasons.append("serviços administrativos podem apoiar acesso inicial ou movimento lateral")
    if "devops_infra" in categories:
        reasons.append("superfície de infraestrutura pode expor controle de plataforma")
    if "database" in categories:
        reasons.append("serviços de dados podem expor informação ou credenciais")
    if "distributed_scan" in scan_types:
        reasons.append("origem distribuída aumenta a relevância da campanha")
    if "slow_scan" in scan_types:
        reasons.append("baixa velocidade pode reduzir detecção por volume")
    label = {
        "critical": "crítico",
        "high": "alto",
        "medium": "médio",
        "low": "baixo",
    }.get(severity, severity)
    if not reasons:
        reasons.append("há padrão de reconhecimento consistente")
    return f"É {label} porque " + "; ".join(reasons[:3]) + "."


def _missing_confirmation(
    case_type: str,
    categories: set[str],
    open_services: list[dict[str, Any]],
    post_scan: bool,
) -> str:
    if case_type == "remote_access_validation":
        return "Confirmar se houve falha ou sucesso de autenticação, sessão RDP/SSH, execução remota ou nova conexão após o scan."
    if case_type == "redis_horizontal_sweep":
        return "Confirmar se algum ativo aceitou conexão Redis, se houve autenticação, comando administrativo, leitura de chave ou tentativa de escrita."
    if case_type == "kubernetes_api_distributed":
        return "Confirmar no audit log se houve chamada anônima, autenticação válida, enumeração de objetos ou resposta 200/401/403 após a descoberta."
    if case_type == "slow_platform_inventory":
        return "Confirmar se algum painel, API ou serviço de dados respondeu depois do scan com página, banner, autenticação, erro 401/403 ou chamada autorizada."
    if case_type == "udp_ot_probe":
        return "Confirmar em firewall, SNMP e BACnet se houve resposta de aplicação, tentativa de enumeração ou tráfego UDP recorrente da mesma origem."
    if {"remote_access", "windows_admin"} & categories:
        return "Para elevar para tentativa de intrusão: encontrar falha/sucesso de autenticação, sessão remota, comando ou payload posterior."
    if "devops_infra" in categories:
        return "Para elevar para intrusão: encontrar chamada autenticada na API, enumeração de objetos, criação de workload ou acesso a segredo."
    if "database" in categories:
        return "Para elevar para intrusão: encontrar autenticação, consulta, dump, alteração de chave ou comando administrativo."
    if "industrial_iot" in categories:
        return "Para elevar para intrusão: encontrar leitura/escrita operacional, alteração de estado ou comando de controle."
    if open_services or post_scan:
        return "Para elevar para intrusão: encontrar autenticação, exploração, payload ou sessão posterior."
    return "Para elevar para ataque confirmado: encontrar resposta aberta, autenticação, exploração ou conexão posterior."


def _next_query(
    case_type: str,
    categories: set[str],
    dossier: dict[str, Any],
    scan_types: set[str],
) -> str:
    source = dossier.get("source_ip") or _join_limited([str(item) for item in dossier.get("sources") or []], 3)
    target = dossier.get("target_ip")
    if case_type == "remote_access_validation":
        return f"Correlacionar {source} -> {target} em 22/TCP e 3389/TCP com eventos Windows 4624/4625/1149 e logs sshd no mesmo intervalo."
    if case_type == "redis_horizontal_sweep":
        return f"Pesquisar {source} -> 6379/TCP nos quatro ativos testados; validar bind, protected-mode, autenticação e regras que permitam Redis fora da rede de aplicação."
    if case_type == "kubernetes_api_distributed":
        return f"Filtrar audit log do Kubernetes em {target} para as origens distribuídas, procurando verbos get/list, respostas 200/401/403 e userAgent no período da sondagem."
    if case_type == "slow_platform_inventory":
        return f"Abrir janela ampliada para {source} -> {target} e agrupar por 80/443/5601/9200/2379/10250/10255; procurar respostas HTTP, 401/403 e chamadas de API."
    if case_type == "udp_ot_probe":
        return f"Filtrar UDP de {source} para {target} em 53/123/161/47808; validar logs/ACL de SNMP e segmentação BACnet antes de descartar o alerta."
    if {"remote_access", "windows_admin"} & categories:
        return f"Windows/RDP: procurar eventos 4624, 4625 e 1149 no ativo {target} para a origem {source}; SSH: revisar auth.log ou journalctl no mesmo período."
    if "devops_infra" in categories:
        if "distributed_scan" in scan_types:
            return "Kubernetes/API: revisar audit log da API para as origens distribuídas e verificar chamadas anônimas ou negadas."
        return f"Infraestrutura: revisar audit logs de Kubernetes/etcd/Kubelet/Kibana no alvo {target} e validar origem permitida."
    if "database" in categories:
        return f"Dados/cache: validar bind, autenticação e origem permitida nos ativos testados; revisar logs de conexão do serviço."
    if "industrial_iot" in categories:
        return f"OT/IoT: verificar logs do gateway/firewall e confirmar se o ativo {target} deveria aceitar esse protocolo."
    if "network_device" in categories:
        return f"Rede: revisar logs de SNMP/DNS/NTP/firewall no alvo {target} e confirmar se a origem {source} é autorizada."
    return f"Consultar firewall/EDR para conexões da origem {source} ao alvo {target} após o reconhecimento."


def _decisive_signal(
    case_type: str,
    open_services: list[dict[str, Any]],
    post_scan: bool,
    pattern: str,
    open_focus: str,
    target: str,
    source: str,
) -> str:
    if case_type == "remote_access_validation":
        return f"{open_focus} responderam como abertos, e a origem {source} realizou conexão posterior."
    if case_type == "redis_horizontal_sweep":
        return f"A mesma origem testou 6379/TCP Redis em múltiplos ativos; isso indica busca horizontal por uma exposição específica."
    if case_type == "kubernetes_api_distributed":
        return f"{open_focus or '6443/TCP Kubernetes API'} respondeu como acessível enquanto a sondagem partiu de múltiplas origens."
    if case_type == "slow_platform_inventory":
        return f"Baixa velocidade com portas de plataforma e web no mesmo alvo: {pattern} contra {target}."
    if case_type == "udp_ot_probe":
        return f"Portas UDP de rede/OT foram testadas e houve resposta negativa útil, confirmando que {target} é alcançável."
    if open_services and post_scan:
        return f"{open_focus} responderam como abertos e a mesma origem fez conexão posterior."
    if open_services:
        return f"{open_focus} responderam como abertos em {target}."
    return f"Padrão de reconhecimento observado: {pattern} contra {target}."


def _supporting_context(
    case_type: str,
    services: list[dict[str, Any]],
    closed_services: list[dict[str, Any]],
    scan_types: set[str],
    target: str,
) -> str:
    critical = [
        _service_ref(service)
        for service in services
        if int(service.get("risk") or 0) >= 80
    ]
    closed = _join_limited([_service_ref(service) for service in closed_services], 2)
    if case_type == "remote_access_validation":
        return f"SMB/WinRM também apareceram no conjunto, reforçando foco em administração Windows e movimento lateral, não apenas em uma porta isolada."
    if case_type == "redis_horizontal_sweep":
        return "O padrão é estreito e objetivo: uma porta sensível repetida em vários ativos, típico de busca por exceção mal exposta."
    if case_type == "kubernetes_api_distributed":
        return "A distribuição de origem reduz dependência de um único IP e pode tentar diluir bloqueios ou alertas por volume."
    if case_type == "slow_platform_inventory":
        return f"O conjunto mistura painéis HTTP, Elasticsearch, etcd e Kubelet; isso sugere inventário de plataforma, não navegação web comum."
    if case_type == "udp_ot_probe":
        return "DNS/NTP/SNMP/BACnet no mesmo caso combinam descoberta de rede com possível superfície operacional."
    if closed:
        return f"Também houve resposta fechada em {closed}, reforçando que {target} estava alcançável."
    if "horizontal_scan" in scan_types:
        return "A mesma porta foi testada em múltiplos ativos, comportamento típico de busca por exposição específica."
    if "distributed_scan" in scan_types:
        return "Múltiplas origens sondaram o mesmo alvo, indicando campanha coordenada ou origem distribuída."
    if "slow_scan" in scan_types:
        return "A baixa taxa reduz ruído e pode evitar alertas baseados apenas em volume."
    if critical:
        return f"Serviços sensíveis também foram testados: {_join_limited(critical, 4)}."
    return "O contexto reforça reconhecimento, mas não adiciona confirmação de exploração."


def _investigation_checklist(
    case_type: str,
    next_steps: list[str],
    missing_confirmation: str,
    pivot_queries: list[str],
) -> list[str]:
    if case_type == "remote_access_validation":
        leading = [
            "Validar se a origem é uma estação administrativa autorizada.",
            "Confirmar se RDP/SSH deveriam estar acessíveis no ativo.",
            "Correlacionar falhas, sucessos e sessões remotas no período do scan.",
        ]
    elif case_type == "redis_horizontal_sweep":
        leading = [
            "Verificar se algum dos ativos testados deveria expor Redis na rede observada.",
            "Validar bind, autenticação e protected-mode dos serviços Redis.",
            "Pesquisar o mesmo padrão em outros segmentos para medir alcance da campanha.",
        ]
    elif case_type == "kubernetes_api_distributed":
        leading = [
            "Confirmar se 6443/TCP está restrito à rede administrativa.",
            "Revisar audit log por chamadas anônimas, negadas ou autenticadas.",
            "Agrupar as origens para bloqueio, reputação e recorrência.",
        ]
    elif case_type == "slow_platform_inventory":
        leading = [
            "Expandir a janela de análise para capturar a baixa taxa do ataque.",
            "Checar logs de painéis, Elasticsearch, etcd e Kubelet.",
            "Validar se esses serviços deveriam coexistir e estar acessíveis no alvo.",
        ]
    elif case_type == "udp_ot_probe":
        leading = [
            "Confirmar se UDP 161 e 47808 são esperados no segmento.",
            "Revisar ACLs, comunidade SNMP e segmentação BACnet.",
            "Verificar se houve novas sondagens UDP após a resposta negativa.",
        ]
    else:
        leading = []
    checklist = list(dict.fromkeys(leading + next_steps + pivot_queries[:1] + [
        "Confirmar se a origem é autorizada para varredura.",
        "Validar se a exposição do serviço é esperada.",
        missing_confirmation,
    ]))
    return checklist[:5]


def _service_roles(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    roles: dict[str, list[str]] = {}
    for service in services:
        name = str(service.get("service") or "")
        category = str(service.get("category") or "")
        label = _service_display(service)
        role = _service_role(name, category)
        roles.setdefault(role, []).append(label)
    return [
        {"role": role, "services": values}
        for role, values in roles.items()
    ]


def _service_role(service_name: str, category: str) -> str:
    normalized = service_name.lower()
    if normalized in {"ssh", "rdp", "telnet", "vnc"}:
        return "Entrada remota"
    if normalized in {"smb", "winrm http", "winrm https", "ms rpc"} or category == "windows_admin":
        return "Administração e movimento lateral"
    if category == "devops_infra":
        return "Controle de infraestrutura"
    if category == "database":
        return "Dados e cache"
    if category == "web":
        return "Aplicações e painéis web"
    if category in {"network_device", "name_resolution"}:
        return "Gestão e descoberta de rede"
    if category == "industrial_iot":
        return "Protocolos operacionais"
    return "Superfície auxiliar"


def _confirmation(
    case_type: str,
    scan_types: set[str],
    open_services: list[dict[str, Any]],
    post_scan: bool,
) -> tuple[str, str]:
    if case_type == "remote_access_validation":
        return (
            "Forte",
            "há resposta aberta em serviço de acesso remoto e conexão posterior da mesma origem",
        )
    if case_type == "kubernetes_api_distributed" and open_services:
        return (
            "Forte",
            "a API Kubernetes respondeu como acessível e o padrão veio de origens distribuídas",
        )
    if case_type in {"redis_horizontal_sweep", "slow_platform_inventory", "udp_ot_probe"}:
        return (
            "Moderada",
            "o padrão de ataque é claro, mas ainda falta evidência de autenticação, exploração ou resposta de aplicação",
        )
    if open_services and post_scan:
        return (
            "Forte",
            "houve resposta compatível com serviço aberto e conexão posterior da mesma origem",
        )
    if open_services:
        return (
            "Forte",
            "o tráfego contém resposta compatível com serviço aberto",
        )
    if "distributed_scan" in scan_types or "horizontal_scan" in scan_types or "slow_scan" in scan_types:
        return (
            "Moderada",
            "o padrão de varredura é consistente, mas sem abertura confirmada",
        )
    return (
        "Parcial",
        "há sondagem relevante, mas a captura não confirma serviço aberto",
    )


def _attacker_learned(
    case_type: str,
    categories: set[str],
    target: str,
    open_services: list[dict[str, Any]],
    closed_services: list[dict[str, Any]],
    scan_types: set[str],
    service_focus: str,
) -> str:
    open_focus = _join_limited([_service_ref(item) for item in open_services], 3)
    closed_focus = _join_limited([_service_ref(item) for item in closed_services], 2)
    if case_type == "remote_access_validation":
        return f"O atacante aprendeu que {target} expõe canais úteis para tentativa de credenciais ou sessão remota: {open_focus}."
    if case_type == "redis_horizontal_sweep":
        return f"O atacante aprendeu quais ativos foram alcançáveis na busca por Redis, mesmo sem confirmação de serviço aberto na captura."
    if case_type == "kubernetes_api_distributed":
        return f"O atacante aprendeu que {target} responde em 6443/TCP e pode ser priorizado para teste de autenticação ou enumeração de API."
    if case_type == "slow_platform_inventory":
        return f"O atacante aprendeu a composição provável do ativo: superfície web, observabilidade, dados e componentes de plataforma no mesmo endereço."
    if case_type == "udp_ot_probe":
        return f"O atacante aprendeu que {target} é alcançável por UDP e recebeu sinal de filtragem/fechamento em serviço sensível."
    if open_focus:
        return f"O atacante provavelmente aprendeu que {target} aceita conexão em {open_focus}."
    if "horizontal_scan" in scan_types:
        return f"O atacante não confirmou abertura, mas mapeou onde procurar {service_focus}."
    if "distributed_scan" in scan_types:
        return f"O atacante confirmou que {target} é alcançável por múltiplas origens."
    if "slow_scan" in scan_types:
        return f"O atacante testou superfície sensível em baixa velocidade para reduzir ruído."
    if closed_focus:
        return f"O atacante aprendeu que {target} está alcançável, embora {closed_focus} tenha respondido fechado."
    if "devops_infra" in categories:
        return f"O atacante validou a existência de superfície de infraestrutura em {target}."
    return f"O atacante obteve sinal de alcance e perfil inicial de serviços em {target}."


def _conclusion_limit(
    case_type: str,
    open_services: list[dict[str, Any]],
    post_scan: bool,
    closed_services: list[dict[str, Any]],
) -> str:
    if case_type == "remote_access_validation":
        return "Confirma descoberta e conexão posterior; ainda não confirma login, comando remoto ou comprometimento."
    if case_type == "redis_horizontal_sweep":
        return "Confirma busca dirigida por Redis; não confirma que algum Redis aceitou conexão ou comando."
    if case_type == "kubernetes_api_distributed":
        return "Confirma alcance da API; não confirma credencial válida, enumeração de objetos ou alteração no cluster."
    if case_type == "slow_platform_inventory":
        return "Confirma inventário lento de portas sensíveis; não confirma banner, autenticação ou exploração de aplicação."
    if case_type == "udp_ot_probe":
        return "Confirma alcance e resposta de rede; não confirma protocolo OT ativo nem comando operacional."
    if post_scan:
        return "Confirma reconhecimento e progressão de conexão; não confirma autenticação bem-sucedida."
    if open_services:
        return "Confirma serviço acessível no tráfego observado; não confirma exploração ou login."
    if closed_services:
        return "Confirma alcance do ativo e resposta negativa; não confirma serviço explorável."
    return "Confirma tentativa de reconhecimento; não confirma serviço aberto nem comprometimento."


def _service_display(item: dict[str, Any]) -> str:
    service = str(item.get("service") or "Serviço")
    port = item.get("port")
    protocol = str(item.get("protocol") or "").upper()
    exposure = str(item.get("exposure") or "unknown")
    state = {
        "open": "aberto",
        "closed": "fechado",
        "attempted": "testado",
        "filtered_or_inconclusive": "inconclusivo",
    }.get(exposure, "desconhecido")
    return f"{service} {port}/{protocol} ({state})"


def _criticality_context(dossier: dict[str, Any]) -> str:
    criticality = int(dossier.get("criticality") or 0)
    reasons = [str(item) for item in dossier.get("criticality_reasons") or [] if item]
    if not criticality and not reasons:
        return "Sem ajuste adicional de reputação, whitelist ou blacklist neste caso."
    if reasons:
        return f"Criticidade {criticality}/100 calculada por: {_join_limited(reasons, 4)}."
    return f"Criticidade operacional calculada em {criticality}/100."


def _operator_focus(case_type: str, target: str, source: str) -> str:
    if case_type == "remote_access_validation":
        return f"Investigar {source} contra {target} como ataque de acesso remoto, não apenas como varredura."
    if case_type == "redis_horizontal_sweep":
        return "Medir quais ativos foram procurados para Redis e eliminar exposição lateral indevida."
    if case_type == "kubernetes_api_distributed":
        return f"Confirmar se {target} expõe API Kubernetes a origens não administrativas."
    if case_type == "slow_platform_inventory":
        return "Reconstruir a janela completa do reconhecimento lento e identificar respostas de plataforma."
    if case_type == "udp_ot_probe":
        return "Validar se UDP de rede/OT está segmentado e se a resposta negativa revelou alcance ao atacante."
    return f"Validar se {source} tinha justificativa para sondar {target}."


def _attacker_objective(case_type: str, target: str, service_focus: str, open_focus: str) -> str:
    if case_type == "remote_access_validation":
        return f"Encontrar canais de acesso inicial no ativo e priorizar os que aceitaram conexão: {open_focus}."
    if case_type == "redis_horizontal_sweep":
        return "Descobrir rapidamente se existe algum Redis exposto entre vários ativos, sem mapear a superfície inteira."
    if case_type == "kubernetes_api_distributed":
        return "Validar se o plano de controle Kubernetes responde externamente e pode receber chamadas de API."
    if case_type == "slow_platform_inventory":
        return f"Montar inventário de painéis, APIs, dados e componentes de plataforma em {target}: {service_focus}."
    if case_type == "udp_ot_probe":
        return "Entender quais serviços UDP respondem, quais estão filtrados e se há protocolo operacional alcançável."
    return f"Mapear serviços úteis para uma etapa posterior em {target}: {service_focus or 'portas observadas'}."


def _attacker_next_step(case_type: str, open_services: list[dict[str, Any]], post_scan: bool) -> str:
    if case_type == "remote_access_validation":
        return "Tentar autenticação, reutilização de credenciais ou nova sessão remota nos serviços que responderam."
    if case_type == "redis_horizontal_sweep":
        return "Retornar aos hosts que responderem em 6379/TCP para testar autenticação, comandos administrativos ou acesso a dados."
    if case_type == "kubernetes_api_distributed":
        return "Testar autenticação da API, chamadas anônimas/negadas e enumeração básica de objetos do cluster."
    if case_type == "slow_platform_inventory":
        return "Priorizar endpoints que retornarem página, banner, 401/403 ou API para enumeração mais específica."
    if case_type == "udp_ot_probe":
        return "Repetir UDP contra serviços que não bloquearam claramente ou tentar enumeração de SNMP/BACnet se houver resposta."
    if open_services:
        return "Voltar aos serviços abertos para autenticação, enumeração ou teste de versão."
    if post_scan:
        return "Usar a conexão posterior para validar se o serviço descoberto aceita interação real."
    return "Usar o mapa de portas como base para nova sondagem mais direcionada."


def _defensive_value(case_type: str, source: str, target: str) -> str:
    if case_type == "remote_access_validation":
        return f"Direciona a investigação para autenticação e sessão remota de {source} no ativo {target}."
    if case_type == "redis_horizontal_sweep":
        return "Ajuda a revisar controles de exposição por serviço, porque o ataque procura uma falha pontual em vários hosts."
    if case_type == "kubernetes_api_distributed":
        return "Permite validar exposição de plano de controle, origem distribuída e respostas do audit log em um único fluxo."
    if case_type == "slow_platform_inventory":
        return "Evita descartar o caso por baixo volume e força análise por janela, sequência e criticidade das portas."
    if case_type == "udp_ot_probe":
        return "Mostra que respostas fechadas também são evidência, pois confirmam alcance e comportamento de filtragem."
    return "Converte portas observadas em perguntas defensivas verificáveis."


def _business_impact(case_type: str, fallback: str) -> str:
    if case_type == "remote_access_validation":
        return "Se confirmado, pode indicar preparação para acesso inicial, tentativa de credenciais ou movimento lateral."
    if case_type == "redis_horizontal_sweep":
        return "Se houver Redis exposto, o impacto potencial envolve dados em cache, segredos, filas e alteração indevida de chaves."
    if case_type == "kubernetes_api_distributed":
        return "Se confirmado, pode expor controle de cluster, enumeração de workloads, segredos e ações no plano de controle."
    if case_type == "slow_platform_inventory":
        return "Se algum componente responder indevidamente, o impacto pode envolver observabilidade, dados, configuração e controle de plataforma."
    if case_type == "udp_ot_probe":
        return "Se houver exposição operacional, pode revelar inventário de rede, telemetria ou sistemas de automação."
    return fallback


def _pivot_queries(
    case_type: str,
    dossier: dict[str, Any],
    services: list[dict[str, Any]],
    scan_types: set[str],
) -> list[str]:
    source = _triage_source_label(dossier)
    target = _triage_target_label(dossier)
    if case_type == "remote_access_validation":
        return [
            f"Windows: filtrar eventos 4624, 4625 e 1149 no ativo {target} para a origem {source}.",
            "SSH: revisar auth.log ou journalctl para falhas, sucesso e início de sessão no mesmo período.",
            "Rede: procurar conexões pós-scan da mesma origem para 22/TCP, 3389/TCP, 445/TCP e 5985/TCP.",
        ]
    if case_type == "redis_horizontal_sweep":
        return [
            f"Firewall: pesquisar {source} para 6379/TCP nos ativos do caso e em segmentos vizinhos.",
            "Redis: validar bind, requirepass, protected-mode e logs de conexão dos ativos testados.",
            "Inventário: confirmar quais aplicações realmente deveriam acessar Redis nesses hosts.",
        ]
    if case_type == "kubernetes_api_distributed":
        return [
            f"Kubernetes audit: filtrar sourceIPs do caso contra {target}, verbos get/list e respostas 200/401/403.",
            "Rede: agrupar as origens distribuídas e verificar bloqueios, reputação e recorrência no perímetro.",
            "Controle: validar se 6443/TCP está restrito a VPN, bastion ou rede administrativa.",
        ]
    if case_type == "slow_platform_inventory":
        return [
            f"Firewall/proxy: agrupar conexões de {source} para {target} em janela ampliada e ordenar por horário.",
            "HTTP/plataforma: procurar respostas 200/301/401/403 em Kibana, Elasticsearch, etcd, Kubelet e portas web.",
            "Inventário: confirmar se o ativo deveria concentrar painéis, APIs de plataforma e serviços de dados.",
        ]
    if case_type == "udp_ot_probe":
        return [
            f"Firewall: filtrar UDP de {source} para {target} nas portas 53, 123, 161 e 47808.",
            "SNMP: revisar comunidade, versão, ACL e logs de negação ou timeout.",
            "BACnet/OT: confirmar segmentação e se o ativo pertence a rede operacional.",
        ]
    if "distributed_scan" in scan_types:
        return [f"Agrupar origens contra {target} e comparar recorrência, reputação e bloqueios."]
    service_focus = _join_limited([_service_ref(service) for service in services], 4)
    return [f"Consultar firewall, EDR e logs do ativo para {source} -> {target} em {service_focus or 'portas observadas'}."]


def _attempted_surface(categories: set[str], service_focus: str, target: str) -> str:
    if {"remote_access", "windows_admin"} & categories:
        return f"Acesso remoto e administração do ativo {target}: {service_focus}."
    if "devops_infra" in categories:
        return f"Plano de controle, APIs e componentes de infraestrutura em {target}: {service_focus}."
    if "database" in categories:
        return f"Serviços de dados, caches ou mecanismos de busca em {target}: {service_focus}."
    if "industrial_iot" in categories:
        return f"Protocolos industriais ou IoT em {target}: {service_focus}."
    if "network_device" in categories:
        return f"Gerenciamento, monitoramento ou descoberta de rede em {target}: {service_focus}."
    if "web" in categories:
        return f"Aplicações web, painéis e portas HTTP alternativas em {target}: {service_focus}."
    return f"Superfície de rede em {target}: {service_focus or 'portas observadas'}."


def _decision_text(
    case_type: str,
    categories: set[str],
    open_services: list[dict[str, Any]],
    scan_types: set[str],
    post_scan: bool,
) -> str:
    if case_type == "remote_access_validation":
        return "Investigar como possível preparação de acesso inicial e validar imediatamente origem, logs de autenticação e exposição de RDP/SSH."
    if case_type == "redis_horizontal_sweep":
        return "Tratar como busca objetiva por exposição de dados; verificar os quatro ativos e bloquear Redis fora das origens esperadas."
    if case_type == "kubernetes_api_distributed":
        return "Priorizar validação da exposição da API Kubernetes e revisar audit log antes de encerrar como simples scan."
    if case_type == "slow_platform_inventory":
        return "Analisar em janela ampliada e verificar logs de plataforma; baixa taxa não deve reduzir prioridade quando os serviços são críticos."
    if case_type == "udp_ot_probe":
        return "Validar segmentação e exposição UDP de SNMP/BACnet; resposta negativa ainda é informação útil para o atacante."
    if post_scan:
        return "Tratar como prioridade de investigação, pois houve atividade após a descoberta do serviço."
    if open_services and ({"remote_access", "windows_admin"} & categories):
        return "Validar origem autorizada e revisar autenticações no ativo antes de encerrar o alerta."
    if open_services and "devops_infra" in categories:
        return "Confirmar se a API está restrita; exposição desse tipo deve ser bloqueada ou justificada."
    if open_services:
        return "Confirmar exposição real do serviço e aplicar restrição de origem se não houver autorização."
    if "horizontal_scan" in scan_types:
        return "Procurar o mesmo padrão em firewall e inventário; a intenção é encontrar onde o serviço existe."
    if "slow_scan" in scan_types:
        return "Analisar janela ampliada; a baixa taxa não deve ser tratada como ruído isolado."
    return "Validar se a origem pertence a ferramenta autorizada e acompanhar novas conexões ao alvo."


def _next_steps(
    case_type: str,
    categories: set[str],
    open_services: list[dict[str, Any]],
    scan_types: set[str],
    post_scan: bool,
) -> list[str]:
    if case_type == "remote_access_validation":
        return [
            "Verificar autenticação RDP/SSH no ativo durante e após o scan.",
            "Confirmar se a origem é administrativa e se a exposição de RDP/SSH é esperada.",
            "Procurar conexões posteriores da mesma origem para identificar progressão.",
        ]
    if case_type == "redis_horizontal_sweep":
        return [
            "Validar nos ativos testados se Redis está vinculado apenas a interfaces e redes esperadas.",
            "Revisar logs de conexão e autenticação Redis para a origem observada.",
            "Pesquisar a mesma porta em outros ativos para medir o alcance do ataque.",
        ]
    if case_type == "kubernetes_api_distributed":
        return [
            "Revisar audit log da API Kubernetes para as origens observadas.",
            "Confirmar se 6443/TCP está exposto somente para rede administrativa.",
            "Verificar respostas 200/401/403 e userAgent após a sondagem.",
        ]
    if case_type == "slow_platform_inventory":
        return [
            "Expandir a janela de análise para capturar a cadência lenta do ataque.",
            "Checar logs de Kibana, Elasticsearch, etcd, Kubelet e proxies HTTP.",
            "Validar se o ativo deveria expor esse conjunto de serviços de plataforma.",
        ]
    if case_type == "udp_ot_probe":
        return [
            "Validar se SNMP e BACnet são esperados no segmento e no ativo.",
            "Revisar ACLs, comunidades SNMP e segmentação de protocolos operacionais.",
            "Procurar novas sondagens UDP da mesma origem após o retorno fechado.",
        ]
    steps = []
    if open_services:
        steps.append("Confirmar no ativo se os serviços marcados como abertos deveriam estar acessíveis.")
    if {"remote_access", "windows_admin"} & categories:
        steps.append("Revisar logs de autenticação, falhas de login e sessões remotas no período do scan.")
    elif "devops_infra" in categories:
        steps.append("Verificar autenticação, TLS, origem permitida e logs da API de infraestrutura.")
    elif "database" in categories:
        steps.append("Checar se bancos ou caches aceitam conexão apenas de redes esperadas.")
    elif "industrial_iot" in categories:
        steps.append("Validar segmentação de rede e exposição dos protocolos operacionais.")
    else:
        steps.append("Correlacionar a origem com firewall, EDR ou inventário de ferramentas autorizadas.")
    if "horizontal_scan" in scan_types:
        steps.append("Pesquisar outros ativos com a mesma porta testada para medir o alcance da campanha.")
    elif "distributed_scan" in scan_types:
        steps.append("Agrupar as origens e verificar bloqueios, reputação e recorrência no perímetro.")
    elif "slow_scan" in scan_types:
        steps.append("Expandir a janela de análise para antes e depois do alerta.")
    elif post_scan:
        steps.append("Investigar conexões subsequentes da mesma origem como possível progressão.")
    else:
        steps.append("Manter a origem em observação para tentativas após o reconhecimento.")
    return steps[:3]


def _triage_evidence(
    dossier: dict[str, Any],
    exposure: list[dict[str, Any]],
    pattern: str,
    open_focus: str,
) -> list[str]:
    ports = dossier.get("ports") or []
    duration = float(dossier.get("duration_seconds") or 0)
    evidence = [
        f"{len(ports)} porta(s) em {duration:.1f}s; padrão: {pattern}.",
        f"Escopo observado: {dossier.get('scope', 'não informado')}.",
    ]
    if open_focus:
        evidence.append(f"Resposta compatível com serviço aberto: {open_focus}.")
    elif exposure:
        top = sorted(exposure, key=lambda item: int(item.get("risk") or 0), reverse=True)[0]
        evidence.append(f"Serviço mais sensível testado: {_service_ref(top)} em {top.get('target_ip')}.")
    else:
        evidence.append("Nenhum serviço aberto foi confirmado no tráfego observado.")
    return evidence


def _short_signal(
    dossier: dict[str, Any],
    exposure: list[dict[str, Any]],
    campaign_events: list[dict[str, Any]],
) -> str:
    open_count = sum(1 for item in exposure if item.get("exposure") == "open")
    targets = len(dossier.get("targets") or [])
    events = len(campaign_events)
    if open_count:
        return f"{open_count} serviço(s) aberto(s), {targets} alvo(s), {events} evento(s)."
    return f"{targets} alvo(s), {len(dossier.get('ports') or [])} porta(s), {events} evento(s)."


def _pattern_label(scan_types: set[str]) -> str:
    labels = []
    if "horizontal_scan" in scan_types:
        labels.append("horizontal")
    if "distributed_scan" in scan_types:
        labels.append("origem distribuída")
    if "slow_scan" in scan_types:
        labels.append("baixa velocidade")
    if "udp_scan" in scan_types:
        labels.append("UDP")
    if "syn_scan" in scan_types:
        labels.append("SYN")
    if not labels:
        labels.extend(sorted(scan_types) or ["scan"])
    return ", ".join(labels)


def _triage_target_label(dossier: dict[str, Any]) -> str:
    targets = [str(item) for item in dossier.get("targets") or [] if item]
    if not targets:
        target = str(dossier.get("target_ip") or "*")
        return "múltiplos ativos" if target == "*" else target
    if len(targets) == 1:
        return targets[0]
    return f"{len(targets)} ativos ({_join_limited(targets, 3)})"


def _triage_source_label(dossier: dict[str, Any]) -> str:
    sources = [str(item) for item in dossier.get("sources") or [] if item]
    if not sources:
        source = str(dossier.get("source_ip") or "*")
        return "múltiplas origens" if source == "*" else source
    if len(sources) == 1:
        return sources[0]
    return f"{len(sources)} origens ({_join_limited(sources, 3)})"


def _service_ref(item: dict[str, Any]) -> str:
    port = item.get("port")
    protocol = str(item.get("protocol") or "").upper()
    service = item.get("service") or "serviço"
    return f"{port}/{protocol} {service}"


def _join_limited(values: list[str], limit: int) -> str:
    clean_values = [value for value in values if value]
    if not clean_values:
        return ""
    visible = clean_values[:limit]
    suffix = "" if len(clean_values) <= limit else f" +{len(clean_values) - limit}"
    return ", ".join(visible) + suffix


def _contains_any(values: list[Any], needles: tuple[str, ...]) -> bool:
    text = " ".join(str(value).lower() for value in values)
    return any(needle.lower() in text for needle in needles)


def _attack_surface_summary(categories: list[str], services: list[dict[str, Any]]) -> str:
    family_labels = [
        OBJECTIVE_LABELS.get(str(category), str(category))
        for category in categories[:2]
    ]
    critical_services = [
        f"{service.get('port')}/{str(service.get('protocol')).upper()} {service.get('service')}"
        for service in services
        if int(service.get("risk") or 0) >= 80
    ]
    surface = ", ".join(family_labels) if family_labels else "superfície de rede"
    if critical_services:
        return f"{surface}; foco técnico em {', '.join(critical_services[:4])}."
    return surface


def _impact_summary(categories: list[str]) -> str:
    category_set = {str(category) for category in categories}
    if {"remote_access", "windows_admin"} & category_set:
        return "Pode apoiar acesso inicial, tentativa de credenciais ou movimento lateral."
    if "devops_infra" in category_set:
        return "Pode expor controle de plataforma, configuração sensível ou workloads."
    if "database" in category_set:
        return "Pode indicar busca por dados, credenciais, caches ou bases expostas."
    if "industrial_iot" in category_set:
        return "Pode afetar telemetria, automação ou ativos operacionais sensíveis."
    if "network_device" in category_set:
        return "Pode revelar topologia, gestão de rede ou interfaces administrativas."
    if "web" in category_set:
        return "Pode anteceder enumeração de aplicações, painéis e rotas administrativas."
    return "Pode orientar seleção posterior de alvos e serviços vulneráveis."


_HTML = r"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Console de Reconhecimento</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --surface: #ffffff;
      --surface-2: #f8fafb;
      --ink: #17212b;
      --muted: #5d6b78;
      --line: #d9e1e7;
      --line-strong: #c3ced8;
      --teal: #0f766e;
      --blue: #2563eb;
      --red: #b42318;
      --amber: #986a16;
      --green: #1d7a4d;
      --critical: #b42318;
      --critical-bg: #fff4f2;
      --high: #986a16;
      --high-bg: #fff8e8;
      --medium: #1b5d8f;
      --medium-bg: #eef6ff;
      --low: #24724f;
      --low-bg: #eef8f3;
      --shadow: 0 12px 24px rgba(23, 33, 43, 0.07);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }

    button {
      font: inherit;
    }

    .app {
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr;
    }

    header {
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      padding: 18px 28px;
      position: sticky;
      top: 0;
      z-index: 5;
    }

    .topline {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      max-width: 1480px;
      margin: 0 auto;
    }

    .title-block {
      max-width: 920px;
    }

    h1 {
      margin: 0;
      font-size: 25px;
      font-weight: 760;
      letter-spacing: 0;
    }

    .subtitle {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 14px;
    }

    .refresh {
      min-height: 38px;
      border: 1px solid #0d5d56;
      background: var(--teal);
      color: #fff;
      border-radius: 6px;
      padding: 0 14px;
      font-weight: 720;
      cursor: pointer;
      white-space: nowrap;
    }

    .refresh:hover {
      background: #0b5f59;
    }

    main {
      max-width: 1280px;
      width: 100%;
      margin: 0 auto;
      padding: 18px 28px 26px;
    }

    .workspace {
      display: grid;
      grid-template-columns: minmax(300px, 0.58fr) minmax(620px, 1.42fr);
      gap: 14px;
      align-items: start;
    }

    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .panel-head {
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
    }

    h2 {
      margin: 0;
      font-size: 15px;
      font-weight: 780;
      letter-spacing: 0;
    }

    .panel-note {
      color: var(--muted);
      font-size: 12px;
      text-align: right;
    }

    .queue {
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 10px;
      max-height: calc(100vh - 230px);
      overflow: auto;
    }

    .campaign-button {
      width: 100%;
      text-align: left;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      cursor: pointer;
      transition: border-color 120ms ease, background 120ms ease, box-shadow 120ms ease;
    }

    .campaign-button:hover {
      border-color: var(--line-strong);
      background: #fbfcfd;
    }

    .campaign-button.active {
      border-color: var(--teal);
      box-shadow: 0 0 0 2px rgba(15, 118, 110, 0.14);
    }

    .campaign-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 8px;
    }

    .campaign-top strong {
      font-size: 13px;
      line-height: 1.28;
    }

    .badges {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }

    .badge {
      min-height: 24px;
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
      font-size: 11px;
      font-weight: 760;
      white-space: nowrap;
      color: var(--ink);
    }

    .badge.critical { color: var(--critical); border-color: #f2b7b0; background: #fff8f7; }
    .badge.high { color: var(--high); border-color: #ead096; background: #fffdf5; }
    .badge.medium { color: var(--medium); border-color: #b6d7f3; background: #f7fbff; }
    .badge.low { color: var(--low); border-color: #b9dec8; background: #f7fcf9; }

    .campaign-title {
      margin: 0;
      font-size: 13px;
      font-weight: 780;
      line-height: 1.3;
    }

    .campaign-brief {
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-top: 6px;
    }

    .campaign-brief strong {
      color: var(--ink);
      font-weight: 740;
    }

    .case-lines {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
    }

    .case-lines b {
      color: var(--ink);
      font-weight: 760;
    }

    .dossier {
      padding: 16px 18px 18px;
    }

    .dossier-title {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 14px;
    }

    .dossier-title h3 {
      margin: 0;
      font-size: 22px;
      line-height: 1.18;
      letter-spacing: 0;
    }

    .plain-text {
      margin: 0 0 14px;
      color: #344454;
      max-width: 920px;
    }

    .plain-text.compact {
      margin-top: 8px;
      margin-bottom: 0;
      color: var(--muted);
      font-size: 13px;
    }

    .plain-text.impact {
      border-left: 3px solid var(--teal);
      padding-left: 10px;
      margin-bottom: 12px;
      font-weight: 680;
    }

    .attack-analysis {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin: 12px 0 14px;
    }

    .analysis-block {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: var(--surface-2);
      min-height: 82px;
    }

    .analysis-block.primary {
      border-color: rgba(15, 118, 110, 0.35);
      background: #f3fbf9;
      grid-column: span 3;
    }

    .analysis-block span {
      display: block;
      color: var(--muted);
      font-size: 11px;
      font-weight: 760;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .analysis-block strong {
      display: block;
      margin-top: 7px;
      font-size: 15px;
      line-height: 1.32;
      overflow-wrap: anywhere;
    }

    .action-list {
      border-top-color: rgba(15, 118, 110, 0.35);
    }

    .role-list {
      display: grid;
      gap: 8px;
    }

    .role-block {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px 10px;
      background: #fff;
    }

    .role-block span {
      display: block;
      color: var(--muted);
      font-size: 11px;
      font-weight: 760;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }

    .role-block strong {
      display: block;
      font-size: 13px;
      line-height: 1.35;
    }

    .empty.inline {
      padding: 0;
    }

    .section-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 16px;
      margin-top: 12px;
    }

    .subsection {
      border-top: 1px solid var(--line);
      padding-top: 14px;
      min-width: 0;
    }

    .subsection h4 {
      margin: 0 0 8px;
      font-size: 13px;
      font-weight: 780;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #334155;
    }

    ul {
      margin: 0;
      padding-left: 18px;
    }

    li {
      margin: 6px 0;
      color: #354658;
    }

    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .chip {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 4px 8px;
      border-radius: 6px;
      background: #eef3f2;
      color: #253843;
      font-size: 12px;
      font-weight: 680;
      border: 1px solid #d7e2df;
    }

    .empty {
      padding: 16px;
      color: var(--muted);
    }

    @media (max-width: 1180px) {
      .workspace {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 760px) {
      header,
      main {
        padding-left: 16px;
        padding-right: 16px;
      }

      .topline,
      .dossier-title {
        flex-direction: column;
      }

      .refresh {
        width: 100%;
      }

      .attack-analysis,
      .section-grid {
        grid-template-columns: 1fr;
      }

      .analysis-block.primary {
        grid-column: span 1;
      }
    }
  </style>
</head>
<body>
  <div class="app">
    <header>
      <div class="topline">
        <div class="title-block">
          <h1>Hipóteses de Ataque</h1>
          <p class="subtitle">Fila defensiva com hipótese de ataque, prova técnica, próximo passo provável e consulta prática.</p>
        </div>
        <button class="refresh" id="refresh" type="button">Atualizar dados</button>
      </div>
    </header>

    <main>
      <div class="workspace">
        <section class="panel">
          <div class="panel-head">
            <h2>Hipóteses</h2>
            <span class="panel-note">Ataques prováveis priorizados</span>
          </div>
          <div class="queue" id="campaignQueue"></div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h2>Análise do Ataque</h2>
            <span class="panel-note">Raciocínio e decisão defensiva</span>
          </div>
          <div class="dossier" id="dossier"></div>
        </section>
      </div>

    </main>
  </div>

  <script>
    let dashboard = null;
    let selectedCampaignId = null;

    const severityLabel = {
      critical: "CRÍTICA",
      high: "ALTA",
      medium: "MÉDIA",
      low: "BAIXA"
    };

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function badge(text, severity = "") {
      return `<span class="badge ${escapeHtml(severity)}">${escapeHtml(text)}</span>`;
    }

    function renderCampaignQueue(campaigns) {
      const root = document.getElementById("campaignQueue");
      if (!campaigns.length) {
        root.innerHTML = '<div class="empty">Nenhuma campanha persistida foi encontrada.</div>';
        return;
      }
      root.innerHTML = campaigns.map((item) => {
        const active = item.campaign_id === selectedCampaignId ? "active" : "";
        const severity = item.severity || "low";
        const triage = item.triage || {};
        return `
          <button class="campaign-button ${active}" data-campaign="${escapeHtml(item.campaign_id)}" type="button">
            <div class="campaign-top">
              <strong>${escapeHtml(severityLabel[severity] || severity.toUpperCase())} · ${escapeHtml(triage.attack_label || item.hypothesis)}</strong>
              ${badge(item.case_id || item.campaign_id)}
            </div>
            <div class="case-lines">
              <span><b>Alvo:</b> ${escapeHtml(triage.target || item.target_ip || "-")}</span>
              <span><b>Indica:</b> ${escapeHtml(triage.operator_focus || triage.phase || "-")}</span>
              <span><b>Prova:</b> ${escapeHtml(triage.decisive_signal || triage.finding || item.discovery || "-")}</span>
              <span><b>Ação:</b> ${escapeHtml(triage.primary_action || triage.decision || "-")}</span>
            </div>
          </button>
        `;
      }).join("");

      root.querySelectorAll(".campaign-button").forEach((button) => {
        button.addEventListener("click", () => {
          selectedCampaignId = button.getAttribute("data-campaign");
          renderAll();
        });
      });
    }

    function renderDossier(item) {
      const root = document.getElementById("dossier");
      if (!item) {
        root.innerHTML = '<div class="empty">Selecione uma campanha para ver o dossiê técnico.</div>';
        return;
      }
      const severity = item.severity || "low";
      const triage = item.triage || {};
      const roleBlocks = (triage.service_roles || []).map((group) => `
        <div class="role-block">
          <span>${escapeHtml(group.role)}</span>
          <strong>${escapeHtml((group.services || []).join(", "))}</strong>
        </div>
      `).join("");
      const queryItems = (triage.pivot_queries || [triage.next_query]).filter(Boolean);
      root.innerHTML = `
        <div class="dossier-title">
          <div>
            <div class="badges" style="margin-bottom: 10px;">
              ${badge(severityLabel[severity] || severity.toUpperCase(), severity)}
              ${badge(`Risco ${item.risk_score}/100`)}
              ${badge(`Criticidade ${item.criticality || 0}/100`, (item.criticality || 0) >= 85 ? "critical" : "")}
              ${badge(`Confirmação ${triage.confirmation_level || "parcial"}`, triage.confirmation_level === "Forte" ? "critical" : "")}
              ${badge(triage.phase || "Fase não classificada")}
              ${badge(item.case_id || item.campaign_id)}
            </div>
            <h3>${escapeHtml(triage.attack_label || item.hypothesis)}</h3>
            <p class="plain-text compact">${escapeHtml(triage.operator_focus || triage.confirmation_reason || item.hypothesis)}</p>
          </div>
        </div>

        <div class="attack-analysis">
          <section class="analysis-block primary">
            <span>Hipótese de ataque</span>
            <strong>${escapeHtml(triage.attack_hypothesis || triage.attempted || item.attack_surface)}</strong>
          </section>
          <section class="analysis-block">
            <span>Objetivo do ataque</span>
            <strong>${escapeHtml(triage.attacker_objective || triage.attempted || "-")}</strong>
          </section>
          <section class="analysis-block">
            <span>Prova que sustenta</span>
            <strong>${escapeHtml(triage.decisive_signal || triage.finding || item.discovery)}</strong>
          </section>
          <section class="analysis-block">
            <span>Próximo passo provável</span>
            <strong>${escapeHtml(triage.attacker_next_step || "Nova sondagem direcionada.")}</strong>
          </section>
          <section class="analysis-block">
            <span>Valor defensivo</span>
            <strong>${escapeHtml(triage.defensive_value || triage.supporting_context || "-")}</strong>
          </section>
          <section class="analysis-block">
            <span>Criticidade contextual</span>
            <strong>${escapeHtml(triage.criticality_context || "Sem ajuste adicional de reputação.")}</strong>
          </section>
          <section class="analysis-block">
            <span>Impacto se confirmado</span>
            <strong>${escapeHtml(triage.business_impact || triage.impact || item.impact_summary)}</strong>
          </section>
          <section class="analysis-block">
            <span>Falta confirmar</span>
            <strong>${escapeHtml(triage.missing_confirmation || "Não há requisito adicional definido.")}</strong>
          </section>
        </div>

        <div class="section-grid">
          <div class="subsection">
            <h4>Consultas práticas</h4>
            <ul>${queryItems.map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}</ul>
          </div>
          <div class="subsection">
            <h4>Papel dos serviços no ataque</h4>
            <div class="role-list">${roleBlocks || '<div class="empty inline">Sem papel técnico classificado.</div>'}</div>
          </div>
        </div>

        <div class="section-grid">
          <div class="subsection">
            <h4>Evidência mínima</h4>
            <ul>${(triage.evidence || item.evidence.slice(0, 3)).map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}</ul>
          </div>
          <div class="subsection action-list">
            <h4>Checklist de decisão</h4>
            <ul>${(triage.investigation_checklist || triage.next_steps || item.recommendations.slice(0, 3)).map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}</ul>
          </div>
        </div>
      `;
    }

    function selectedCampaign() {
      if (!dashboard || !dashboard.campaigns.length) return null;
      return dashboard.campaigns.find((item) => item.campaign_id === selectedCampaignId) || dashboard.campaigns[0];
    }

    function renderAll() {
      if (!dashboard) return;
      if (!selectedCampaignId && dashboard.campaigns.length) {
        selectedCampaignId = dashboard.campaigns[0].campaign_id;
      }
      renderCampaignQueue(dashboard.campaigns);
      renderDossier(selectedCampaign());
    }

    async function loadDashboard() {
      const response = await fetch("/api/dashboard", { cache: "no-store" });
      dashboard = await response.json();
      if (selectedCampaignId && !dashboard.campaigns.some((item) => item.campaign_id === selectedCampaignId)) {
        selectedCampaignId = null;
      }
      renderAll();
    }

    document.getElementById("refresh").addEventListener("click", loadDashboard);
    loadDashboard().catch((error) => {
      document.getElementById("campaignQueue").innerHTML = '<div class="empty">Falha ao carregar dados operacionais.</div>';
      document.getElementById("dossier").innerHTML = '<div class="empty">Verifique se o banco SQLite informado possui eventos persistidos.</div>';
      console.error(error);
    });
  </script>
</body>
</html>
"""
