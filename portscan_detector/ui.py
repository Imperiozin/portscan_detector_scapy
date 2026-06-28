from __future__ import annotations

from typing import Any

from .storage import SQLiteEventStore


SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "green",
}

EXPOSURE_LABEL = {
    "open": "possivelmente aberto",
    "closed": "fechado",
    "attempted": "testado",
    "filtered_or_inconclusive": "filtrado/inconclusivo",
    "unknown": "desconhecido",
}


def render_operational_ui(store: SQLiteEventStore, limit: int = 20) -> None:
    try:
        from rich import box
        from rich.console import Console
        from rich.markup import escape
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        _render_plain_fallback(store, limit)
        return

    console = Console()
    overview = store.fetch_overview()
    events = store.fetch_recent_events(limit=limit)
    highest_risk_event = store.fetch_highest_risk_event()
    campaigns = store.fetch_campaigns(limit=10)
    exposures = store.fetch_exposure(limit=12)

    header = Panel(
        (
            "[bold]Recon Intelligence Console[/bold]\n"
            "Análise operacional de reconhecimento, exposição observada e hipóteses técnicas."
        ),
        border_style="blue",
        padding=(1, 2),
    )

    metrics = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold blue")
    metrics.add_column("Métrica", style="white")
    metrics.add_column("Valor", justify="right", style="bold")
    metrics.add_row("Eventos persistidos", str(overview["total_events"]))
    metrics.add_row("Eventos high/critical", str(overview["high_or_critical"]))
    metrics.add_row("Campanhas correlacionadas", str(overview["campaigns"]))
    metrics.add_row("Serviços possivelmente abertos", str(overview["open_services"]))
    metrics.add_row("Maior prioridade observada", f"{overview['max_risk_score']}/100")

    exposure_table = Table(title="Exposição Observada", box=box.SIMPLE, header_style="bold blue")
    exposure_table.add_column("Ativo", width=13)
    exposure_table.add_column("Serviço", width=22)
    exposure_table.add_column("Estado", width=20)
    exposure_table.add_column("R", justify="right", width=3, no_wrap=True)
    for item in exposures:
        service_label = (
            f"{item.get('port', '')}/{str(item.get('protocol', '')).upper()} "
            f"{item.get('service', '')}"
        )
        exposure_table.add_row(
            str(item.get("target_ip", "")),
            _short(service_label, 28),
            EXPOSURE_LABEL.get(str(item.get("exposure")), str(item.get("exposure", ""))),
            str(item.get("risk", 0)),
        )

    events_panel = _events_panel(events, Panel, escape)
    campaigns_panel = _campaigns_panel(campaigns, Panel, escape)
    detail_panel = _detail_panel(highest_risk_event, Panel)
    console.print(header)
    console.print(metrics)
    console.print(events_panel)
    console.print(campaigns_panel)
    console.print(exposure_table)
    console.print(detail_panel)


def _detail_panel(event: dict[str, Any] | None, panel_type: Any) -> Any:
    if event is None:
        return panel_type(
            "Nenhum evento persistido foi encontrado no banco informado.",
            title="Detalhe Técnico",
            border_style="yellow",
        )

    evidence = "\n".join(f"- {item}" for item in event.get("evidence", [])[:5])
    recommendations = "\n".join(f"- {item}" for item in event.get("recommendations", [])[:4])
    text = (
        f"[bold]{event.get('hypothesis', '')}[/bold]\n"
        f"Origem: {event.get('source_ip')} | Destino: {event.get('target_ip')} | "
        f"Campanha: {event.get('campaign_id')}\n"
        f"Risco técnico: {event.get('risk_score', 0)}/100 | "
        f"Criticidade: {event.get('criticality', 0)}/100\n"
        f"Intenção provável: {event.get('intent', '')}\n"
        f"MITRE: {event.get('mitre_technique', '')}\n\n"
        f"[bold]Evidências[/bold]\n{evidence or '- Sem evidências adicionais.'}\n\n"
        f"[bold]Ações Recomendadas[/bold]\n{recommendations or '- Sem recomendações adicionais.'}"
    )
    return panel_type(text, title="Detalhe Técnico do Maior Risco", border_style="blue")


def _events_panel(events: list[dict[str, Any]], panel_type: Any, escape: Any) -> Any:
    if not events:
        return panel_type(
            "Nenhum alerta persistido foi encontrado.",
            title="Alertas Recentes",
            border_style="yellow",
        )

    blocks = []
    for event in events[:6]:
        severity = str(event.get("severity", "low"))
        style = SEVERITY_STYLE.get(severity, "white")
        flow = f"{event.get('source_ip', '')} -> {event.get('target_ip', '')}"
        services = _service_summary(event.get("services", []))
        blocks.append(
            "\n".join(
                (
                    f"[{style}]{severity.upper()}[/] risco={event.get('risk_score', 0)}/100 "
                    f"criticidade={event.get('criticality', 0)}/100 "
                    f"confiança={float(event.get('confidence') or 0):.0%} "
                    f"campanha={escape(str(event.get('campaign_id', '')))}",
                    f"Fluxo: {escape(flow)}",
                    f"Hipótese: {escape(str(event.get('hypothesis', '')))}",
                    f"Serviços: {escape(services)}",
                )
            )
        )
    return panel_type(
        "\n\n".join(blocks),
        title="Alertas Recentes",
        border_style="blue",
        padding=(1, 2),
    )


def _campaigns_panel(campaigns: list[dict[str, Any]], panel_type: Any, escape: Any) -> Any:
    if not campaigns:
        return panel_type(
            "Nenhuma campanha correlacionada foi encontrada.",
            title="Campanhas Correlacionadas",
            border_style="yellow",
        )

    blocks = []
    for campaign in campaigns[:6]:
        severity = str(campaign.get("severity", "low"))
        style = SEVERITY_STYLE.get(severity, "white")
        sources = campaign.get("sources", [])
        targets = campaign.get("targets", [])
        ports = _list_summary(campaign.get("ports", []), 8)
        hypotheses = _list_summary(campaign.get("hypotheses", []), 1)
        blocks.append(
            "\n".join(
                (
                    f"[{style}]{severity.upper()}[/] {escape(str(campaign.get('campaign_id', '')))} "
                    f"prioridade={campaign.get('risk_score', 0)}/100 "
                    f"eventos={campaign.get('event_count', 0)}",
                    f"Escopo: {len(sources)} origem(ns), {len(targets)} destino(s) | Portas: {escape(ports)}",
                    f"Hipótese dominante: {escape(hypotheses)}",
                )
            )
        )
    return panel_type(
        "\n\n".join(blocks),
        title="Campanhas Correlacionadas",
        border_style="blue",
        padding=(1, 2),
    )


def _render_plain_fallback(store: SQLiteEventStore, limit: int) -> None:
    overview = store.fetch_overview()
    print("Recon Intelligence Console")
    print("Análise operacional de reconhecimento, exposição observada e hipóteses técnicas.")
    print(f"Eventos persistidos: {overview['total_events']}")
    print(f"Eventos high/critical: {overview['high_or_critical']}")
    print(f"Campanhas correlacionadas: {overview['campaigns']}")
    print(f"Serviços possivelmente abertos: {overview['open_services']}")
    print(f"Maior prioridade observada: {overview['max_risk_score']}/100")
    print()
    for event in store.fetch_recent_events(limit=limit):
        print(
            f"[{str(event.get('severity', 'low')).upper()}] "
            f"{event.get('hypothesis')} | {event.get('source_ip')} -> {event.get('target_ip')} "
            f"| risco={event.get('risk_score')}/100 | criticidade={event.get('criticality', 0)}/100"
        )


def _service_summary(services: list[dict[str, Any]]) -> str:
    if not services:
        return "-"
    labels = []
    for service in services[:4]:
        labels.append(
            f"{service.get('port')}/{str(service.get('protocol', '')).upper()} "
            f"{service.get('service')}"
        )
    suffix = "" if len(services) <= 4 else f" +{len(services) - 4}"
    return _short(", ".join(labels) + suffix, 70)


def _list_summary(values: list[Any], limit: int) -> str:
    if not values:
        return "-"
    visible = [str(value) for value in values[:limit]]
    suffix = "" if len(values) <= limit else f" +{len(values) - limit}"
    return _short(", ".join(visible) + suffix, 60)


def _short(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return f"{value[:limit - 3]}..."
