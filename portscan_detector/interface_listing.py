from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from scapy.all import conf, get_if_list


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    description: str
    index: str
    mac: str
    ips: tuple[str, ...]


def get_interfaces() -> list[NetworkInterface]:
    detailed_interfaces = _get_detailed_interfaces()
    if detailed_interfaces:
        return detailed_interfaces

    return [
        NetworkInterface(
            name=name,
            description="",
            index="",
            mac="",
            ips=(),
        )
        for name in get_if_list()
    ]


def print_interfaces() -> None:
    interfaces = get_interfaces()
    if not interfaces:
        print("Nenhuma interface encontrada pelo Scapy.")
        return

    print("Interfaces encontradas pelo Scapy:")
    for interface in interfaces:
        print(f"- name: {interface.name}")
        if interface.description:
            print(f"  description: {interface.description}")
        if interface.index:
            print(f"  index: {interface.index}")
        if interface.mac:
            print(f"  mac: {interface.mac}")
        if interface.ips:
            print(f"  ips: {', '.join(interface.ips)}")
        print(f"  usar: python -m portscan_detector --interface \"{interface.name}\"")


def format_interface_names() -> str:
    interfaces = get_interfaces()
    if not interfaces:
        return "Nenhuma interface encontrada pelo Scapy."

    names = "\n".join(f"- {interface.name}" for interface in interfaces)
    return f"Interfaces disponiveis:\n{names}"


def _get_detailed_interfaces() -> list[NetworkInterface]:
    scapy_interfaces = getattr(conf, "ifaces", None)
    if scapy_interfaces is None:
        return []

    interfaces = []
    for scapy_interface in _interface_values(scapy_interfaces):
        name = str(getattr(scapy_interface, "name", "") or scapy_interface)
        if not name:
            continue

        interfaces.append(
            NetworkInterface(
                name=name,
                description=str(getattr(scapy_interface, "description", "") or ""),
                index=str(getattr(scapy_interface, "index", "") or ""),
                mac=str(getattr(scapy_interface, "mac", "") or ""),
                ips=tuple(str(ip) for ip in getattr(scapy_interface, "ips", []) or ()),
            )
        )

    return interfaces


def _interface_values(scapy_interfaces: object) -> Iterable[object]:
    values = getattr(scapy_interfaces, "values", None)
    if callable(values):
        return values() # type: ignore
    return ()
