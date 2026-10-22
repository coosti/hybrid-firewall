from dataclasses import dataclass
from typing import Literal

IPVersion = Literal[4, 6]

TransportProtocol = Literal[
    "TCP", "UDP", "ICMP", "ICMPv6", "OTHER"
]

# --- PACKET DATA ---

@dataclass(frozen=True, slots=True)
class Packet:

    timestamp: float
    packet_length: int

    src_mac: str | None = None
    dst_mac: str | None = None

    ip_version: IPVersion | None = None
    src_ip: str | None = None
    dst_ip: str | None = None

    ip_protocol_number: int | None = None
    transport_protocol: TransportProtocol = "OTHER"

    src_port: int | None = None
    dst_port: int | None = None

    tcp_flags: str | None = None

    icmp_type: int | None = None
    icmp_code: int | None = None
