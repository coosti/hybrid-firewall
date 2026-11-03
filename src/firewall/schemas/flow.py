from dataclasses import dataclass

from firewall.schemas.packet import IPVersion, TransportProtocol

# --- FLOW DATA ---

@dataclass(frozen=True, slots=True)
class Endpoint:
    ip: str  # normalized with ipaddress
    port: int | None


@dataclass(frozen=True, slots=True)
class FlowKey:
    ip_version: IPVersion
    ip_protocol_number: int
    transport_protocol: TransportProtocol
    endpoint_a: Endpoint
    endpoint_b: Endpoint

@dataclass(slots=True)
class Flow:

    # identity
    key: FlowKey
    flow_id: int

    # time
    first_seen: float | None = None
    last_seen: float | None = None
    previous_timestamp: float | None = None

    # volumes
    packet_count: int = 0
    byte_count: int = 0

    # directions
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0

    # packet sizes
    min_packet_size: int | None = None
    max_packet_size: int | None = None

    # inter-packet intervals
    interval_sum: float = 0.0
    interval_sq_sum: float = 0.0
    interval_count: int = 0

    # TCP behavior
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    # coherence
    invalid_timestamps: int = 0