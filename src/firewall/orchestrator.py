from collections.abc import Iterable

from firewall.analysis.flow_analyzer import FlowAnalyzer
from firewall.analysis.packet_analyzer import PacketAnalyzer
from firewall.analysis.util import valid_timestamp
from firewall.schemas.capture_analysis import CaptureAnalysis
from firewall.schemas.flow_process_result import FlowExclusionReason, FlowProcessResult
from firewall.schemas.indexed_packet import IndexedPacket
from firewall.schemas.packet import Packet

# firewall core
# it manages filtering pipeline:
# file PCAP reading  ->  extract info
# - IPs, protocol, ports
# - packets, bytes, duration, frequency
# policy engine -> ALLOW/DROP decision

# --- PACKET INDEXING ---

def index_packets(packets: Iterable[Packet]) -> list[IndexedPacket]:
    # preserve reader order
    return [IndexedPacket(capture_index=index, packet=packet) for index, packet in enumerate(packets, start=1)]

# --- PACKET PREPARATION ---

def prepare_packets(original_packets: list[IndexedPacket]) -> tuple[list[IndexedPacket], list[int]]:
    eligible: list[tuple[float, IndexedPacket]] = []
    invalid_timestamp_indexes: list[int] = []

    for indexed in original_packets:
        timestamp = valid_timestamp(indexed.packet.timestamp)

        if timestamp is None:
            invalid_timestamp_indexes.append(indexed.capture_index)
        else:
            eligible.append((timestamp, indexed))

    # equal timestamps keep the capture order
    eligible.sort(key=lambda item: item[0])

    ordered_packets = [indexed for _, indexed in eligible]

    return ordered_packets, invalid_timestamp_indexes


# --- CAPTURE ANALYSIS ---

def analyze_capture(packets: Iterable[Packet], packet_analyzer: PacketAnalyzer, flow_analyzer: FlowAnalyzer) -> CaptureAnalysis:
    original_packets = index_packets(packets)

    ordered_packets, invalid_timestamp_indexes = prepare_packets(original_packets)

    packet_analyses = {indexed.capture_index: packet_analyzer.analyze(indexed.packet) for indexed in original_packets}

    flow_analyzer.reset()

    # packets without a valid timestamp cannot be aggregated
    flow_results: dict[int, FlowProcessResult] = {capture_index: FlowProcessResult(flow_id=None, exclusion_reason=FlowExclusionReason.INVALID_TIMESTAMP) for capture_index in invalid_timestamp_indexes}

    for indexed in ordered_packets:
        flow_results[indexed.capture_index] = flow_analyzer.process(indexed.packet)

    flow_analyzer.finalize_all()

    flows = {analysis.flow_id: analysis for analysis in flow_analyzer.completed}

    return CaptureAnalysis(packets=tuple(original_packets), packet_analyses=packet_analyses, flow_results=flow_results, flows=flows)
