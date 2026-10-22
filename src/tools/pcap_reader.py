from collections.abc import Iterator
from pathlib import Path

from scapy.all import PcapReader

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6, IPv6ExtHdrFragment

from firewall.schemas.packet import Packet

# rdpcap for short files
# PcapReader for big files and to reduce RAM use

# --- PCAP FILES READER ---

# stream packets without loading the whole file into RAM

# with PcapReader(data\samples\sample_capture.pcapng) as packets:
    # for pkt in packets:
        # process each packet individually
        # if pkt.haslayer('IP'):
            # extract and put in Packet...

def read_packets(path: str | Path) -> Iterator[Packet]:

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"invalid path: {path}"
        )

    with PcapReader(str(path)) as packets:

        for pkt in packets:

            # lenghts could be different

            captured_length = len(pkt)
            wire_length = getattr(pkt, "wirelen", None)

            fields = {
                "timestamp": float(pkt.time),
                "packet_length": (
                    int(wire_length)
                    if wire_length is not None
                    else captured_length
                ),
                "captured_length": captured_length,
            }

            # ethernet info
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                fields["src_mac"] = eth.src
                fields["dst_mac"] = eth.dst

            # IP info

            # IPv4
            if pkt.haslayer(IP):
                ip = pkt[IP]

                fields["ip_version"] = 4
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst
                fields["ip_protocol_number"] = int(ip.proto)

                if ip.ihl is not None:
                    fields["ip_header_length"] = int(ip.ihl) * 4

                if ip.len is not None:
                    fields["ip_total_length"] = int(ip.len)

            # IPv6
            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]

                fields["ip_version"] = 6
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst
                fields["ip_protocol_number"] = int(ip.nh)

                # 40 bytes for IPv6 header
                fields["ip_header_length"] = 40

                if ip.plen is not None:
                    fields["ip_payload_length"] = int(ip.plen)

            # transport level info

            # TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]

                fields["transport_protocol"] = "TCP"
                fields["src_port"] = int(tcp.sport)
                fields["dst_port"] = int(tcp.dport)
                fields["tcp_flags"] = str(tcp.flags)

                if tcp.dataofs is not None:
                    fields["tcp_header_length"] = int(tcp.dataofs) * 4

                fields["tcp_sequence_number"] = int(tcp.seq)
                fields["tcp_ack_number"] = int(tcp.ack)

                fields["payload_length"] = len(bytes(tcp.payload))

            # UDP
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]

                fields["transport_protocol"] = "UDP"
                fields["src_port"] = int(udp.sport)
                fields["dst_port"] = int(udp.dport)

                if udp.len is not None:
                    fields["udp_length"] = int(udp.len)

                fields["payload_length"] = len(bytes(udp.payload))

            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]

                fields["transport_protocol"] = "ICMP"
                fields["icmp_type"] = int(icmp.type)
                fields["icmp_code"] = int(icmp.code)

                fields["payload_length"] = len(bytes(icmp.payload))

            # check header and extension headers to find ICMPv6
            elif pkt.haslayer(IPv6):

                icmp6 = pkt[IPv6]

                fields["transport_protocol"] = "ICMPv6"
                fields["icmp_type"] = int(icmp6.type)
                fields["icmp_code"] = int(icmp6.code)

                fields["payload_length"] = len(bytes(icmp6.payload))

            yield Packet(**fields)
