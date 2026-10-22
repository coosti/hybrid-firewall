import sys
from collections.abc import Iterator
from pathlib import Path

from scapy.all import PcapReader

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6

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

            fields = {
                "timestamp": float(pkt.time),
                "packet_length": len(pkt),
            }

            # ethernet info
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                fields["src_mac"] = eth.src
                fields["dst_mac"] = eth.dst

            # IP info
            if pkt.haslayer(IP):
                ip = pkt[IP]

                fields["ip_version"] = 4
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst
                fields["ip_protocol_number"] = int(ip.proto)

            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]

                fields["ip_version"] = 6
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst
                fields["ip_protocol_number"] = int(ip.nh)

            # transport level info
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]

                fields["transport_protocol"] = "TCP"
                fields["src_port"] = int(tcp.sport)
                fields["dst_port"] = int(tcp.dport)
                fields["tcp_flags"] = str(tcp.flags)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]

                fields["transport_protocol"] = "UDP"
                fields["src_port"] = int(udp.sport)
                fields["dst_port"] = int(udp.dport)

            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]

                fields["transport_protocol"] = "ICMP"
                fields["icmp_type"] = int(icmp.type)
                fields["icmp_code"] = int(icmp.code)

            # check header and extension headers to find ICMPv6
            elif pkt.haslayer(IPv6):

                icmp6 = pkt[IPv6]

                fields["transport_protocol"] = "ICMPv6"
                fields["icmp_type"] = int(icmp6.type)
                fields["icmp_code"] = int(icmp6.code)

            yield Packet(**fields)
