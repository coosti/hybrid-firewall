from pathlib import Path
from typing import Any, Iterator

from scapy.all import PcapReader

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# rdpcap for short files
# PcapReader for big files and to reduce RAM use

# --- PCAP FILES READER ---

# stream packets without loading the whole file into RAM

# with PcapReader(data\samples\sample_capture.pcapng) as packets:
    # for pkt in packets:
        # process each packet individually
        # if pkt.haslayer('IP'):
            # extract and put in dict...

def pcap_reader (path: str | Path) -> Iterator[dict[str, Any]]:

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
                "src_mac": None,
                "dst_mac": None,
                "ip_version": None,
                "src_ip": None,
                "dst_ip": None,
                "protocol": "OTHER",
                "src_port": None,
                "dst_port": None,
                "tcp_flags": None,
                "icmp_type": None,
                "icmp_code": None,
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

            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]

                fields["ip_version"] = 6
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst

            # transport level info
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]

                fields["protocol"] = "TCP"
                fields["src_port"] = tcp.sport
                fields["dst_port"] = tcp.dport
                fields["tcp_flags"] = str(tcp.flags)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]

                fields["protocol"] = "UDP"
                fields["src_port"] = udp.sport
                fields["dst_port"] = udp.dport

            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]

                fields["protocol"] = "ICMP"
                fields["icmp_type"] = icmp.type
                fields["icmp_code"] = icmp.code

            yield fields

