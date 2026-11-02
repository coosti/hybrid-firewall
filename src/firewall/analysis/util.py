from typing import TypeGuard

# --- SHARED HELPERS ---

# Scapy flag letter -> descriptive name
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "NS",
}

def is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def tcp_flag_names(raw_flags: str | None) -> frozenset[str]:
    if not raw_flags:
        return frozenset()

    return frozenset(TCP_FLAGS[letter] for letter in raw_flags if letter in TCP_FLAGS)
