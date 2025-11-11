from enum import Enum
from scapy.layers.inet import TCP, UDP, ICMP


class Protocol(Enum):
    TCP = TCP
    UDP = UDP
    ICMP = ICMP