#!/usr/bin/env python3
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr1
from protocol import Protocol


class Tracer:
    def __init__(self, protocol: Protocol, target_ip: str,
                 target_port: int = None, timeout: float = 2, ttl: int = 30):
        self.protocol = protocol
        self.target_port = target_port
        self.target_ip = target_ip
        self.timeout = timeout
        self.ttl = ttl

    def create_packet(self, ttl: int) -> IP | None:
        ip_packet = IP(dst=self.target_ip, ttl=ttl)

        if self.protocol == Protocol.ICMP:
            return ip_packet / ICMP()

        if self.protocol == Protocol.TCP:
            return ip_packet / TCP(dport=self.target_port, flags='S')

        if self.protocol == Protocol.UDP:
            return ip_packet / UDP(dport=self.target_port)

        return None

    def traceroute(self):
        for current_ttl in range(1, self.ttl + 1):
            packet = self.create_packet(ttl=current_ttl)
            parts = [str(current_ttl)]

            start_time = time.time()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            end_time = time.time()
            duration = (end_time - start_time) * 1000

            if response is None:
                parts.append("*")
                yield " ".join(parts)
                continue

            src_ip = response.src
            parts.append(src_ip)
            parts.append(f"{duration:.2f} ms")
            yield " ".join(parts)

            if src_ip == self.target_ip:
                break
