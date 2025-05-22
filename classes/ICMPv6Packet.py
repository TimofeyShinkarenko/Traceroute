import os
import struct
import socket
from typing import Optional

from classes.IPv6Header import IPv6Header


class ICMPv6Packet:
    def __init__(self, length: int, ttl: int, source_ip: str,
                 destination_ip: str, data: Optional[bytes] = None):
        if data is None:
            self.data = bytes('a' * max(0, length - 48), 'ascii')
        else:
            self.data = data if isinstance(data, bytes) else bytes(data,
                                                                   'ascii')

        icmp_length = 8 + len(self.data)

        self.ipv6_header = IPv6Header(ttl, source_ip, destination_ip,
                                      icmp_length)
        self.type = 128
        self.code = 0
        self.checksum = 0
        self.identifier = os.getpid() & 0xFFFF
        self.sequence_number = 1

    @staticmethod
    def calculate_checksum(pseudo_header: bytes, icmp_packet: bytes) -> int:
        data = pseudo_header + icmp_packet

        if len(data) % 2 != 0:
            data += b'\x00'

        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            total = (total & 0xFFFF) + (total >> 16)

        return ~total & 0xFFFF

    def get_icmp_header(self) -> bytes:
        return struct.pack("!BBHHH", self.type, self.code, self.checksum,
                           self.identifier, self.sequence_number)

    def get_pseudo_header(self, payload_length: int) -> bytes:
        pseudo_header = (
                socket.inet_pton(socket.AF_INET6,
                                 self.ipv6_header.source_ip) +
                socket.inet_pton(socket.AF_INET6,
                                 self.ipv6_header.destination_ip) +
                struct.pack("!I", payload_length) +
                b'\x00\x00\x00' + struct.pack("!B",
                                              self.ipv6_header.next_header)
        )
        return pseudo_header

    def get_header_bytes(self) -> bytes:
        temp_header = struct.pack("!BBHHH", self.type, self.code, 0,
                                  self.identifier, self.sequence_number)
        icmp_packet = temp_header + self.data
        pseudo_header = self.get_pseudo_header(len(icmp_packet))
        self.checksum = self.calculate_checksum(pseudo_header, icmp_packet)
        return struct.pack("!BBHHH", self.type, self.code, self.checksum,
                           self.identifier, self.sequence_number)

    def get_packet(self) -> bytes:
        return self.ipv6_header.get_header_bytes() + self.get_header_bytes() + self.data
