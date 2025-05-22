import os

from classes.IPv4Header import *


class ICMPv4Packet:
    def __init__(self, length, ttl, source_ip, destination_ip):
        self.ipv4_header = IPv4Header(ttl, source_ip, destination_ip, length)
        self.type = 8
        self.code = 0
        self.checksum = 0
        self.identifier = os.getpid() & 0xFFFF
        self.sequence_number = 1
        self.data = bytes('a' * (length - 28), 'ascii')

    def get_header_bytes(self):
        header = struct.pack("!BBHHH",
                             self.type,
                             self.code,
                             self.checksum,
                             self.identifier,
                             self.sequence_number
                             )
        self.checksum = IPv4Header.calculate_checksum(header + self.data)
        header = struct.pack("!BBHHH",
                             self.type,
                             self.code,
                             self.checksum,
                             self.identifier,
                             self.sequence_number
                             )

        return header

    def get_packet(self):
        return self.ipv4_header.get_header_bytes() + self.get_header_bytes() + self.data
