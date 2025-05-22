import socket
import struct


class IPv4Header:
    def __init__(self, ttl, source_ip, destination_ip, length):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.length = length
        self.identification = 0
        self.flags = 0
        self.offset = 0
        self.ttl = ttl
        self.protocol = 1
        self.checksum = 0
        self.source_ip = source_ip
        self.destination_ip = destination_ip

    @staticmethod
    def calculate_checksum(data):
        if len(data) % 2:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff

    def get_header_bytes(self):
        header = struct.pack("!BBHHHBBH4s4s",
                             (self.version << 4) | self.ihl,
                             self.tos,
                             self.length,
                             self.identification,
                             (self.flags << 13) | self.offset,
                             self.ttl,
                             self.protocol,
                             0,
                             socket.inet_aton(self.source_ip),
                             socket.inet_aton(self.destination_ip)
                             )

        self.checksum = self.calculate_checksum(header)
        header = struct.pack("!BBHHHBBH4s4s",
                             (self.version << 4) | self.ihl,
                             self.tos,
                             self.length,
                             self.identification,
                             (self.flags << 13) | self.offset,
                             self.ttl,
                             self.protocol,
                             self.checksum,
                             socket.inet_aton(self.source_ip),
                             socket.inet_aton(self.destination_ip)
                             )

        return header
