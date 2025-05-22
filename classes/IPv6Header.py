import socket
import struct


class IPv6Header:
    def __init__(self, hop_limit, source_ip, destination_ip, payload_length):
        self.version = 6
        self.traffic_class = 0
        self.flow_label = 0
        self.payload_length = payload_length
        self.next_header = 58
        self.hop_limit = hop_limit
        self.source_ip = source_ip
        self.destination_ip = destination_ip

    def get_header_bytes(self):
        version_tc_fl = ((self.version & 0xF) << 28) | (
                    (self.traffic_class & 0xFF) << 20) | (
                                    self.flow_label & 0xFFFFF)

        header = struct.pack(
            "!IHBB16s16s",
            version_tc_fl,
            self.payload_length,
            self.next_header,
            self.hop_limit,  # Используем hop_limit вместо ttl
            socket.inet_pton(socket.AF_INET6, self.source_ip),
            socket.inet_pton(socket.AF_INET6, self.destination_ip)
        )

        return header
