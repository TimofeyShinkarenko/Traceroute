import unittest
import struct
import os
from classes.ICMPv6Packet import ICMPv6Packet


class TestICMPv6Packet(unittest.TestCase):
    def setUp(self):
        self.length = 64
        self.ttl = 64
        self.source_ip = "2001:db8::1"
        self.destination_ip = "2001:db8::2"
        self.icmp_packet = ICMPv6Packet(self.length, self.ttl, self.source_ip,
                                        self.destination_ip)

    def test_initialization(self):
        self.assertEqual(self.icmp_packet.type, 128)
        self.assertEqual(self.icmp_packet.code, 0)
        self.assertEqual(self.icmp_packet.checksum, 0)
        self.assertEqual(self.icmp_packet.identifier, os.getpid() & 0xFFFF)
        self.assertEqual(self.icmp_packet.sequence_number, 1)
        self.assertEqual(len(self.icmp_packet.data), self.length - 48)

    def test_get_icmp_header(self):
        header = self.icmp_packet.get_icmp_header()
        self.assertEqual(len(header), 8)
        unpacked = struct.unpack("!BBHHH", header)
        self.assertEqual(unpacked[0], 128)
        self.assertEqual(unpacked[1], 0)
        self.assertEqual(unpacked[2], 0)
        self.assertEqual(unpacked[3], os.getpid() & 0xFFFF)
        self.assertEqual(unpacked[4], 1)


if __name__ == '__main__':
    unittest.main()
