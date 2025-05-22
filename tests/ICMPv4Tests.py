import unittest

from classes.ICMPv4Packet import *


class TestICMPv4Packet(unittest.TestCase):
    def setUp(self):
        self.length = 56
        self.ttl = 64
        self.source_ip = "192.168.1.1"
        self.destination_ip = "8.8.8.8"
        self.icmp_packet = ICMPv4Packet(self.length, self.ttl, self.source_ip,
                                        self.destination_ip)

    def test_initialization(self):
        self.assertEqual(self.icmp_packet.type, 8)
        self.assertEqual(self.icmp_packet.code, 0)
        self.assertEqual(self.icmp_packet.checksum, 0)
        self.assertEqual(self.icmp_packet.identifier, os.getpid() & 0xFFFF)
        self.assertEqual(self.icmp_packet.sequence_number, 1)
        self.assertEqual(len(self.icmp_packet.data),
                         self.length - 28)

    def test_get_header_bytes(self):
        header_bytes = self.icmp_packet.get_header_bytes()
        self.assertEqual(len(header_bytes), 8)
        unpacked_header = struct.unpack("!BBHHH", header_bytes)
        self.assertEqual(unpacked_header[0], 8)
        self.assertEqual(unpacked_header[1], 0)
        self.assertNotEqual(unpacked_header[2],
                            0)
        self.assertEqual(unpacked_header[3],
                         os.getpid() & 0xFFFF)
        self.assertEqual(unpacked_header[4], 1)

    def test_checksum_calculation(self):
        header_before_checksum = struct.pack("!BBHHH",
                                             self.icmp_packet.type,
                                             self.icmp_packet.code,
                                             0,
                                             self.icmp_packet.identifier,
                                             self.icmp_packet.sequence_number)
        calculated_checksum = IPv4Header.calculate_checksum(
            header_before_checksum + self.icmp_packet.data)

        header_bytes = self.icmp_packet.get_header_bytes()
        unpacked_header = struct.unpack("!BBHHH", header_bytes)
        self.assertEqual(unpacked_header[2], calculated_checksum)

    def test_get_packet(self):
        packet = self.icmp_packet.get_packet()
        self.assertEqual(len(packet), self.length)

        ip_header = packet[:20]
        icmp_header = packet[20:28]
        data = packet[28:]

        self.assertEqual(len(ip_header), 20)
        self.assertEqual(len(icmp_header), 8)
        self.assertEqual(len(data), self.length - 28)


if __name__ == '__main__':
    unittest.main()