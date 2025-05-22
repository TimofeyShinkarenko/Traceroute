import unittest
import struct
import socket
from classes.IPv4Header import IPv4Header


class TestIPv4Header(unittest.TestCase):
    def setUp(self):
        self.ttl = 64
        self.source_ip = "192.168.1.1"
        self.destination_ip = "8.8.8.8"
        self.length = 60
        self.header = IPv4Header(self.ttl, self.source_ip,
                                 self.destination_ip, self.length)

    def test_initialization(self):
        self.assertEqual(self.header.version, 4)
        self.assertEqual(self.header.ihl, 5)
        self.assertEqual(self.header.tos, 0)
        self.assertEqual(self.header.length, self.length)
        self.assertEqual(self.header.identification, 0)
        self.assertEqual(self.header.flags, 0)
        self.assertEqual(self.header.offset, 0)
        self.assertEqual(self.header.ttl, self.ttl)
        self.assertEqual(self.header.protocol, 1)
        self.assertEqual(self.header.checksum, 0)
        self.assertEqual(self.header.source_ip, self.source_ip)
        self.assertEqual(self.header.destination_ip, self.destination_ip)

    def test_get_header_bytes(self):
        header_bytes = self.header.get_header_bytes()
        self.assertEqual(len(header_bytes),
                         20)

        (version_ihl, tos, length, ident, flags_offset,
         ttl, protocol, checksum, src_ip, dst_ip) = struct.unpack(
            "!BBHHHBBH4s4s", header_bytes)

        self.assertEqual(version_ihl, 0x45)
        self.assertEqual(tos, 0)
        self.assertEqual(length, self.length)
        self.assertEqual(ident, 0)
        self.assertEqual(flags_offset, 0)
        self.assertEqual(ttl, self.ttl)
        self.assertEqual(protocol, 1)
        self.assertNotEqual(checksum, 0)
        self.assertEqual(socket.inet_ntoa(src_ip), self.source_ip)
        self.assertEqual(socket.inet_ntoa(dst_ip), self.destination_ip)

    def test_checksum_in_header(self):
        temp_header = struct.pack("!BBHHHBBH4s4s",
                                  (
                                          self.header.version << 4) | self.header.ihl,
                                  self.header.tos,
                                  self.header.length,
                                  self.header.identification,
                                  (
                                          self.header.flags << 13) | self.header.offset,
                                  self.header.ttl,
                                  self.header.protocol,
                                  0,
                                  socket.inet_aton(self.source_ip),
                                  socket.inet_aton(self.destination_ip))

        expected_checksum = IPv4Header.calculate_checksum(temp_header)

        header_bytes = self.header.get_header_bytes()
        actual_checksum = struct.unpack("!BBHHHBBH4s4s", header_bytes)[7]

        self.assertEqual(actual_checksum, expected_checksum)


if __name__ == '__main__':
    unittest.main()
