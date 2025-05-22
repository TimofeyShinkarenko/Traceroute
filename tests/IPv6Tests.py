import unittest

from classes.IPv6Header import IPv6Header


class TestIPv6Header(unittest.TestCase):
    def setUp(self):
        self.ttl = 64
        self.source_ip = "2001:db8::1"
        self.destination_ip = "2001:db8::2"
        self.payload_length = 1280
        self.header = IPv6Header(self.ttl, self.source_ip,
                                 self.destination_ip, self.payload_length)

    def test_initialization(self):
        self.assertEqual(self.header.version, 6)
        self.assertEqual(self.header.traffic_class, 0)
        self.assertEqual(self.header.flow_label, 0)
        self.assertEqual(self.header.payload_length, self.payload_length)
        self.assertEqual(self.header.next_header, 58)
        self.assertEqual(self.header.hop_limit, self.ttl)
        self.assertEqual(self.header.source_ip, self.source_ip)
        self.assertEqual(self.header.destination_ip, self.destination_ip)


if __name__ == '__main__':
    unittest.main()
