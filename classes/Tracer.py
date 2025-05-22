from types import NoneType

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

from classes.ICMPv4Packet import ICMPv4Packet
from classes.ICMPv6Packet import ICMPv6Packet


class Tracer:
    def __init__(self, source: str, target: str, version=4, number_requests=3,
                 interval=0.1,
                 timeout=4, max_ttl=10, packet_size=80, data=None):
        self.version = version
        self.ip_source = source
        self.ip_target = target
        self.number_requests = number_requests
        self.interval = interval
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.packet_size = packet_size
        self.data = data

    @staticmethod
    def reformat_to_binary(number: int, length: int) -> str:
        binary_number = bin(number)[2:]
        return (length - len(binary_number)) * '0' + binary_number

    @staticmethod
    def reformat_data_routing(number: int, data: list[Any]) -> str:
        result_string = str(number) + (5 - len(str(number))) * ' '
        for i in range(0, len(data)):
            result_string += data[i][1] + (10 - len(data[i][1])) * ' '

        set_ip_address = set([data[i][0] for i in range(len(data))])
        for ip_address in set_ip_address:
            result_string += ip_address + (20 - len(ip_address)) * ' '

        return result_string

    def make_packet(self, ttl: int) -> ICMPv6Packet | ICMPv4Packet:
        if self.version == 6:
            return ICMPv6Packet(self.packet_size, ttl,
                                self.ip_source, self.ip_target, self.data)

        return ICMPv4Packet(self.packet_size, ttl, self.ip_source,
                            self.ip_target)

    def send_packet_and_receive(self, packet: bytes):
        try:
            if self.version == 6:
                ipv6_header = packet[0:40]
                icmpv6_header = packet[40:48]
                data = packet[48:]

                response = sr1(
                    IPv6(ipv6_header) / ICMPv6EchoRequest(
                        icmpv6_header) / Raw(data),
                    timeout=self.timeout, verbose=False)

                if response is None:
                    print(
                        f"Timeout waiting for response (ttl={IPv6(ipv6_header).hlim})")

                return response
            else:
                response = sr1(
                    IP(packet[0:20]) / ICMP(packet[20:28]) / Raw(packet[28:]),
                    timeout=self.timeout, verbose=False)
                return response

        except Exception as e:
            print(f"Error sending packet: {str(e)}")
            return None

    def run(self) -> None:
        print(
            f"Tracing route to {self.ip_target} over IPv{self.version}, maximum hops: {self.max_ttl}")
        print("TTL   Time      IP Address")
        print("-" * 50)

        for ttl in range(1, self.max_ttl + 1):
            sent_packet = self.make_packet(ttl).get_packet()
            is_target_achieved = False
            data = []

            for j in range(self.number_requests):
                start_time = time.time()
                response = self.send_packet_and_receive(sent_packet)

                if response is None:
                    data.append(["*", "*"])
                    time.sleep(self.interval)
                    continue

                try:
                    src_ip = response.fields.get('src')
                    if src_ip == self.ip_target:
                        is_target_achieved = True

                    data.append([src_ip,
                                 str(round((time.time() - start_time) * 1000,
                                           2)) + ' ms'])
                except Exception as e:
                    data.append(["Error", "Error"])
                    print(f"Error processing response: {str(e)}")

                time.sleep(self.interval)

            if len(data) != 0:
                print(self.reformat_data_routing(ttl, data))

            if is_target_achieved:
                print(
                    f"Trace complete. Target {self.ip_target} reached in {ttl} hops.")
                break

        if not is_target_achieved:
            print(
                f"Trace incomplete. Target {self.ip_target} not reached within {self.max_ttl} hops.")
