#!/usr/bin/env python3
from classes.Tracer import *
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source",
        help="Source ip address"
    )
    parser.add_argument(
        "target",
        help="Target (goal) of traceroute"
    )
    parser.add_argument(
        "-v", "--version-protocol",
        type=int,
        default=4,
        help="Version used protocol. Default: 4"
    )
    parser.add_argument(
        "-n", "--number-requests",
        type=int,
        default=3,
        help="Number of requests to send on each router. Default: 3"
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=0.5,
        help="Interval between requests on routers. Default: 1.0"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1,
        help="Maximum time to wait for a request. Default: 2"
    )
    parser.add_argument(
        "-m", "--max-ttl",
        type=int,
        default=15,
        help="Maximum TTL (time to life) for requests. Default: 15"
    )
    parser.add_argument(
        "-s", "--packet-size",
        type=int,
        default=40,
        help="Packet size of sending packet. Default: 40"
    )
    parser.add_argument(
        "-d", "--data",
        type=str,
        default=None,
        help="Sent data. Default: 'a' * n"
    )

    args = parser.parse_args()

    traceroute = Tracer(
        source=args.source,
        target=args.target,
        version=args.version_protocol,
        number_requests=args.number_requests,
        interval=args.interval,
        timeout=args.timeout,
        max_ttl=args.max_ttl,
        packet_size=args.packet_size,
        data=args.data
    )

    traceroute.run()


if __name__ == "__main__":
    main()
