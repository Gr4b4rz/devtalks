import argparse
from dataclasses import dataclass
from time import time
from pyrust import estimate_pi as rust_estimate_pi
from pyrust import get_pkt_infos as rust_get_pkt_infos
from pyrust import get_filtered_pkt_infos, get_filtered_pkt_infos2
from scapy.all import TCP, IP, PcapReader

PI = 3.141592653589


def parse_args():
    "Parse arguments passed by cli"
    parser = argparse.ArgumentParser(prog="rust-pyo3-devtalk")
    parser.add_argument("--pi", action="store", type=int,
                        help="Run pi estimation program. The higher value is passed as an"
                        "argument the more precise is the estimation")
    parser.add_argument("--py", action="store_true",
                        help="Run python without rust")
    parser.add_argument("--rust", action="store_true",
                        help="Run python with rust")
    parser.add_argument("--pcap-info", action="store", type=str,
                        help="Run pcap info program and pass path to pcap file as an argument")

    args = parser.parse_args()
    return args


def estimate_pi(n: int) -> float:
    """
    Estimate pi using Leibniz’s formula:
    X = 4 - 4/3 + 4/5 - 4/7 + 4/9 ...
    """
    denominator = 1
    pi = 0
    sign = 1

    for _ in range(n):
        pi += sign * 4/denominator
        denominator += 2
        sign = -sign

    return pi


@dataclass
class PktFilter:
    "Pkt filtering class used in Rust get_filtered_pkt_infos function"
    ports: list[int]
    ips: list[str]

    def check_ports(self, src_port: int, dst_port: int) -> bool:
        "Check if src/dst ports are in ports list"
        return src_port in self.ports or dst_port in self.ports


@dataclass
class PyPktInfo:
    "Pure Python PktInfo class"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int


def get_pkt_infos(filename: str) -> list[PyPktInfo]:
    """
    Decode packets from given pcap file.
    Store each packet data in PyPktInfo struct.
    Return list of PktInfo structs.
    """
    pkt_infos = []
    with PcapReader(filename) as pkts:
        for pkt in pkts:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                pkt_infos.append(PyPktInfo(src_ip, dst_ip, src_port, dst_port))

    return pkt_infos


def main():
    arguments = parse_args()
    if arguments.pi:
        if arguments.rust or not arguments.py and not arguments.rust:
            print("Running π estimation in rust")
            start = time()
            rust_pi = rust_estimate_pi(arguments.pi)
            end = time()
            print(f"estimated: π={rust_pi:.12f}")
            print(f"target:    π={PI:.12f}")
            print(f"Estimation took {round(end - start, 2)} seconds")
            print()

        if arguments.py or not arguments.py and not arguments.rust:
            print("Running π estimation in python")
            start = time()
            py_pi = estimate_pi(arguments.pi)
            end = time()
            print(f"estimated: π={py_pi:.12f}")
            print(f"target:    π={PI:.12f}")
            print(f"Estimation took {round(end - start, 2)} seconds")
            print()
    if arguments.pcap_info:
        if arguments.rust or not arguments.py and not arguments.rust:
            print("Decoding packets in rust")
            start = time()
            print(
                f"Decoded pcaps: {len(rust_get_pkt_infos(arguments.pcap_info))}")
            end = time()
            print(f"Pcap decoding took {round(end - start, 2)} seconds")
            print()
        if arguments.py or not arguments.py and not arguments.rust:
            print("Decoding packets in python")
            start = time()
            print(f"Decoded pcaps: {len(get_pkt_infos(arguments.pcap_info))}")
            end = time()
            print(f"Pcap decoding took {round(end - start, 2)} seconds")
            print()


if __name__ == '__main__':
    main()
