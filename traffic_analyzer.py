from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP


packet_count = 0
protocol_counter = Counter()
destination_port_counter = Counter()


def analyze_packet(packet):
    """Analyze and display one captured IP packet."""
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    protocol_counter[protocol] += 1

    if destination_port != "-":
        destination_port_counter[destination_port] += 1

    print(
        f"[{packet_count:03}] "
        f"{timestamp} | "
        f"{source_ip:<15} -> "
        f"{destination_ip:<15} | "
        f"{protocol:<5} | "
        f"{str(source_port):<6} -> "
        f"{destination_port}"
    )


def print_summary():
    """Display capture statistics."""
    print("\n" + "=" * 80)
    print("CAPTURE SUMMARY")
    print("=" * 80)

    print(f"Total packets captured: {packet_count}")

    print("\nProtocol Statistics:")

    for protocol, count in protocol_counter.most_common():
        print(f"  {protocol:<8}: {count}")

    print("\nTop Destination Ports:")

    if destination_port_counter:
        for port, count in destination_port_counter.most_common(10):
            print(f"  Port {port:<5}: {count} packets")
    else:
        print("  No TCP/UDP destination ports detected.")

    print("=" * 80)


def main():
    print("=" * 80)
    print("                  NETWORK TRAFFIC ANALYZER")
    print("=" * 80)

    print("\nThis tool captures basic IP packet metadata.")
    print("Use it only on networks/interfaces you are authorized to monitor.")

    try:
        packet_limit = int(
            input("\nEnter number of packets to capture [default 20]: ").strip() or "20"
        )

        if packet_limit <= 0:
            print("[-] Packet count must be greater than zero.")
            return

    except ValueError:
        print("[-] Please enter a valid number.")
        return

    print(f"\n[+] Capturing {packet_limit} packets...")
    print("[+] Generate some network traffic while capture is running.\n")

    print(
        f"{'NO.':<5}"
        f"{'TIME':<9}"
        f"{'SOURCE IP':<18}"
        f"{'DESTINATION IP':<18}"
        f"{'PROTO':<8}"
        f"{'PORTS'}"
    )

    print("-" * 80)

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            count=packet_limit,
            store=False
        )

    except PermissionError:
        print("\n[-] Permission denied.")
        print("[!] Try running the terminal with Administrator privileges.")

        return

    except Exception as error:
        print(f"\n[-] Capture error: {error}")
        return

    print_summary()


if __name__ == "__main__":
    main()