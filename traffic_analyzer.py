import csv
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap


# Ports worth flagging for analyst attention.
# A match does NOT mean malicious activity; it is simply a watchlist event.
WATCHLIST_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Common Metasploit test port",
    5900: "VNC",
}

packets_data = []
protocol_counter = Counter()
destination_port_counter = Counter()
alert_counter = Counter()


def analyze_packet(packet):
    """Analyze and store information from one IP packet."""

    if IP not in packet:
        return

    packet_number = len(packets_data) + 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"
    source_port = ""
    destination_port = ""
    alert = ""

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

    if destination_port != "":
        destination_port_counter[destination_port] += 1

        if destination_port in WATCHLIST_PORTS:
            alert = f"Watchlist port {destination_port} ({WATCHLIST_PORTS[destination_port]})"
            alert_counter[destination_port] += 1

    packet_info = {
        "packet_number": packet_number,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "alert": alert,
    }

    packets_data.append(packet_info)

    alert_marker = f" | ALERT: {alert}" if alert else ""

    print(
        f"[{packet_number:03}] "
        f"{timestamp} | "
        f"{source_ip:<15} -> "
        f"{destination_ip:<15} | "
        f"{protocol:<5} | "
        f"{str(source_port):<6} -> "
        f"{str(destination_port):<5}"
        f"{alert_marker}"
    )


def export_csv(filename="traffic_capture.csv"):
    """Export captured packet information to CSV."""

    if not packets_data:
        print("\n[-] No packet data available for CSV export.")
        return

    fieldnames = [
        "packet_number",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "alert",
    ]

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(packets_data)

        print(f"[+] CSV report saved as: {filename}")

    except OSError as error:
        print(f"[-] Could not create CSV report: {error}")


def print_summary():
    """Display final capture statistics."""

    print("\n" + "=" * 80)
    print("CAPTURE SUMMARY")
    print("=" * 80)

    print(f"Total packets captured: {len(packets_data)}")

    print("\nProtocol Statistics:")
    if protocol_counter:
        for protocol, count in protocol_counter.most_common():
            print(f"  {protocol:<8}: {count}")
    else:
        print("  No protocol data available.")

    print("\nTop Destination Ports:")
    if destination_port_counter:
        for port, count in destination_port_counter.most_common(10):
            print(f"  Port {port:<5}: {count} packets")
    else:
        print("  No TCP/UDP destination ports detected.")

    print("\nWatchlist Events:")
    if alert_counter:
        for port, count in alert_counter.most_common():
            print(
                f"  Port {port:<5} "
                f"({WATCHLIST_PORTS[port]}): {count} packet(s)"
            )
    else:
        print("  No watchlist ports observed.")

    print("=" * 80)


def main():
    print("=" * 80)
    print("                 NETWORK TRAFFIC ANALYZER")
    print("=" * 80)

    print("\nFeatures:")
    print("  • Packet capture")
    print("  • Protocol statistics")
    print("  • Port statistics")
    print("  • Watchlist alerts")
    print("  • CSV reporting")
    print("  • PCAP export for Wireshark")

    print(
        "\nUse this tool only on network interfaces "
        "you are authorized to monitor."
    )

    try:
        packet_limit = int(
            input(
                "\nEnter number of packets to capture [default 20]: "
            ).strip()
            or "20"
        )

        if packet_limit <= 0:
            print("[-] Packet count must be greater than zero.")
            return

    except ValueError:
        print("[-] Please enter a valid number.")
        return

    pcap_filename = "traffic_capture.pcap"

    print(f"\n[+] Capturing {packet_limit} packets...")
    print("[+] Generate some network traffic while capture is running.\n")

    print(
        f"{'NO.':<5}"
        f"{'TIME':<20}"
        f"{'SOURCE IP':<18}"
        f"{'DESTINATION IP':<18}"
        f"{'PROTO':<8}"
        f"{'PORTS'}"
    )

    print("-" * 80)

    try:
        captured_packets = sniff(
            filter="ip",
            prn=analyze_packet,
            count=packet_limit,
            store=True
        )

    except PermissionError:
        print("\n[-] Permission denied.")
        print("[!] Try running CMD as Administrator.")
        return

    except Exception as error:
        print(f"\n[-] Capture error: {error}")
        return

    # Save raw packets for Wireshark.
    try:
        wrpcap(pcap_filename, captured_packets)
        print(f"\n[+] PCAP capture saved as: {pcap_filename}")
    except OSError as error:
        print(f"\n[-] Could not save PCAP: {error}")

    print_summary()

    export_choice = input(
        "\nExport packet information to CSV? (y/n): "
    ).strip().lower()

    if export_choice == "y":
        export_csv()

    print("\n[+] Analysis complete.")


if __name__ == "__main__":
    main()