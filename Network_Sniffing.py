from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Other"

        # Print packet details
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol_name}")

        if TCP in packet or UDP in packet:
            payload = packet[TCP].payload if TCP in packet else packet[UDP].payload
            print(f"Payload (truncated): {bytes(payload)[:100]}")  # Limit payload printout to 100 bytes

        print("-" * 60)

def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffer on {interface}")
    # Filter to capture only TCP and UDP packets
    sniff(iface=interface, prn=packet_callback, store=0, filter="tcp or udp")

if __name__ == "__main__":
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    start_sniffing(interface)
