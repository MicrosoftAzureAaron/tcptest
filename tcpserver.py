from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
import time
import random

# Define the IP and port to listen on
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 12345

# Function to handle each connection
def handle_connection(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":  # Handle SYN packet
        # Create a random initial sequence number
        server_seq = random.randint(0, 4294967295)
        # Create a SYN-ACK packet
        syn_ack = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, seq=server_seq, ack=pkt[TCP].seq + 1, flags="SA")
        send(syn_ack)
        server_seq += 1
    elif pkt.haslayer(TCP) and pkt[TCP].flags == "A" and pkt.haslayer(Raw):  # Handle TCP Proxy V2 Payload
        payload = pkt[Raw].load
        if payload.startswith(b'\r\n\r\n') or payload.startswith(b'PROXY'):
            print(f"TCP Proxy V2 Payload: {payload}")
    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):  # Handle data from client, and send FINACK
        #payload = pkt[Raw].load
        #print(f"Payload: {payload}")
        print("Received Payload from Client, Sending FIN ACK")
        fin_ack = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                  TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, seq=server_seq, ack=pkt[TCP].seq + len(pkt[Raw].load), flags="FA")
        send(fin_ack)
    elif pkt.haslayer(TCP) and pkt[TCP].flags == "FA":  # Handle FINACK from client
        print("Received FIN-ACK from Client")
        # Send ACK in response to FIN-ACK
        ack = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
              TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, seq=pkt[TCP].ack, ack=pkt[TCP].seq + 1, flags="A")
        send(ack)

# Function to start the server, listen for packets
def start_server():
    sniff(filter=f"tcp and dst port {LISTEN_PORT}", prn=handle_connection)

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()