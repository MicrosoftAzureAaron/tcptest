#import argparse
import time
import random
from scapy.all import IP, TCP, sr1, send, sniff, DNS, DNSQR, Raw
from scapy.all import conf

# Set the path to the manuf file
conf.manufdb = "C:/Program Files/Wireshark/manuf"

# # Parse command-line arguments
# parser = argparse.ArgumentParser(description="TCP connection script")
# parser.add_argument("--destination_ip", required=True, help="Destination IP address")
# parser.add_argument("--destination_port", type=int, required=True, help="Destination port")
# parser.add_argument("--source_ip", required=True, help="Source IP address")
# parser.add_argument("--source_port", type=int, required=True, help="Source port")
# args = parser.parse_args()

# # Define the destination details
# destination_ip = args.destination_ip
# destination_port = args.destination_port
# source_port = args.source_port
# source_ip = args.source_ip

# hardcore the destination details use above args when scripting
destination_ip = '192.168.1.75'
destination_port = 12345
source_port = random.randint(30000, 59999)
source_ip = '192.168.1.156'

# Initialize a random starting value for IP.id
ip_id = random.randint(0, 65535)

# Initialize sequence number
seq_num = 2147483600

# Step 1: SYN packet (part of 3-way handshake)
syn = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags="S", seq=seq_num) 
syn_ack = sr1(syn, timeout=2)  # Send SYN and receive SYN-ACK
seq_num += 1  # Increment SEQ number
ip_id += 1  # Increment IP.id

if not syn_ack:
    print("No response to SYN packet. Exiting...")
    exit()

# Step 2: ACK packet (completing the handshake)
ack = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags="A", seq=seq_num, ack=syn_ack.seq)
send(ack)
print("Sent ACK")
#seq_num += 1  # Increment SEQ number
ip_id += 1  # Increment IP.id

def send_packet(payload, flags="PA"):
    global seq_num, ip_id
    pkt = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags=flags, seq=seq_num, ack=syn_ack.seq) / Raw(load=payload)
#   pkt = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags=flags, seq=seq_num) / Raw(load=payload)
    send(pkt)


# Step 3: Send data
payload = "Hello, this is a test!"  # Replace with your data
send_packet(payload)
seq_num += len(payload) # Increment SEQ number by the length of the payload
ip_id += 1  # Increment IP.id
print("Sent Data Payload")

# # Step 3: Send DNS query | was using this against my router as legit DNS traffic
# dns_query = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags="PA", seq=seq_num, ack=syn_ack.seq + 1) / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
# send(dns_query)
# seq_num += 1  # Increment SEQ number
# ip_id += 1  # Increment IP.id

#define a filter to capture the server's FIN-ACK packet
def capture_server_fin(packet):
    return (
        IP in packet and
        TCP in packet and 
        packet[IP].src == destination_ip and
        packet[IP].dst == source_ip and
        packet[TCP].flags == "FA"
    )

print("Waiting for server to send FIN-ACK...")
server_fin_ack = sniff(filter=f"tcp and host {destination_ip} and port {destination_port}", stop_filter=capture_server_fin, timeout=20)

if not server_fin_ack:
    print("No FIN-ACK received from the server after 20 seconds. Exiting...")
    exit()

server_fin_ack = server_fin_ack[0]
print(f"Captured server's FIN-ACK: {server_fin_ack.summary()}")

# # Acknowledge the server's FIN
# ack_to_server_fin = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags="A", seq=seq_num, ack=server_fin_ack.seq + 1)
# send(ack_to_server_fin)
# seq_num += 1  # Increment SEQ number
# ip_id += 1  # Increment IP.id

# print("Acknowledged server's FIN-ACK.")

# Wait for 18 seconds
print("Waiting for 18 seconds before sending client's FIN...")
time.sleep(18)

# Send the client's FIN
client_fin = IP(src=source_ip, dst=destination_ip, id=ip_id) / TCP(sport=source_port, dport=destination_port, flags="FA", seq=seq_num, ack=server_fin_ack.seq + 1)
#fin_ack_from_server = sr1(client_fin, timeout=5)
send(client_fin)
seq_num += 1  # Increment SEQ number
ip_id += 1  # Increment IP.id

# if fin_ack_from_server:
#     print(f"Captured server's ACK for client FIN: {fin_ack_from_server.summary()}")
#     print("FIN-ACK sequence with 18-second delay completed.")
# else:
#     print("No ACK received for client's FIN.")
 
# def packet_filter(packet):#, destination_ip):
#     # Check if the packet has the necessary layers and matches criteria
#     if (
#         IP in packet and
#         TCP in packet and
#         #packet[IP].dst == destination_ip and
#         #packet[TCP].dport == destination_port and
#         packet[TCP].flags == "R" and  # TCP RST flag
#         packet[IP].id == 1  # IP ID is 1
#     ):
#         print(f"RST Packet Caught: {packet.summary()}")
#         print(f"Source IP: {packet[IP].src}, Source Port: {packet[TCP].sport}")
#         print(f"Destination IP: {packet[IP].dst}, Destination Port: {packet[TCP].dport}")
#         print(f"IP ID: {packet[IP].id}")

# # Start sniffing packets
# print(f"Listening for RST packets on {source_ip}:{source_port} with IP ID=1...")
# sniff(filter=f"tcp port {source_port}", prn=packet_filter, timeout=5) ##ADJUST TIMEOUT FOR VFP RST