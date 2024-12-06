from scapy.all import send, Raw
from scapy.layers.inet import IP

# Craft the IP packet with a raw payload
identifier = b"UniquePacket12345"  # Unique identifier to find the sending packet
ip_packet = IP(dst="127.0.0.1", src="127.0.0.1", ttl=64) / Raw(identifier)  # Add identifier as payload

# Send the IP packet directly to the loopback interface
send(ip_packet)
print("Packet sent")
