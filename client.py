from scapy.all import send, Raw
from scapy.layers.inet import IP

# Function to read the content of a file
def read_file(file_path):
    with open(file_path, "rb") as f:
        file_content = f.read()
    return file_content

# Path to the file you want to send
file_path = "./sample.txt"  # Replace with your file path

# Read the file content
file_data = read_file(file_path)

# Define the identifier (this could be anything you want to tag the packet with)
identifier = b"UniquePacket12345"

# Combine the identifier and the file content into a single payload
combined_payload = identifier + file_data

# Create an IP packet with the combined payload (identifier + file content)
ip_packet = IP(dst="127.0.0.1", src="127.0.0.1", ttl=64) / Raw(combined_payload)

# Send the packet
send(ip_packet)
print("Packet with identifier and file content sent")
