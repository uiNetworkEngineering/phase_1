# packet_sender.py
from scapy.all import send, Raw
from scapy.layers.inet import IP

class Client:
    def __init__(self, file_path, identifier, dst_ip="127.0.0.1", src_ip="127.0.0.1", ttl=64):
        self.file_path = file_path
        self.identifier = identifier
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.ttl = ttl

    def read_file(self):
        """Reads the content of the file."""
        with open(self.file_path, "rb") as f:
            return f.read()

    def create_packet(self, file_data):
        """Creates an IP packet with the identifier and file data."""
        combined_payload = self.identifier + file_data
        return IP(src=self.src_ip, dst=self.dst_ip, ttl=self.ttl) / Raw(combined_payload)

    def send_packet(self):
        """Sends the crafted packet."""
        file_data = self.read_file()
        packet = self.create_packet(file_data)
        send(packet)
        print(f"Packet sent: {self.src_ip} -> {self.dst_ip} with identifier: {self.identifier}")

# Main execution flow
if __name__ == "__main__":
    # Define your file path and identifier
    file_path = "sample.txt"  # Replace with your file path
    identifier = b"UniquePacket12345"

    # Create a PacketSender instance and send the packet
    sender = Client(file_path, identifier)
    sender.send_packet()
