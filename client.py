from scapy.all import send
from utils.packet_utils import logger, CustomHeader
from utils.packet_handler import PacketHandler
class PacketSender:
    def __init__(self, file_path, identifier, dst_ip="127.0.0.1", src_ip="127.0.0.1", ttl=64, seq_num=1):
        self.file_path = file_path
        self.identifier = identifier
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.ttl = ttl
        self.seq_num = seq_num

    def send_packet(self):
        """Reads the file, creates the inner packet, wraps it in another packet, and sends it."""
        file_data = PacketHandler.read_file(self.file_path)
        if not file_data:
            print(f"Error: No data to send from the file '{self.file_path}'")
            return

        # Create the inner packet and calculate its checksum
        inner_packet_checksum = CustomHeader.generate_crc32(file_data)
        inner_packet = PacketHandler.create_packet(self.src_ip, self.dst_ip, self.ttl, file_data, self.identifier, self.seq_num, inner_packet_checksum)

        # Wrap the inner packet in another packet (outer packet) and calculate its checksum
        outer_packet_data = inner_packet.build()  # Get the inner packet data
        outer_packet_checksum = CustomHeader.generate_crc32(outer_packet_data)  # Generate checksum for the outer packet

        outer_packet = PacketHandler.create_packet(self.src_ip, self.dst_ip, self.ttl, outer_packet_data, self.identifier, self.seq_num, outer_packet_checksum)

        try:
            send(outer_packet)
            print(f"Outer packet sent: {self.src_ip} -> {self.dst_ip} with custom header (ID: {self.identifier}, Seq: {self.seq_num})")
        except Exception as e:
            print(f"Error sending packet: {e}")
            logger.error(f"Error sending packet: {e}")

if __name__ == "__main__":
    file_path = "sample.txt"  # Replace with your file path
    identifier = 12345678  # Unique identifier (as an example)

    sender = PacketSender(file_path, identifier)
    sender.send_packet()
