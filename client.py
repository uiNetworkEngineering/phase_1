from scapy.all import send
from utils.packet_utils import PacketHandler, logger
import zlib


class PacketSender:
    def __init__(self, file_path, identifier, dst_ip="127.0.0.1", src_ip="127.0.0.1", ttl=64):
        self.file_path = file_path
        self.identifier = identifier
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.ttl = ttl

    def send_packet(self):
        """Reads the file, creates the inner packet, wraps it in another packet, and sends it."""
        file_data = PacketHandler.read_file(self.file_path)
        if not file_data:
            print(f"Error: No data to send from the file '{self.file_path}'")
            return

        # Create the inner packet
        inner_packet = PacketHandler.create_packet(self.src_ip, self.dst_ip, self.ttl, file_data, self.identifier)

        # Wrap the inner packet in another packet (outer packet)
        outer_packet_data = inner_packet.build()
        print(outer_packet_data[20:])
        outer_packet = PacketHandler.create_packet(self.src_ip, self.dst_ip, self.ttl, outer_packet_data, self.identifier)

        try:
            send(outer_packet)
        except Exception as e:
            print(f"Error sending packet: {e}")
            logger.error(f"Error sending packet: {e}")


if __name__ == "__main__":
    file_path = "sample.txt"  # Replace with your file path
    identifier = 65535 # Unique identifier (as an example)

    sender = PacketSender(file_path, identifier)
    sender.send_packet()
