import time
import os
from scapy.layers.inet import IP
from scapy.all import Raw
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class CustomHeader:
    """Class representing the custom header for packet."""

    def __init__(self, identifier, timestamp, seq_num):
        self.identifier = identifier
        self.timestamp = timestamp
        self.seq_num = seq_num

    def build_header(self):
        """Builds the custom header."""
        return self.identifier.to_bytes(4, byteorder='big') + \
               self.timestamp.to_bytes(4, byteorder='big') + \
               self.seq_num.to_bytes(4, byteorder='big')

    @classmethod
    def from_bytes(cls, header_bytes):
        """Converts raw bytes into a CustomHeader instance."""
        identifier = int.from_bytes(header_bytes[:4], byteorder='big')
        timestamp = int.from_bytes(header_bytes[4:8], byteorder='big')
        seq_num = int.from_bytes(header_bytes[8:12], byteorder='big')
        return cls(identifier, timestamp, seq_num)


class PacketHandler:
    """Class for handling packet operations like file reading and packet creation."""

    @staticmethod
    def read_file(file_path):
        """Reads the content of a file and returns its data."""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return b""
            with open(file_path, "rb") as f:
                file_data = f.read()
            logger.info(f"File '{file_path}' read successfully.")
            return file_data
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return b""

    @staticmethod
    def create_packet(src_ip, dst_ip, ttl, file_data, identifier, seq_num):
        """Creates an IP packet with a custom header and the file data."""
        timestamp = int(time.time())
        header = CustomHeader(identifier, timestamp, seq_num).build_header()
        combined_payload = header + file_data
        return IP(src=src_ip, dst=dst_ip, ttl=ttl) / Raw(combined_payload)