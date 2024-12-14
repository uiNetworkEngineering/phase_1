import os
import logging
from scapy.layers.inet import IP
from utils.utills import checksum

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class CustomHeader:
    """Class representing the custom header for packet."""

    def __init__(self, identifier, seq_num):
        self.identifier = identifier
        self.seq_num = seq_num

    @classmethod
    def from_bytes(cls, header_bytes):
        """Converts raw bytes into a CustomHeader instance."""
        identifier = int.from_bytes(header_bytes[:4], byteorder='big')
        seq_num = int.from_bytes(header_bytes[4:8], byteorder='big')
        return cls(identifier, seq_num)


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
    def create_packet(src_ip, dst_ip, ttl, file_data, identifier):
        """Creates an IP packet with a custom header and the file data."""
        result = IP(src=src_ip, dst=dst_ip, ttl=ttl, version=4, id=65535)

        # Add the custom header and file data as payload
        result.add_payload(file_data)

        # Calculate checksum over the first 20 bytes of the IP header (without the checksum)
        raw_ip_header = bytes(result)  # Get the raw packet including the payload
        result.chksum = 0  # Set checksum to 0 before calculating
        calculated_checksum = checksum(raw_ip_header[:20])  # Only the first 20 bytes (IP header)

        # Set the checksum in the IP header
        result.chksum = calculated_checksum

        return result
