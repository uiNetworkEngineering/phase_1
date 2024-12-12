import logging
import struct

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class CustomHeader:
    """Class representing the custom header for packet."""

    def __init__(self, identifier, timestamp, seq_num, checksum=None):
        self.identifier = identifier
        self.timestamp = timestamp
        self.seq_num = seq_num
        self.checksum = checksum if checksum is not None else 0  # Default checksum to 0 if not provided

    def build_header(self):
        """Builds the custom header."""
        return self.identifier.to_bytes(4, byteorder='big') + \
               self.timestamp.to_bytes(4, byteorder='big') + \
               self.seq_num.to_bytes(4, byteorder='big') + \
               self.checksum.to_bytes(4, byteorder='big')

    @classmethod
    def from_bytes(cls, header_bytes):
        """Converts raw bytes into a CustomHeader instance."""
        identifier = int.from_bytes(header_bytes[:4], byteorder='big')
        timestamp = int.from_bytes(header_bytes[4:8], byteorder='big')
        seq_num = int.from_bytes(header_bytes[8:12], byteorder='big')
        checksum = int.from_bytes(header_bytes[12:16], byteorder='big')
        return cls(identifier, timestamp, seq_num, checksum)

    @staticmethod
    def checksum(data):
        """Calculate the one's complement checksum."""
        if len(data) % 2 == 1:
            data += b'\0'  # If odd, pad with a zero byte
        s = sum(struct.unpack('!%sH' % (len(data) // 2), data))  # Unpack as 16-bit words
        s = (s >> 16) + (s & 0xFFFF)  # Add the carry bits
        s += (s >> 16)  # Add carry if necessary
        return ~s & 0xFFFF  # Return one's complement

    @staticmethod
    def calculate_ip_checksum(ip_header):
        """Calculate checksum for an IP header."""
        return CustomHeader.checksum(ip_header)
