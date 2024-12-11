import zlib
import logging

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
    def generate_crc32(data):
        """Generate CRC32 checksum for the provided data."""
        return zlib.crc32(data) & 0xffffffff

    @staticmethod
    def validate_crc32(data, expected_crc32):
        """Validate the CRC32 checksum of the given data."""
        calculated_crc32 = zlib.crc32(data) & 0xffffffff
        return calculated_crc32 == expected_crc32

