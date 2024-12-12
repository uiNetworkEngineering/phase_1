

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

