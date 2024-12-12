import logging
import struct

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def checksum(data):
    """Calculate the one's complement checksum."""
    if len(data) % 2 == 1:
        data += b'\0'  # If odd, pad with a zero byte
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))  # Unpack as 16-bit words
    s = (s >> 16) + (s & 0xFFFF)  # Add the carry bits
    s += (s >> 16)  # Add carry if necessary
    return ~s & 0xFFFF  # Return one's complement