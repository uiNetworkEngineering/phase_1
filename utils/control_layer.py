from scapy.all import Packet, IntField
from scapy.fields import StrField


class CustomLayer(Packet):
    name = "ControlLayer"
    fields_desc = [ IntField("chunk_number",3), StrField("load", b"")]          # Field for the raw file data (string type)


