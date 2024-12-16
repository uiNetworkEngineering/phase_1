from scapy.all import Packet, IntField
from scapy.fields import StrField


class CustomLayer(Packet):
    name = "ControlLayer"
    fields_desc = [ IntField("more_chunk",0),IntField("seq_number",0), StrField("load", b"")]          # Field for the raw file data (string type)


