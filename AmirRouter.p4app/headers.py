from scapy.fields import IntField, ByteField, ShortField, LongField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from consts import *

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ByteField("fromCpu", 0),
                    ShortField("origEtherType", None),
                    ShortField("srcPort", None),
                    ShortField("outPort", 0)
                    ]

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [ ByteField("version", None),
                    ByteField("type", None),
                    ShortField("totalLen", None),
                    IntField("routerID", None),
                    IntField("areaID", None),
                    ShortField("checksum", None),
                    ShortField("auType", None),
                    LongField("authentication", None)
                    ]


bind_layers(Ether, CPUMetadata)
bind_layers(CPUMetadata, IP, origEtherType=ETHER_TYPE_IP)
bind_layers(CPUMetadata, ARP, origEtherType=ETHER_TYPE_ARP)

bind_layers(IP, PWOSPF, proto=IP_PROTO_PWOSPF)