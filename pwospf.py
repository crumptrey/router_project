from scapy.fields import ByteField, ShortField, IntField, LongField, IPField, FieldLenField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

LSUINT = 30
ALLSPFRouters_dstAddr = '224.0.0.5'
PWOSPF_PROTO = 0x59
TYPE_HELLO = 0x01
TYPE_LSU = 0x04

'''
PWOSPF Packet Header Format

  All PWOSPF packets are encapsulated in a common header that is identical to
  the OSPFv2 header.   Using the OSPFv2 header will allow PWOSPF to converge on
  OSPF compliance in the future and is recognized by protocol analyzers such
  as ethereal which can greatly aid in debugging.  The PWOSPF header is as
  follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version #   |     Type      |         Packet length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Router ID                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Area ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |             Autype            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Authentication                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Authentication                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


'''
class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [
        ByteField("version", None),            
        ByteField("type", None),
        ShortField("length", None),
        IPField("routerID", None),
        IntField("areaID", None),
        ShortField("checksum", None),
        ShortField("auType", 0), # auType set to zero in PWOSPF
        LongField("auth", 0) # auth set to zero in PWOSPF
        ]
'''
HELLO Packet Format

  Hello packets are PWOSPF packet type 1.  These packets are sent periodically
  on all interfaces in order to establish and maintain neighbor relationships.
  In addition, Hellos broadcast enabling dynamic discovery of neighboring
  routers.

  All routers connected to a common network must agree on certain parameters
  (network mask and helloint).  These parameters are included in Hello packets,
  so that differences can inhibit the forming of neighbor relationships.  A
  full HELLO packet with PWOSPF header is as follows:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Version #   |       1       |         Packet length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Router ID                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Area ID                             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           Checksum            |             Autype            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Authentication                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Authentication                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Network Mask                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         HelloInt              |           padding             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
# Type: 1
class HELLO(Packet):
    name = "HELLO"
    fields_desc = [
        IPField("mask", None),
        ShortField("helloint", None),
        ShortField("padding", 0)
        ]
'''
LSU Packet Format

  LSU packets implement the flooding of link states and  are used to build and
  maintain the network topology database at each router.  Each link state
  update packet carries a collection of link state advertisements on hop
  further from its origin.  Several link state advertisements may be included
  in a single packet.  A link state packet with full PWOSF header looks as
  follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version #   |       4       |         Packet length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Router ID                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Area ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |             Autype            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Authentication                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Authentication                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Sequence                |          TTL                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      # advertisements                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-                                                            +-+
   |                  Link state advertisements                    |
   +-                                                            +-+
   |                              ...                              |
Link state advertisements

   Each link state update packet should contain 1 or more link state
   advertisements.  The advertisements are the reachable routes directly
   connected to the advertising router.  Routes are in the form of the subnet,
   mask and router neighor for the attached link. Link state advertisements
   look specifically as follows:

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Subnet                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Mask                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Router ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
class LSUadv(Packet):
    name = "LSUadv"
    fields_desc = [
        IPField("subnet", None),
        IPField("mask", None),
        IPField("routerID", None)
        ]
    def extract_padding(self, s):
        return '', s

class LSU(Packet):
    name = "LSU"
    fields_desc = [
        ShortField("sequence", None),
        ShortField("ttl", None),
        FieldLenField("numAdvs", None, fmt = "I", count_of = "Advs"),
        PacketListField("Advs", None, LSUadv, count_from = lambda pkt: pkt.numAdvs)
        ]
    def extract_padding(self, s):
        return '', s

bind_layers(IP, PWOSPF, proto = PWOSPF_PROTO)
bind_layers(PWOSPF, HELLO, type = TYPE_HELLO)
bind_layers(PWOSPF, LSU, type = TYPE_LSU)

