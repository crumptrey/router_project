from threading import Thread, Event
from scapy.all import sendp
from scapy.all import get_if_addr
from scapy.all import Packet, Ether, IP, ARP, ICMP, Raw
from async_sniff import sniff
from mininet.log import lg
import ipaddress
from cpu_metadata import CPUMetadata
from pwospf import LSUINT, ALLSPFRouters_dstAddr, PWOSPF_PROTO, TYPE_HELLO, TYPE_LSU, PWOSPF, HELLO, LSUadv, LSU
import time

TYPE_CPU_METADATA = 0x080a
TYPE_IPV4 = 0x0800
TYPE_ARP = 0x0806

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

ICMP_PROTO = 0x01
ICMP_ECHO_REQUEST = 0x08
ICMP_ECHO_REPLY = 0x00
ICMP_ECHO_CODE = 0x00
ICMP_HOST_UNREACHABLE = 0x03
ICMP_HOST_UNREACHABLE_CODE = 0x01

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"

PWOSPF_VERSION = 2

CPU_PORT = 0x1

'''
PWOSPF/ARP Timing:

We need a few different threads for timing/nonsequential operations (i.e. periodically sending packets)

1) PWOSPF_HELLO
Thread that deals with periodically sending HELLO packets on each of our interfaces

2) PWOSPF_LSU
Thread that deals with Link State Updates

3) ARP_CACHE
Thread that deals with timing out ARP requests
'''
class PWOSPFInterface():
    def __init__(self, controller, port, helloint):
        self.controller = controller
        self.port = port
        self.helloint = helloint
        self.routerID = self.controller.routerID
        self.neighbor = []
        self.subnet, self.mask, self.prefixLen = self.controller.infoIP(self.port) 
        self.initializeNeighbors()

    def initializeNeighbors(self):
        for self.port, _ in self.controller.sw.intfs.items():
            if self.port > 1: # avoids controller
                self.addNeighbor(self.port, '0.0.0.0')
                subnet, mask, prefixLen = self.controller.infoIP(self.port)
                self.controller.addRoute(subnet, prefixLen, self.port, '0.0.0.0')

    def addNeighbor(self, port, routerID):
        self.neighbor.append((routerID, port))

    def removeNeighbor(self, port, routerID):
        self.neighbor.remove((routerID, port))
    
    def existentNeighbor(self, port, routerID):
        return (routerID, port) in self.neighbors

class PWOSPFHello(Thread):
    def __init__(self, controller, interface):
        super(PWOSPFHello, self).__init__()
        self.controller = controller
        self.intf = interface

    def run(self):
        for i in range(len(self.controller.sw.intfs)):
            if self.intf.port > 1:
                helloPkt = Ether()/CPUMetadata()/IP()/PWOSPF()/HELLO()
                # Ether
                helloPkt[Ether].src = self.controller.MAC
                helloPkt[Ether].dst = MAC_BROADCAST
                helloPkt[Ether].type = TYPE_CPU_METADATA  
                #IP
                helloPkt[CPUMetadata].origEtherType = TYPE_IPV4
                helloPkt[CPUMetadata].dstPort = self.intf.port
                helloPkt[IP].src = self.controller.swIP[self.intf.port]
                helloPkt[IP].dst = ALLSPFRouters_dstAddr
                helloPkt[IP].proto = PWOSPF_PROTO
                # PWOSPF
                helloPkt[PWOSPF].version = PWOSPF_VERSION
                helloPkt[PWOSPF].type = TYPE_HELLO
                helloPkt[PWOSPF].routerID = 1
                helloPkt[PWOSPF].areaID = self.controller.areaID
                helloPkt[PWOSPF].checksum = 0
                helloPkt[HELLO].mask = ((0xffffffff >> (32 - self.intf.prefixLen)) << (32 - self.intf.prefixLen))
                helloPkt[HELLO].helloint = self.controller.helloint
            
                self.controller.send(helloPkt)

        time.sleep(self.controller.helloint)

class PWOSPFLSU(Thread):
    def __init__(self, controller):
        super(PWOSPFLSU, self).__init__()
        self.controller = controller

class Controller(Thread):
    def __init__(self, sw, routerID, MAC, areaID = 1, helloint = 30, lsu_int = 3, lsu_seq = 0, start_wait=0.3):
        super(Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller
        self.iface = sw.intfs[1].name
        # Router Info
        self.MAC = MAC
        self.routerID = routerID
        self.areaID = areaID
        self.helloint = helloint
        # ARP/PWOSPF stuff
        self.ip_for_mac = {}
        self.port_for_mac = {}
        self.routes = {}
        self.arp_times = []
        self.PWOSPFInterfaces = []
        self.PWOSPFHellos = []
        self.swIP = []
        self.lsu_seq = lsu_seq
        for i in range(len(sw.intfs)):
            self.PWOSPFInterfaces.append(PWOSPFInterface(controller = self, port = i, helloint = self.helloint))
            self.PWOSPFHellos.append(PWOSPFHello(controller=self, interface=self.PWOSPFInterfaces[i]))
            self.swIP.append(self.sw.intfs[i].ip)
        self.defaultTables()
        self.flag = 0
        self.stop_event = Event()
    # 
    # *** Basic Functions ***
    #
    def infoIP(self, port):
        intf = self.sw.intfs[port]
        subnet = self.ip2masked(intf.ip, int(intf.prefixLen))
        mask = self.ip2masked('255.255.255.255', int(intf.prefixLen))
        return subnet, mask, int(intf.prefixLen)

    def ip2masked(self, ip, prefixLen: int):
        shift = 32 - prefixLen
        maskedIP = str(ipaddress.ip_address((int(ipaddress.ip_address(ip)) >> shift) << shift))
        return maskedIP
    
    def defaultTables(self):
        for i in range(len(self.sw.intfs)):
            if i > 0:
                self.addIPAddr(self.sw.intfs[i].ip,self.sw.intfs[i].mac)
        print(self.ip_for_mac)
        for port, intf in self.sw.intfs.items():
            if intf.mac and port > 1:
                self.sw.insertTableEntry(table_name='MyEgress.mac_rewrite',
                        match_fields={'standard_metadata.egress_port': [port]},
                        action_name = 'MyEgress.set_smac',
                        action_params={'mac':intf.mac})
    # *** Routing/ARP Functions and Tables ***
    #
    # Layer 2
    #
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return
        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port
    # ARP Entries 
    def addIPAddr(self, ip, mac):
        if ip in self.ip_for_mac: return
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'meta.routing.ipv4_next_hop': [ip]},
                action_name='MyIngress.arp_match',
                action_params={'dstAddr': mac})
        self.ip_for_mac[ip] = mac
        #self.arp_times[ip] = time.time()
    #
    # *** Layer 3 ***
    #
    def addRoute(self, subnet, prefixLen, port, ipv4_next_hop):
        if (subnet, prefixLen) in self.routes: return
        entry = {'table_name': 'MyIngress.routing_table',
                'match_fields':{'hdr.ipv4.dstAddr': [subnet, prefixLen]},
                'action_name':'MyIngress.ipv4_match',
                'action_params':{'port': [port], 'dstAddr':[ipv4_next_hop]}}

        self.sw.insertTableEntry(entry=entry)
        self.routes[(subnet, prefixLen)] = (port, ipv4_next_hop, entry)

    def searchRoutes(self, ip):
        for subnet, prefixLen in self.routes.keys():
            maskedIP = self.ip2masked(ipaddress.ip_address(ip), prefixLen)
            if maskedIP == subnet:
                return self.routes[(subnet, prefixLen)][0]
        return 0
            
        
                        
    # 
    # *** ARP Functionality ***
    # * generateArpRequest: function is applied when next hop pkt[Ether].dst is not in the ARP table
    # * handleArpReply: function is applied when ARP has request in it

    def generateArpRequest(self, ip, port):
        pkt = Ether()/CPUMetadata()/ARP()
        # Ether 
        pkt[Ether].src = self.sw.intfs[1].mac
        pkt[Ether].dst = MAC_BROADCAST
        pkt[Ether].type = TYPE_CPU_METADATA
        # CPU Meta
        pkt[CPUMetadata].origEtherType = TYPE_ARP
        pkt[CPUMetadata].dstPort = port
        # ARP 
        pkt[ARP].op = ARP_OP_REQ
        pkt[ARP].pdst = ip
        pkt[ARP].hwsrc = self.sw.intfs[port].mac
        pkt[ARP].psrc = self.sw.intfs[port].ip
        pkt[ARP].hwdst = MAC_BROADCAST
        pkt.show2()
        self.send(pkt)

    def handleArpReply(self, pkt):
        self.send(pkt)

    def handleArpRequest(self, pkt):
        # Destination IP address
        if pkt[ARP].pdst in self.swIP:
            dstAddr = pkt[ARP].pdst
            # Ether 
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.sw.intfs[pkt[CPUMetadata].srcPort].mac
            # CPU Meta
            # ARP
            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = self.sw.intfs[pkt[CPUMetadata].srcPort].mac
            pkt[ARP].psrc = dstAddr
            pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
            pkt[CPUMetadata].srcPort = CPU_PORT
            #pkt.show2()
            self.send(pkt)

    def icmpEcho(self, pkt):
        # Ether
        srcEth = pkt[Ether].src
        pkt[Ether].src = self.sw.intfs[pkt[CPUMetadata].srcPort].mac
        pkt[Ether].dst = srcEth
        # CPU Meta
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
        pkt[CPUMetadata].srcPort = CPU_PORT
        # IP Meta
        srcIP = pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = srcIP
        pkt[ICMP].type = ICMP_ECHO_REPLY
        pkt[ICMP].code = ICMP_ECHO_CODE
        pkt[ICMP].chksum = None
        
        self.send(pkt)

    def icmpHostUnreachable(self, pkt):
        pkt = Ether()/CPUMetadata()/IP()/ICMP()
        # Ether
        srcEth = pkt[Ether].src
        pkt[Ether].src = self.MAC
        pkt[Ether].dst = srcEth
        # CPU Meta
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
        pkt[CPUMetadata].srcPort = CPU_PORT
        # IP Meta
        srcIP = pkt[IP].src
        pkt[IP].src = pkt[IP].dst
        pkt[IP].dst = srcIP
        pkt[IP].proto = ICMP_PROTO
        # ICMP
        pkt[ICMP].type = ICMP_HOST_UNREACHABLE
        pkt[ICMP].code = ICMP_HOST_UNREACHABLE_CODE
        pkt[ICMP].chksum = None

        self.send(pkt)

    def handlePkt(self, pkt):
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

        if IP in pkt:

            port = self.searchRoutes(pkt[IP].dst)
            print(pkt[IP].dst)
            print(port)
                    
            if (pkt[IP].dst not in self.ip_for_mac):
                print('dst not in ARP')
                self.generateArpRequest(pkt[IP].dst, port)

            
            if ICMP in pkt:
                #pkt.show2()
                # Responding to ICMP ECHO requests
                if pkt[ICMP].type == ICMP_ECHO_REQUEST and pkt[ICMP].code == ICMP_ECHO_CODE:
                    self.icmpEcho(pkt)

            if PWOSPF in pkt:
                if pkt[PWOSPF].version != PWOSPF_VERSION: return
                if pkt[PWOSPF].routerID == self.routerID: return
                if pkt[PWOSPF].areaID != self.areaID: return




    def send(self, pkt, *args, **override_kwargs):
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        pkt.show2()
        sendp(pkt, *args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(Controller, self).start(*args, **kwargs)
#        for i in self.PWOSPFHellos:
#            i.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Controller, self).join(*args, **kwargs)
