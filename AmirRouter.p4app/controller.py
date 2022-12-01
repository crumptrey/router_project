from threading import Thread, Event, Lock
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from headers import CPUMetadata, PWOSPF
import time
from ospf_helper import *

from consts import *


class RouterController(Thread):
    def __init__(self, router, areaID, start_wait=0.3):
        super(RouterController, self).__init__()
        self.router = router
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = router.intfs[1].name
        self.switchIPs = [self.router.intfs[i].ip for i in range(1, len(self.router.intfs))]
        self.port_for_mac = {}
        self.routing_entries = {}
        self.arp_entries = {}
        self.stop_event = Event()
        
        self.arp_timeout = 30
        self.queue_timeout = 5
        self.waitingList = []
        self.waitingLock = Lock()
        self.routingLock = Lock()
        self.arpLock = Lock()
        
        self.populateTables()
        self.ospfHelper = OSPFHelper(self, areaID)
        
        Timer(1, self.timeoutTimer).start()
        
    def timeoutTimer(self):
        Timer(1, self.timeoutTimer).start()
        self.updateArpEntries()
        self.updateRoutingEntries()
        self.checkWaitingList()
    
    def checkWaitingList(self):
        to_remove = []
        with self.waitingLock:
            for item in self.waitingList:
                item[1] -= 1
                print(item[1])
                if item[1] <= 0:
                    to_remove.append(item)
            for item in to_remove:
                self.waitingList.remove(item)
        for item in to_remove:
            self.unreachable(item[0], code=1)
    
    def updateArpEntries(self):
        to_remove = []
        with self.arpLock:
            for ip in self.arp_entries:
                mac, ttl = self.arp_entries[ip]
                if ttl > 0:
                    self.arp_entries[ip] = [mac, ttl-1]
                else:
                    to_remove.append([ip, mac])
        
        for ip, mac in to_remove:
            print('Removing old ARP', ip, mac)
            self.delArpEntry(ip, mac)
                
    
    def updateRoutingEntries(self):
        pass
    
    def unreachable(self, pkt, code):
        pkt.show2()
        srcip = self.router.intfs[pkt[CPUMetadata].srcPort].ip
        srcmac = self.router.intfs[pkt[CPUMetadata].srcPort].mac
        # Constructing the packet headers
        pkt2 = Ether(src=srcmac, dst=pkt[Ether].src, type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_IP)
        pkt2 = pkt2 / IP(src=srcip, dst=pkt[IP].src, proto=IP_PROTO_ICMP) 
        pkt2 = pkt2 / pkt[ICMP]
        pkt2[ICMP].type = 3
        pkt2[ICMP].code = code
        del pkt2[ICMP].chksum
        print('Sending unreachable:', pkt2)
        self.send(pkt2)
        
    def populateTables(self):
        # Local Table
        for ip in self.switchIPs:
            self.router.insertTableEntry(table_name='MyIngress.local_table',
                    match_fields={'hdr.ipv4.dstAddr': [ip]},
                    action_name='NoAction')
        # Egress Mac Table
        for port, intf in self.router.intfs.items():
            if intf.mac and port >= 2:
                self.router.insertTableEntry(table_name='MyEgress.ports_mac_table',
                    match_fields={'standard_metadata.egress_port': [port]},
                    action_name='MyEgress.set_smac',
                    action_params={'mac': intf.mac})
        
        # Arp entry for OSPF broadcast
        # self.addArpEntry(ALLSPFRoutersIP, 'ff:ff:ff:ff:ff:ff')
    
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.router.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port
        
    def addArpEntry(self, ip, mac):
        with self.arpLock:
            if ip not in self.arp_entries:
                self.router.insertTableEntry(table_name='MyIngress.arp_table',
                            match_fields={'meta.routing.nhop_ipv4': [ip]},
                            action_name='MyIngress.set_dmac',
                            action_params={'dmac': mac})
            
            self.arp_entries[ip] = [mac, self.arp_timeout]
        
    def delArpEntry(self, ip, mac):
        with self.arpLock:
            entry = {'table_name':'MyIngress.arp_table', 'match_fields':{'meta.routing.nhop_ipv4': [ip]},
                        'action_name':'MyIngress.set_dmac',
                        'action_params':{'dmac': mac}}
            self.router.removeTableEntry(entry=entry)
            del self.arp_entries[ip]
            
        
    def addRoutingEntry(self, subnet, prefixLen, port, nhop):
        with self.routingLock:
            if (subnet, prefixLen) not in self.routing_entries:
                entry = {'table_name':'MyIngress.routing_table', 'match_fields':{'hdr.ipv4.dstAddr': [subnet, prefixLen]},
                            'action_name':'MyIngress.set_nhop',
                            'action_params':{'port': [port], 'ipv4': [nhop]}}
                
                self.router.insertTableEntry(entry=entry)
                self.routing_entries[(subnet, prefixLen)] = (port, nhop, entry)
        
    def delAllRoutingEntries(self):
        with self.routingLock:
            for item in self.routing_entries:
                _, _, entry = self.routing_entries[item]
                self.router.removeTableEntry(entry)
            self.routing_entries.clear()

    def handleArpRequest(self, pkt):
        if pkt[ARP].pdst in self.switchIPs:
            tmp = pkt[ARP].pdst
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].psrc = tmp
            
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].hwsrc = self.router.intfs[pkt[CPUMetadata].srcPort].mac
            
            pkt[ARP].op = ARP_OP_REPLY
            
            self.swapEther(pkt)
            
            self.send(pkt)
    
    def handleArpReply(self, pkt): 
        if pkt[ARP].pdst in self.switchIPs:
            print('Arp reply received!')
            to_remove = []
            with self.waitingLock:
                for item in self.waitingList:
                    nhop = item[2]
                    if nhop in self.arp_entries:
                        to_remove.append(item)
                for item in to_remove:
                    self.waitingList.remove(item)
            for item in to_remove:
                print('sending waited packets')
                self.send(item[0])
    
    def swapEther(self, pkt):
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = self.router.intfs[pkt[CPUMetadata].srcPort].mac
    
    def swapIP(self, pkt):
        tmp = pkt[IP].dst
        pkt[IP].dst = pkt[IP].src
        pkt[IP].src = tmp
    
    def handleICMP(self, pkt):
        if pkt[ICMP].type == ICMP_TYPE_REQUEST and pkt[IP].dst in self.switchIPs:
            pkt[ICMP].type = ICMP_TYPE_REPLY
            pkt[IP].ttl = 99
            self.swapIP(pkt)
            self.swapEther(pkt)
            self.send(pkt)
        elif pkt[IP].dst not in self.switchIPs:
            pkt[Ether].src = self.router.intfs[pkt[CPUMetadata].srcPort].mac
            self.send(pkt)
            

    def handlePkt(self, pkt):
        # pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        # Handling ARP packets
        if ARP in pkt:
            # if pkt[ARP].pdst in self.switchIPs:
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            self.addArpEntry(pkt[ARP].psrc, pkt[ARP].hwsrc)
            
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
                
        # Handle IP packets
        elif IP in pkt:
            if ICMP in pkt:
                self.handleICMP(pkt)
            if PWOSPF in pkt:
                self.ospfHelper.handlePacket(pkt)
        else:
            print("Not an IP packet! Dropping...")
            
    def sendArp(self, ip, port):
        print('Sending ARP...')
        intf = self.router.intfs[1]
        out_intf = self.router.intfs[port]
        pkt = Ether(src=intf.mac, dst='ff:ff:ff:ff:ff:ff', type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_ARP, outPort=port)
        pkt = pkt / ARP(hwsrc=out_intf.mac, hwdst='ff:ff:ff:ff:ff:ff', psrc=out_intf.ip, pdst=ip, op=ARP_OP_REQ)
        self.send(pkt)
        

    def findRouting(self, ip):
        port, nhop = 0,0
        with self.routingLock:
            for subnet, prefixLen in self.routing_entries.keys():
                maskedIP = self.ospfHelper.truncate(ipaddress.ip_address(ip), prefixLen)
                if maskedIP == subnet:
                    port, nhop = self.routing_entries[(subnet, prefixLen)][0], self.routing_entries[(subnet, prefixLen)][1]
        return port, nhop
            
    

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        # Check for routing entries if packet is not OSPF
        if IP in pkt and PWOSPF not in pkt:
            port, nhop_tmp = self.findRouting(pkt[IP].dst)
            nhop = None
            if nhop_tmp == '0.0.0.0':
                nhop = pkt[IP].dst
            else:
                nhop = nhop_tmp
            if (port == 0):
                print('Did not find routing for the packet. Dropping...')
                self.unreachable(pkt, code=0)
                return # drop the packet
            elif (nhop not in self.arp_entries):
                with self.waitingLock:
                    self.waitingList.append([pkt, self.queue_timeout, nhop])
                self.sendArp(nhop, port)
                return
        
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(RouterController, self).join(*args, **kwargs)
