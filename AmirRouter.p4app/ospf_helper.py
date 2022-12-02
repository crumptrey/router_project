import time
from threading import Thread, Timer
import ipaddress
from headers import *
from scapy.all import ARP, ICMP, IP, Ether, Packet, Raw

from consts import *
import io

import os
os.system('pip install networkx==2.2')
import networkx as nx


class OSPFHelper:
    def __init__(self, controller, areaID, hello_int=40, lsuint=40):
        self.arp_table = {}
        self.neighborsTTL = {}
        self.global_routes = {}
        self.controller = controller
        self.router = controller.router
        self.areaID = areaID
        self.hello_int = hello_int
        self.lsuint = lsuint
        
        self.LSUsequence = 0
        
        self.control_intf = controller.router.intfs[1]
        self.routerID = int(ipaddress.ip_address(self.control_intf.ip))
        self.neighbor_timeout = 3 * hello_int
        self.routerID_to_ip = {} # Helpful dict that keeps track of the interface ip address of the neighboring router. 
        
        self.global_topo = nx.Graph()
        self.lsu_history = {}
        self.addInitialNeighbors()
        self.constructGlobalTopo()
        self.addAllShortestPaths()
        
        Timer(5, self.startHelloBroadcast).start()
        Timer(10, self.startLSUBroadcast).start()
        # Timer(2, self.timeoutTimer).start()
        
    # def timeoutTimer(self):
    #     Timer(1, self.timeoutTimer).start()
    #     to_remove = []
    #     for ip in self.lsu_history:
    #         self.lsu_history[ip]['time'] -= 1
    #         if self.lsu_history[ip]['time'] < 0:
    #             to_remove.append(ip)
        
    #     if len(to_remove) > 0:
    #         for ip in to_remove:
    #             del self.lsu_history[ip]
    #         self.constructGlobalTopo()
    #         self.addAllShortestPaths()
    
    def addInitialNeighbors(self):
        """
        Adds directly connected subnets to the list of neighbors. Also creates a fake LSU data for itself to be used later by 
        constructGlobalTopo.
        """
        data = {} 
        i = 0
        # Adding initial neighbors
        for port, _ in self.router.intfs.items():
            if port >= 2:
                self.addNeighbor(port, '0.0.0.0', 99999)
                subnet, mask, prefixLen = self.getSubnetAndMask(port)
                data[i] = {'subnet': subnet, 'mask': mask, 'neighborID': '0.0.0.0'}
                i += 1
        # Create a fake lsu history for self
        self.lsu_history[self.routerID] = {'seq': 0, 'data': data, 'time': 99999999}
        
    def handlePacket(self, pkt):
        """
        The function that is called when receiving a PWOSPF packet by controller. 
        """
        if pkt[PWOSPF].type == PWOSPF_TYPE_HELLO:
            self.handleHelloPacket(pkt)
        elif pkt[PWOSPF].type == PWOSPF_TYPE_LSU:
            self.processLSUPacket(pkt)
        else:
            print('Unkown PWOSPF type received, dropping...')
    
    def handleHelloPacket(self, pkt):
        """
        Reads the hello packet. Checks the netmask and hello_int match the source interface values, and add the sender of the packet
        to the list of neighbors.
        """
        interface = self.router.intfs[pkt[CPUMetadata].srcPort]
        
        routerID = pkt[PWOSPF].routerID
        payload = io.BytesIO(bytes(pkt[Raw]))
        netMask = str(ipaddress.ip_address(payload.read(4)))
        helloInt = payload.read(2)
        
        print('Hello packet data received at ID={}: '.format(ipaddress.ip_address(self.routerID)))
        # print(' RouterID: {}, netmask: {}, helloInt: {}'.format(ipaddress.ip_address(pkt[PWOSPF].routerID), netMask, helloInt))
        
        if (netMask == self.truncate("255.255.255.255", int(interface.prefixLen)) and
                    int.from_bytes(helloInt, 'big') == self.hello_int):
            self.addNeighbor(pkt[CPUMetadata].srcPort, routerID, self.neighbor_timeout)
        else:
            print("helloInt or netMask does not match!!!")
        
        # Saves the nhop value if we're later required to forward packets to this router.
        self.routerID_to_ip[str(ipaddress.ip_address(routerID))] = {'nhop': str(ipaddress.ip_address(pkt[IP].src)),
                                                                    'port': pkt[CPUMetadata].srcPort}
    
    def processLSUPacket(self, pkt):
        """
        Reads the incoming packet. Drop it if seq is old, ttl=0 or sent by itself. Constructs the global topology if packet data
        is new and populate routing tables
        """
        senderID = pkt[PWOSPF].routerID
        payload = io.BytesIO(bytes(pkt[Raw]))
        
        seq = int.from_bytes(payload.read(2), 'big')
        ttl = int.from_bytes(payload.read(2), 'big')
        n = int.from_bytes(payload.read(4), 'big')
        
        data = {}
        for i in range(n):
            subnet = str(ipaddress.ip_address(payload.read(4)))
            mask = str(ipaddress.ip_address(payload.read(4)))
            neighborID = str(ipaddress.ip_address(payload.read(4)))
            data[i] = {'subnet': subnet, 'mask': mask, 'neighborID': neighborID}
            
        print('LSU packet data received at ID={}: '.format(ipaddress.ip_address(self.routerID)))
        # print(data)
        
        # Drop if created by yourself
        if ttl == 0:
            print('Dropping the lsu packet due to zero TTL')
            return
        if self.routerID == senderID:
            print('Dropping the lsu packet due to receiving own packet')
            return
        # Drop if seq matches the last received packet by this router
        if senderID in self.lsu_history and self.lsu_history[senderID]['seq'] == seq:
            print('Dropping the lsu packet due to receiving old seq number')
            return
        # Update seq if data matches the last received packet by this router
        if senderID in self.lsu_history and self.lsu_history[senderID]['data'] == data:
            self.lsu_history[senderID]['seq'] = seq
            print('Updating the sequence number: the lsu packet with same data as before')
        else:
            self.lsu_history[senderID] = {'seq': seq, 'data': data, 'time': self.neighbor_timeout}
            self.constructGlobalTopo()
            self.addAllShortestPaths()
        
        self.broadcastOthersLSUPacket(pkt)
        
    
    def constructGlobalTopo(self):
        """
        Contructs the global topology using the received data by all routers.
        """
        self.global_topo.clear()
        self.global_routes.clear()
        
        for id in self.lsu_history:
            self.updateTopoWithData(id, self.lsu_history[id]['data'])
        
        # print('Edges at id={}\n'.format(self.routerID), self.global_topo.edges)
    
    def addAllShortestPaths(self):
        """
        Finds all the shortest paths from this node to other subnets and write them on the routing table 
        """
        source = (str(ipaddress.ip_address(self.routerID)), '255.255.255.255')
        shortest_paths = nx.shortest_path(self.global_topo, source=source)
        
        # Clear the data plane routing table
        self.controller.delAllRoutingEntries()
        # Add direct connectivities
        for port, _ in self.router.intfs.items():
            if port >= 2:
                subnet, mask, prefixLen = self.getSubnetAndMask(port)
                self.controller.addRoutingEntry(subnet, prefixLen, port, '0.0.0.0')
        
        # print(shortest_paths)
        # Add remote subnets
        for dst in shortest_paths:
            # Path to itself
            if len(shortest_paths[dst]) == 1: continue
            
            nhop = shortest_paths[dst][1]
            # If nhop is a router then add the entry
            if nhop[1] == '255.255.255.255':
                subnet, mask = dst
                prefixLen = self.maskToPrefix(mask)
                nhop_rid = nhop[0]
                
                if nhop_rid in self.routerID_to_ip:
                    nhop_ip = self.routerID_to_ip[nhop_rid]['nhop']
                    nhop_port = self.routerID_to_ip[nhop_rid]['port']
                    
                    self.controller.addRoutingEntry(subnet, prefixLen, nhop_port, nhop_ip)
                else:
                    print("Something is wrong in finding the neighbor router")
                    
            
    def maskToPrefix(self, mask):
        """
        Translates a mask to prefixLength, e.g '255.255.255.0' to 24
        """
        m = int(ipaddress.ip_address(mask))
        i = 0
        while m % 2 == 0:
            m /= 2
            i += 1
        return 32 - i
            
        
    def updateTopoWithData(self, id, data):
        """
        Adds the edges defined in data to the global topology
        """
        for i in data:
            src = (str(ipaddress.ip_address(id)), '255.255.255.255')
            dst = (0,0)
            if data[i]['neighborID'] == '0.0.0.0':
                dst = (data[i]['subnet'], data[i]['mask'])
            else:
                dst = (str(ipaddress.ip_address(data[i]['neighborID'])), '255.255.255.255')
            self.global_topo.add_edge(src, dst)

    def getSubnetAndMask(self, port):
        """
        returns the subent, mask, and prefixLen of the interface on #port 
        """
        intf = self.router.intfs[port]
        subnet = self.truncate(intf.ip, int(intf.prefixLen))
        mask = self.truncate('255.255.255.255', int(intf.prefixLen))
        return subnet, mask, int(intf.prefixLen)
    
    def truncate(self, ip, prefixLen: int):
        """ 
        Masks the ip with the appropriate prefix length.
        """
        assert (prefixLen <= 32 and prefixLen >= 0)
        shift = 32 - prefixLen
        ip_l = int(ipaddress.ip_address(ip))
        masked_l = (ip_l >> shift) << shift
        return str(ipaddress.ip_address(masked_l))
    
    def addNeighbor(self, port, routerID, ttl):
        assert port > 1
        if port not in self.neighborsTTL:
            self.neighborsTTL[port] = {}
        
        id = str(ipaddress.ip_address(routerID))
        self.neighborsTTL[port][id] = ttl
    
    # def timeoutTimer(self):
    #     seconds = 10
    #     Timer(seconds, self.timeoutTimer).start()
        
    #     print('neighbors of {}:'.format(self.routerID))
    #     for port in self.neighborsTTL.keys():
    #         subnet, mask, _ = self.getSubnetAndMask(port)
    #         for id in self.neighborsTTL[port].keys():
    #             self.neighborsTTL[port][id] -= seconds
    #             print('subnet = {}, mask = {}, routerID = {}, ttl = {}'.format(subnet, mask, id, self.neighborsTTL[port][id]))
        
    
    def genHello(self, port, intf):
        """
        Generates a hello packets to be sent on intf with port number port
        """
        # Creating the hello packet data
        prefixLen = 32 - int(intf.prefixLen)
        mask = ((0xFFFFFFFF >> prefixLen) << prefixLen).to_bytes(4, 'big')
        hello = self.hello_int.to_bytes(2, 'big')
        padding = (0).to_bytes(2, 'big')
        
        # Constructing the packet headers
        pkt = Ether(src=self.control_intf.mac, dst='ff:ff:ff:ff:ff:ff', type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_IP, outPort=port)
        pkt = pkt / IP(src=intf.ip, dst=ALLSPFRoutersIP, proto=IP_PROTO_PWOSPF) 
        pkt = pkt / PWOSPF(version=2, type=PWOSPF_TYPE_HELLO, routerID=self.routerID, areaID=self.areaID,
                           auType=0, authentication=0, totalLen=24)
        pkt = pkt / Raw(mask+hello+padding)
        return pkt   
    
    def startHelloBroadcast(self):
        Timer(self.hello_int, self.startHelloBroadcast).start()
        # Send hello on each interface
        for port, intf in self.router.intfs.items():
            if port >= 2:
                pkt = self.genHello(port, intf)
                self.controller.send(pkt)
                
    def genLSUData(self):
        res = b''
        n = 0
        for port in self.neighborsTTL.keys():
            for id in self.neighborsTTL[port].keys():
                subnet, mask, prefixLen = self.getSubnetAndMask(port)
                res += int(ipaddress.ip_address(subnet)).to_bytes(4, 'big')
                res += int(ipaddress.ip_address(mask)).to_bytes(4, 'big')
                res += int(ipaddress.ip_address(id)).to_bytes(4, 'big')
                n += 1
        return n, res
                
    
    def genLSU(self, port, dstIP):
        """
        Generates LSU packet for this router
        """
        # Creating the LSU packet data
        n, data = self.genLSUData()
        seq = self.LSUsequence.to_bytes(2, 'big')
        ttl = (64).to_bytes(2, 'big')
        
        
        # Constructing the packet headers
        pkt = Ether(src=self.control_intf.mac, type=TYPE_CPU_METADATA) / CPUMetadata(
            origEtherType=ETHER_TYPE_IP, outPort=port)
        pkt = pkt / IP(src=self.control_intf.ip, dst=dstIP, proto=IP_PROTO_PWOSPF) 
        pkt = pkt / PWOSPF(version=2, type=PWOSPF_TYPE_LSU, routerID=self.routerID, areaID=self.areaID,
                           auType=0, authentication=0, totalLen=24)
        pkt = pkt / Raw(seq + ttl + n.to_bytes(4, 'big') + data)
        return pkt

    def modifyOthersLSUPacket(self, pkt, port, dstIP):
        """
        This function is called after receiving a LSU. Modifies the LSU packet so that 
        it can be sent to other neighboring routers.
        """
        pkt[Ether].src = self.control_intf.mac
        pkt[CPUMetadata].outPort = port
        pkt[IP].dst = dstIP
        pkt[IP].ttl -= 1
        return pkt
    
    def broadcastOthersLSUPacket(self, pkt):
        """
        This function will broadcast the LSU packet received by other routers.
        """
        inPort = pkt[CPUMetadata].srcPort
        
        for port, intf in self.router.intfs.items():
            if port >= 2 and port != inPort:
                for id in self.neighborsTTL[port].keys():
                    # We wont send hello packets to the endhosts
                    if id != '0.0.0.0':
                        pkt2 = self.modifyOthersLSUPacket(pkt, port, dstIP=id)     
                        self.controller.send(pkt2)
                        
    def startLSUBroadcast(self):
        Timer(self.lsuint, self.startLSUBroadcast).start()
        # Send LSU on each interface
        for port, intf in self.router.intfs.items():
            if port >= 2:
                for id in self.neighborsTTL[port].keys():
                    # We wont send hello packets to the endhosts
                    if id != '0.0.0.0':
                        pkt = self.genLSU(port, dstIP=id)
                        self.controller.send(pkt)
        self.LSUsequence += 1
        

