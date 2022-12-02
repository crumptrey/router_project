from mininet.topo import Topo

class DemoTopo(Topo):
    "Demo topology"

    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Topology:
        #                                    -----s3 --- h4
        #                                   |     |
        #                              h1 --- s1 --- s2 --- h2
        #                                   |
        #                                  h3
        
        # Creating Routers
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Assigning a controller host on the first interface of routers
        c1 = self.addHost('c1', ip="10.1.1.10/24", mac='00:00:00:00:00:01')
        c2 = self.addHost('c2', ip="10.1.2.10/24", mac='00:00:00:00:00:02')
        c3 = self.addHost('c3', ip="10.1.3.10/24", mac='00:00:00:00:00:03')
        self.addLink(s1, c1)
        self.addLink(s2, c2)
        self.addLink(s3, c3)
        
        # Adding simple hosts
        h1 = self.addHost('h1', ip="10.0.1.10/24", mac='00:00:00:00:00:11')
        h2 = self.addHost('h2', ip="10.0.2.10/24", mac='00:00:00:00:00:12')
        h3 = self.addHost('h3', ip="10.0.3.10/24", mac='00:00:00:00:00:13')
        h4 = self.addHost('h4', ip="10.0.4.10/24", mac='00:00:00:00:00:14')

        # Adding links
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)
        self.addLink(s1, h3)
        self.addLink(s3, s1)
        self.addLink(s3, s2)
        self.addLink(s3, h4)
        

    def initialize(self, net):
        s1 = net.get('s1')
        s2 = net.get('s2')
        s3 = net.get('s3')
        h1 = net.get('h1')
        h2 = net.get('h2')
        h3 = net.get('h3')
        h4 = net.get('h4')
        
        # Assigning IP and MAC addresses
        s1.setIP('10.1.1.1/24', intf = 's1-eth1') # s1-c1
        s1.setMAC('00:00:00:00:01:01', intf = 's1-eth1')
        s1.setIP('10.0.1.1/24', intf = 's1-eth2') # s1-h1
        s1.setMAC('00:00:00:00:01:02', intf='s1-eth2')
        s1.setIP('10.2.0.1/30', intf = 's1-eth3') # s1-s2
        s1.setMAC('00:00:00:00:01:03', intf='s1-eth3')
        s1.setIP('10.0.3.1/24', intf = 's1-eth4') # s1-h3
        s1.setMAC('00:00:00:00:01:06', intf='s1-eth4')
        s1.setIP('10.2.1.1/30', intf = 's1-eth5') # s1-s3
        s1.setMAC('00:00:00:00:01:07', intf='s1-eth5')
        
        s2.setIP('10.1.2.1/24', intf = 's2-eth1') # s2-c2
        s2.setMAC('00:00:00:00:02:01', intf = 's2-eth1')
        s2.setIP('10.2.0.2/30', intf = 's2-eth2') # s2-s1
        s2.setMAC('00:00:00:00:02:02', intf='s2-eth2')
        s2.setIP('10.0.2.1/24', intf = 's2-eth3') # s2-h2
        s2.setMAC('00:00:00:00:02:03', intf='s2-eth3')
        s2.setIP('10.2.2.1/30', intf = 's2-eth4') # s2-s3
        s2.setMAC('00:00:00:00:02:04', intf='s2-eth4')
        
        s3.setIP('10.1.3.1/24', intf = 's3-eth1') # s3-c3
        s3.setMAC('00:00:00:00:03:01', intf = 's3-eth1')
        s3.setIP('10.2.1.2/30', intf = 's3-eth2') # s3-s1
        s3.setMAC('00:00:00:00:03:02', intf='s3-eth2')
        s3.setIP('10.2.2.2/30', intf = 's3-eth3') # s3-s2
        s3.setMAC('00:00:00:00:03:03', intf='s3-eth3')
        s3.setIP('10.0.4.1/24', intf = 's3-eth4') # s3-h4
        s3.setMAC('00:00:00:00:03:04', intf='s3-eth4')

        # Set default routes:
        h1.setDefaultRoute("dev eth0 via 10.0.1.1")
        h2.setDefaultRoute("dev eth0 via 10.0.2.1")
        h3.setDefaultRoute("dev eth0 via 10.0.3.1")
        h4.setDefaultRoute("dev eth0 via 10.0.4.1")
        
        # Disabling auto ARP and ICMP responses in the routers
        for s in [s1, s2, s3]:
            for _ , intf in s.intfs.items():
                print(s.cmd('ip link set dev %s arp off' % intf))
            print(s.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all'))
            print(s.cmd('sysctl -w net.ipv4.ip_forward=0'))
        