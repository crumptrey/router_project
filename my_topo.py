from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')

        for i in range(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)
    

class DemoTopo(Topo):
    "Demo topology"

    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        # Creating Routers
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Assigning a controller host on the first interface of routers
        c1 = self.addHost('c1', ip="10.1.1.10/24", mac='00:00:00:00:00:01')
        c2 = self.addHost('c2', ip="10.2.1.10/24", mac='00:00:00:00:00:02')
        self.addLink(s1, c1)
        self.addLink(s2, c2)

        # Adding simple hosts
        h1 = self.addHost('h1', ip="10.0.1.10/24", mac='00:00:00:00:00:03')
        h2 = self.addHost('h2', ip="10.0.2.10/24", mac='00:00:00:00:00:04')
        h3 = self.addHost('h3', ip="10.0.5.10/24", mac='00:00:00:00:00:05')

        # Connecting nodes:         h1 --- s1 --- s2 --- h2
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)
        self.addLink(s1, h3)

    def initialize(self, net):
        s1 = net.get('s1')
        s2 = net.get('s2')
        h1 = net.get('h1')
        h2 = net.get('h2')
        
        s1.setIP('10.1.1.1/24', intf = 's1-eth1')
        s1.setMAC('00:00:00:00:01:01', intf = 's1-eth1')
        s1.setIP('10.0.1.1/24', intf = 's1-eth2')
        s1.setMAC('00:00:00:00:01:02', intf='s1-eth2')
        s1.setIP('10.0.3.1/30', intf = 's1-eth3')
        s1.setMAC('00:00:00:00:01:03', intf='s1-eth3')

        s2.setIP('10.2.1.1/24', intf = 's2-eth1')
        s2.setMAC('00:00:00:00:02:01', intf = 's2-eth1')
        s2.setIP('10.0.3.2/30', intf = 's2-eth2')
        s2.setMAC('00:00:00:00:02:02', intf='s2-eth2')
        s2.setIP('10.0.2.1/24', intf = 's2-eth3')
        s2.setMAC('00:00:00:00:02:03', intf='s2-eth3')

        # h1.setDefaultRoute("dev eth0 via 10.0.1.1")
        h1.setDefaultRoute("dev eth0 via 10.0.1.1")
        h2.setDefaultRoute("dev eth0 via 10.0.2.1")

        # Disabling auto ARP and ICMP responses in the routers
        for s in [s1, s2]:
            for _ , intf in s.intfs.items():
                print(s.cmd('ip link set dev %s arp off' % intf))
            print(s.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all'))

