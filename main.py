from p4app import P4Mininet
from my_topo import SingleSwitchTopo, DemoTopo
from controller import Controller
import time

topo = DemoTopo()
net = P4Mininet(program='router.p4', topo=topo, auto_arp=False)

net.start()

s1 = net.get('s1')
s2 = net.get('s2')
h1 = net.get('h1')
h2 = net.get('h2')
h3 = net.get('h3')
c1 = net.get('c1')
c2 = net.get('c2')

s1.setIP('10.1.1.1/24', intf = 's1-eth1')
s1.setMAC('00:00:00:00:01:01', intf = 's1-eth1')
s1.setIP('10.0.1.1/24', intf = 's1-eth2')
s1.setMAC('00:00:00:00:01:02', intf='s1-eth2')
s1.setIP('10.0.3.1/30', intf = 's1-eth3')
s1.setMAC('00:00:00:00:01:03', intf='s1-eth3')
s1.setIP('10.0.5.1/24', intf = 's1-eth4')
s1.setMAC('00:00:00:00:01:06', intf='s1-eth4')

s2.setIP('10.2.1.1/24', intf = 's2-eth1')
s2.setMAC('00:00:00:00:02:01', intf = 's2-eth1')
s2.setIP('10.0.3.2/30', intf = 's2-eth2')
s2.setMAC('00:00:00:00:02:02', intf='s2-eth2')
s2.setIP('10.0.2.1/24', intf = 's2-eth3')
s2.setMAC('00:00:00:00:02:03', intf='s2-eth3')

        # h1.setDefaultRoute("dev eth0 via 10.0.1.1")
h1.setDefaultRoute("dev eth0 via 10.0.1.1")
h2.setDefaultRoute("dev eth0 via 10.0.2.1")
h3.setDefaultRoute("dev eth0 via 10.0.5.1")
        # Disabling auto ARP and ICMP responses in the routers
for s in [s1, s2]:
    for _ , intf in s.intfs.items():
        print(s.cmd('ip link set dev %s arp off' % intf))
        print(s.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all'))
        print(s.cmd('sysctl -w net.ipv4.ip_forward=0'))

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
s1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 5))
s2.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 4))

# Send MAC bcast packets to the bcast multicast group
s1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
s2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
s1.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.1.1.1'},
        action_name='MyIngress.send_to_cpu')
s1.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.0.1.1'},
        action_name='MyIngress.send_to_cpu')
s1.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.0.5.1'},
        action_name='MyIngress.send_to_cpu')
s1.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.0.3.1'},
        action_name='MyIngress.send_to_cpu')
s2.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.2.1.1'},
        action_name='MyIngress.send_to_cpu')
s2.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.0.3.2'},
        action_name='MyIngress.send_to_cpu')
s2.insertTableEntry(table_name='MyIngress.local_routing',
        match_fields={'hdr.ipv4.dstAddr': '10.0.2.1'},
        action_name='MyIngress.send_to_cpu')
# Start the controllers
cpu1 = Controller(s1, c1.IP(), c1.MAC())
cpu2 = Controller(s2, c2.IP(), c2.MAC())
cpu1.start()
cpu2.start()


from mininet.cli import CLI
CLI(net)


# These table entries were added by the CPU:
s1.printTableEntries()
s2.printTableEntries()
# Counters
print('-----------------')
print('Router 1 Counters:')
print('-----------------')
print('Number of IP Packets: ' + str(s1.readCounter('ip_packets', 1)[0]))
print('Number of ICMP Packets: ' + str(s1.readCounter('icmp_packets', 1)[0]))
print('Number of PWOSPF Packets: ' + str(s1.readCounter('pwospf_packets', 1)[0]))
print('Number of ARP Packets: ' + str(s1.readCounter('arp_packets', 1)[0]))
print('Number of CPU Packets: ' + str(s1.readCounter('cpu_packets', 1)[0]))
print('-----------------')
print('Router 2 Counters')
print('-----------------')
print('Number of IP Packets: ' + str(s2.readCounter('ip_packets', 1)[0]))
print('Number of ICMP Packets: ' + str(s2.readCounter('icmp_packets', 1)[0]))
print('Number of PWOSPF Packets: ' + str(s2.readCounter('pwospf_packets', 1)[0]))
print('Number of ARP Packets: ' + str(s2.readCounter('arp_packets', 1)[0]))
print('Number of CPU Packets: ' + str(s2.readCounter('cpu_packets', 1)[0]))
print('-----------------')
