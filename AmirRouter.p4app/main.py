from p4app import P4Mininet
from my_topo import DemoTopo
from controller import RouterController
from mininet.cli import CLI
from time import sleep
from consts import *

# Port 1 (h1) is reserved for the CPU.
# You can view the topology in my_topo.py

topo = DemoTopo()
net = P4Mininet(program='router.p4', topo=topo, auto_arp=False)
net.start()
topo.initialize(net)

sw1 = net.get('s1') 
sw2 = net.get('s2') 
sw3 = net.get('s3') 

# Start the controllers
cpu1 = RouterController(sw1, areaID=1)
cpu2 = RouterController(sw2, areaID=2)
cpu3 = RouterController(sw3, areaID=3)
cpu1.start()
cpu2.start()
cpu3.start()

sleep(2)

## You can use the following syntax to add static routes to the router
# cpu1.addRoutingEntry(subnet='20.10.0.0', prefixLen=24, port=2, nhop='0.0.0.0', static=True)

## Staring the CLI
# CLI(net)

h1, h2 = net.get('h1'), net.get('h2')
h3, h4 = net.get('h3'), net.get('h4')

sleep(15)
print (h2.cmd('ping -c3 10.0.3.10')) # Should be successful
print (h1.cmd('ping -c3 10.0.4.10')) # Should be successful
print (h3.cmd('ping -c1 10.0.1.200')) # Should receive Host Unreachable
print (h4.cmd('ping -c1 10.0.37.200')) # Should receive Net Unreachable

sleep(5)

# Show the table entries
sw1.printTableEntries()
sw2.printTableEntries()
sw3.printTableEntries()

# Reading counters in the first switch
print('ip count:', sw1.readCounter('c', COUNTER_IP_PACKETS))
print('cpu count:', sw1.readCounter('c', COUNTER_CPU_PACKETS))
print('arp count:', sw1.readCounter('c', COUNTER_ARP_PACKETS))