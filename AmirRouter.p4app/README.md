# Router

All parts are done except dynamic routing timeouts! Sample topology is as follows. We have 3 routers names s1-s3 and 4 hosts h1-h4.

                                     -----s3 --- h4
                                    |     |
                      h1 --- s1 --- s2 --- h2
                                    |
                                   h3


- This project is tested in my home computer which runs WSL inside windows, and uses python3. Althogh, I am using networkx version 2.2 because it is compatible with python2!
- To save and process on the global topology we use networkx, which is a package for studying networks. So upon starting the program networkx pip package is going to be installed inside the docker container and then the mininet network is run. 

Notes:
- corrupted packets and the ones with ttl=0 are dropped in the data plane
- Arp requests will be sent out when arp entry doesn't exists for a packet with IP header, and the original packet will be queued.
- Arp entry timeout is implemented in controller.py
- ICMP host/network unreachable packet are created when routing/Arp entry is not available in the tables.
- Static routes can be added inside main.py. These entries will not be removed by ospf_helper.
- Counters are implemented in p4 and can be accessed using main.py
- ospf_helper.py broadcasts hello and LSU packets to other routers periodically. It constructs the global topology after receiving new LSU by other routers and rewrite the routing tables.
- Arp/ICMP packets addressed directly to any of the router addresses are handled in the controller
