# Router

All parts are done except timeouts! Sample topology is as follows. We have 3 routers names s1-s3 and 4 hosts h1-h4.

                                   -----s3 --- h4
                                  |     |
Connecting nodes:         h1 --- s1 --- s2 --- h2
                                  |
                                 h3


- This project is tested in my home computer which runs WSL inside windows, and uses python3.
- To save and process on the global topology we use networkx, which is a package for studying networks. So upon starting the program networkx pip package is going to be installed inside the docker container and then the mininet network is run.  