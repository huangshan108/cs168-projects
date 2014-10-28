import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from hub import Hub
import sim.topo as topo

def create (switch_type = Hub, host_type = BasicHost):
    """
    Creates a topology with loops that looks like:
        h1    h2
        |     |
        s1 - s2 
         |   /
         |  / 
   h3 -- s3 -
         |
        s4
         |
         h4

    No router should handle packages to h4 is s3 and s4 is unlinked
    """

    switch_type.create('s1')
    switch_type.create('s2')
    switch_type.create('s3')
    switch_type.create('s4')

    host_type.create('h1')
    host_type.create('h2')
    host_type.create('h3')
    host_type.create('h4')

    topo.link(s1, h1)
    topo.link(s2, h2)
    topo.link(s3, h3)
    topo.link(s4, h4)

    topo.link(s1, s2)
    topo.link(s1, s3)
    topo.link(s2, s3)
    topo.link(s3, s4)




