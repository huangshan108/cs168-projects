import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from hub import Hub
import sim.topo as topo

def create (switch_type = Hub, host_type = BasicHost):
    """
    Creates a topology with loops that looks like:

    h1 -- s1 -------- s3 -- h2
          |            |
          ---- s4 ------
    """

    switch_type.create('s1')
    switch_type.create('s3')
    switch_type.create('s4')

    host_type.create('h1')
    host_type.create('h2')
    

    
    topo.link(s1, s3, 10)
    topo.link(s1, s4, 1)
    topo.link(s4, s3, 5)

    # topo.link(s1, s3)
    # topo.link(s1, s4)
    # topo.link(s4, s3)

    topo.link(h1, s1)
    topo.link(s3, h2)

    
    
    

