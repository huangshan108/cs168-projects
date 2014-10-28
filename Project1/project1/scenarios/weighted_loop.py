import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from hub import Hub
import sim.topo as topo

def create (switch_type = Hub, host_type = BasicHost):
    """
    Creates a topology with loops that looks like:
            h2
            |
            s2
           /  \  
        s1 ---- s3
         |       |
        h1      h3
    
    """

    switch_type.create('s1')
    switch_type.create('s2')
    switch_type.create('s3')

    host_type.create('h1')
    host_type.create('h2')
    host_type.create('h3')

    topo.link(s1, s3, 10)
    topo.link(s3, s2, 1)
    topo.link(s1, s2, 4)
    topo.link(h2, s2, 1)
    topo.link(h1, s1, 1)
    topo.link(h3, s3, 1)

