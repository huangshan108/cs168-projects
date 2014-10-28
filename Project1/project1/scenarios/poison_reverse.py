import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from hub import Hub
import sim.topo as topo

def create (switch_type = Hub, host_type = BasicHost):
    """
    Creates a topology with loops that looks like:
    	   	    

    	   	 s1 
    	   /    \ 
    h2 -- s2 -- s3 -- h3

    Then we cut s2 -x- s1
    """

    switch_type.create('s1')
    switch_type.create('s2')
    switch_type.create('s3')

    host_type.create('h2')
    host_type.create('h3')

    topo.link(h2, s2)
    topo.link(s2, s3)
    topo.link(s2, s1)
    topo.link(s1, s3)
    topo.link(s3, h3)