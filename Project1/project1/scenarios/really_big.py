import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from hub import Hub
import sim.topo as topo
from dv_router import DVRouter

def create (switch_type = DVRouter, host_type = BasicHost):
    """
    Creates a topology with loops that looks like:
    h1a    s4--s5           h2a
       \  /      \          /
        s1        s2--s6--s7
       /  \      /     \    \    
    h1b    --s3--       s8--s9--h2b
    """
    switch_type.create('s1')
    switch_type.create('s2')
    switch_type.create('s3')
    switch_type.create('s4')
    switch_type.create('s5')

    switch_type.create('s6')
    switch_type.create('s7')
    switch_type.create('s8')
    switch_type.create('s9')


    host_type.create('h1a')
    host_type.create('h1b')
    host_type.create('h2a')
    host_type.create('h2b')


    # ReceiveEntity.create('sneakylistener', [s7, s9, s8, s6, s2, s5, s4, s1] , [h1a, 1], 5)

    # topo.link(sneakylistener, h1a)
    # topo.link(sneakylistener, s1)
    topo.link(s1, h1a)
    topo.link(s1, h1b)
    topo.link(s2, s6)
    topo.link(s6, s8)
    topo.link(s8, s9)
    topo.link(s9, h2b)
    topo.link(s6, s7)
    topo.link(s7, s9)
    topo.link(s7, h2a)
    

    topo.link(s1, s3)
    topo.link(s3, s2)

    topo.link(s1, s4)
    topo.link(s4, s5)
    topo.link(s5, s2)