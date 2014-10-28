import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from hub import Hub
import sim.topo as topo

def create (switch_type = Hub, host_type = BasicHost):
    """
    Creates a topology with loops that looks like:

    h1 -- s1 -- s2 -- s3 -- h2

    Then we cut s1 -x- s2
    """

    switch_type.create('s1')
    switch_type.create('s2')
    switch_type.create('s3')

    host_type.create('h1')
    host_type.create('h2')

    topo.link(s1, h1)
    topo.link(s1, s2)
    topo.link(s2, s3)
    topo.link(s3, h2)
