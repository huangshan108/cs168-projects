from sim.api import *
from sim.basics import *

'''
Create your distance vector router in this file.
'''
class DVRouter (Entity):
    def __init__(self):        
        # forwarding table for self router
        # @key: the router
        # @value: latency for that router
        self.forwardingTable = {}
        self.forwardingTable[self] = self
        
        # a table keeps tracking all the port numbers from our neighbors
        # @key: the neighbor routers
        # @value: port number for that router (key)
        self.portTable = {} 
        
        # a table keeps track of all the cost in this nextwork
        # @key: the source router
        # @value: another table maps the destination to the path cost
        self.costTable = {}
        # add the cost for self router
        self.costTable[self] = {self: 0}
        

    def handle_rx (self, packet, port):
        # @self:
        # @packet: the packet we received
        # @port: the port number where we get the packet from 
        
        if type(packet) == DiscoveryPacket:
            if packet.is_link_up:
                # inform all our neighbors of the newly discovered router  
                # update he forwardingTable and portTable for the new coming packet from our neighbor

                # if the newly discovery router is not in the port table
                # we add it to the port table
                if packet.src not in self.portTable:
                    self.portTable[packet.src] = port
                    #print("Port:" + str(self.portTable))
                    
                # if the newly discovery router is not in the forwarding table
                # we add it to the forwarding table
                if packet.src not in self.forwardingTable:
                    self.forwardingTable[packet.src] = packet.src
                    #print("Forwarding:" + str(self.forwardingTable))
                    
                # if the newly discovery router is not in the cost table
                # or the newly received cost is lower than the current cost
                # we update the cost from self to the received point to packet.latency
                # we create a empty row for received packet router's cost to other routers
                if packet.src not in self.costTable[self].keys() or packet.latency < self.costTable[self][packet.src]:
                    self.costTable[self][packet.src] = packet.latency
                    self.costTable[packet.src] = {}
                    self.send_update_packets()
            else:
                del self.portTable[packet.src]
                new_routes = []
                for dest in self.forwardingTable.keys():
                    if self.forwardingTable[dest] == packet.src:
                        new_dist, new_forward = self.shortestDistAndNeighbor(dest)
                        self.costTable[self][dest] = new_dist
                        if new_forward != None:
                            self.forwardingTable[dest] = new_forward
                        else:
                            del self.forwardingTable[dest]                     
                self.send_update_packets()     
        elif type(packet) == RoutingUpdate:
            # apply changes in RoutingUpdate packet to self.costTable
            changed = False
            for router in packet.all_dests():
                self.costTable[packet.src][router] = packet.get_distance(router)
                if router not in self.costTable[self].keys():
                    self.costTable[self][router] = self.shortestDistAndNeighbor(router)[0]
                    changed = True
                if router not in self.forwardingTable.keys():
                    self.forwardingTable[router] = self.shortestDistAndNeighbor(router)[1]
            changed = changed or self.update_cost_table_and_forwarding_table(packet)
            if changed:
                self.send_update_packets()
        else:
            #print(self.forwardingTable)
            #print(self.costTable)
            if packet.dst == None or packet.dst not in self.forwardingTable:
                return #drop packet
            neighbor = self.forwardingTable[packet.dst]
            if neighbor == self:
                return #correct destination
            out_port = self.portTable[neighbor]
            self.send(packet, out_port)
                
    def send_update_packets(self):
        # sends out an update packet whose paths is the row of self in the cost table
        for neighbor in self.portTable.keys():
            updatePacket = RoutingUpdate()
            updatePacket.src = self
            for dest in self.costTable[self].keys():
                if self.forwardingTable[dest] == neighbor:
                    updatePacket.add_destination(dest, float("inf"))
                else:
                    updatePacket.add_destination(dest, self.costTable[self][dest])
            self.send(updatePacket, self.portTable[neighbor])      
                
    def update_cost_table_and_forwarding_table(self, packet):
        # update the cost table after we receive a new row from a update packet
        # @return: whether there is a change to the cost time due to the shorter path change
        changed = False
        for currentDest in packet.all_dests():
            newPathCost = self.costTable[self][packet.src] + self.costTable[packet.src][currentDest]
            if self.costTable[self][currentDest] > newPathCost:
                self.costTable[self][currentDest] = newPathCost
                self.forwardingTable[currentDest] = packet.src
                changed = True
            # elif newPathCost > self.costTable[self][currentDest] and self.forwardingTable[currentDest] == packet.src:
            #     dist, neighbor = self.shortestDistAndNeighbor(currentDest)
            #     self.costTable[self][currentDest] = dist
            #     self.forwardingTable[currentDest] = neighbor
            #     changed = True
        return changed

    def shortestDistAndNeighbor(self, dest):
        shortest = float("inf")
        closest = None
        for neighbor in self.portTable.keys():
            if dest in self.costTable[neighbor].keys():
                dist = self.costTable[self][neighbor] + self.costTable[neighbor][dest]
                shortest = min(shortest, dist)
                closest = neighbor
        return (shortest, closest)
              