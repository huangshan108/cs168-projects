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
                    ## print("Port:" + str(self.portTable))
                    
                # if the newly discovery router is not in the forwarding table
                # we add it to the forwarding table
                if packet.src not in self.forwardingTable:
                    self.forwardingTable[packet.src] = packet.src
                    ## print("Forwarding:" + str(self.forwardingTable))
                    
                # if the newly discovery router is not in the cost table
                # or the newly received cost is lower than the current cost
                # we update the cost from self to the received point to packet.latency
                # we create a empty row for received packet router's cost to other routers
                if packet.src not in self.costTable[self].keys() or packet.latency < self.costTable[self][packet.src]:
                    self.costTable[self][packet.src] = packet.latency
                    self.forwardingTable[packet.src] = packet.src
                    self.costTable[packet.src] = {}
                    # # print "link on"
                    self.send_update_packets()
                # # print "forwardingTable in link up: ", self.forwardingTable
            
            # if it is a link down
            else:
                # first we remove it from the portTable
                del self.portTable[packet.src]
                # we need to update our forwarding table for all the destinations we currently have
                for dest in self.forwardingTable.keys():
                    # if the route down use to be a forward port, we update it with the 
                    # new calculate forwarding ports 
                    if self.forwardingTable[dest] == packet.src:
                        newCost, new_forward = self.shortestDistAndNeighbor(dest)
                        self.costTable[self][dest] = newCost
                        # if we have a new forward port, update it into our forwarding table
                        if new_forward != None:
                            self.forwardingTable[dest] = new_forward
                        # otherwise we just claim we can't get to that destinion by removing the 
                        # the destination from our forwarding table
                        else:
                            del self.forwardingTable[dest]
                # print "link update"                   
                self.send_update_packets()

        elif type(packet) == RoutingUpdate:
            # apply changes in RoutingUpdate packet to self.costTable
            # changed = False
            # for router in packet.all_dests():
            #     # we update the cost table in us based on what we get from the cost table
            #     # # print self.costTable[packet.src][router]
            #     if router not in self.costTable[packet.src] or self.costTable[packet.src][router] > packet.get_distance(router):
            #         self.costTable[packet.src][router] = packet.get_distance(router)
            #     if router not in self.costTable[self] or self.costTable[self] > self.shortestDistAndNeighbor(router)[0]:
            #         self.costTable[self][router] = self.shortestDistAndNeighbor(router)[0]
            #         changed = True
            #     if router not in self.forwardingTable.keys():
            #         self.forwardingTable[router] = self.shortestDistAndNeighbor(router)[1]
            # changed = changed or self.routers()
            # if changed:
            #     self.send_update_packets()

            changed = False
            routers = []
            for router in packet.all_dests():
                self.costTable[packet.src][router] = packet.get_distance(router)
                routers.append(router)
            for router in routers:
                if router not in self.costTable[self].keys():
                    self.costTable[self][router] = self.shortestDistAndNeighbor(router)[0]
                    changed = True
                if router not in self.forwardingTable.keys() and self.shortestDistAndNeighbor(router)[1] != None:
                    self.forwardingTable[router] = self.shortestDistAndNeighbor(router)[1]
                # print self, " forwardingTable in update: ", self.forwardingTable
            changed = changed or self.update_cost_table_and_forwarding_table()
            if changed:
                self.send_update_packets()

        else:
            ## print(self.forwardingTable)
            ## print(self.costTable)

            # we drop the packet if this pack doesn't have a destination or not in our forwarding table
            if packet.dst == None or packet.dst not in self.forwardingTable:
                return #drop packet
            neighbor = self.forwardingTable[packet.dst]
            # # print "forwardingTable: ", self.forwardingTable
            if neighbor == self:
                return #correct destination
            # # print "key: ", neighbor
            # # print "portTable: ", self.portTable
            out_port = self.portTable[neighbor]
            self.send(packet, out_port)

    # this function handles sending updating packets to our neighbors when something changed to self
    # send update packets when:
    #   1. we discover a new route (link up)
    #   2. we lost a route (link down)
    #   3. when we receive update packet from other router about their table change and thus our table change
    def send_update_packets(self):
        # sends out an update packet whose paths is the row of self in the cost table
        for neighbor in self.portTable.keys():
            updatePacket = RoutingUpdate()
            updatePacket.src = self

            for dest in self.costTable[self].keys():
                # Poisoned Reverse
                if dest in self.forwardingTable and self.forwardingTable[dest] == neighbor and dest != neighbor:
                    updatePacket.add_destination(dest, float("inf"))
                else:
                    updatePacket.add_destination(dest, self.costTable[self][dest])
            # print self, " self.costTable: ", self.costTable
            # print self, " self.portTable: ", self.portTable
            # print 
            self.send(updatePacket, self.portTable[neighbor])      
                
    def update_cost_table_and_forwarding_table(self):
        # update the cost table after we receive a new row from a update packet
        # @return: whether there is a change to the cost time due to the shorter path change
        changed = False
        for dest in self.costTable[self].keys():
            cost, neighbor = self.shortestDistAndNeighbor(dest)
            if neighbor != None and self.forwardingTable[dest] != neighbor:
                self.forwardingTable[dest] = neighbor
            if self.costTable[self][dest] > cost:
                self.costTable[self][dest] = cost
                changed = True
        return changed

    def shortestDistAndNeighbor(self, dest):
        if dest == self:
            return (0, self)
        shortest = float("inf")
        closest = None
        for neighbor in self.portTable.keys():
            if dest in self.costTable[neighbor].keys():
                dist = self.costTable[self][neighbor] + self.costTable[neighbor][dest]
                if dist < shortest:
                    shortest = dist
                    closest = neighbor
        return (shortest, closest)
              