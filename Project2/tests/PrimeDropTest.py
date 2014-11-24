import random

from BasicTest import *

"""
This tests random packet drops. We randomly decide to drop about half of the
packets that go through the forwarder in either direction.

Note that to implement this we just needed to override the handle_packet()
method -- this gives you an example of how to extend the basic test case to
create your own.
"""
class PrimeDropTest(BasicTest):
    def __init__(self, forwarder, input_file, sackMode = False):
        BasicTest.__init__(self, forwarder, input_file, sackMode)
        self.prime = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
        
        self.prime = [x + 1 for x in self.prime]

        self.dropped = dict()
        for p in self.prime:
        	self.dropped[p] = False;

    def drop(self, packet):
        seqno = int(str(packet).split('|')[1])
        packet_type = str(packet).split('|')[0]
        if seqno in self.prime and packet_type != 'ack':
            if self.dropped[seqno]:
                return False
            else:
                print 'dropped', seqno
                self.dropped[seqno] = True
                return True
        return False

    def handle_packet(self):
        for p in self.forwarder.in_queue:
            if not self.drop(p):
	            self.forwarder.out_queue.append(p)

        # empty out the in_queue
        self.forwarder.in_queue = []
