import random
import copy

from BasicTest import *

class DuplicatesPacketsTest(BasicTest):
    def handle_packet(self):
        for p in self.forwarder.in_queue:
            # if random.choice([True, False]):
        	# print "(TEST)packet.seqno: ", p.seqno
            self.forwarder.out_queue.append(p)
            # print "(TEST)packet.seqno: ", p.seqno
            self.forwarder.out_queue.append(copy.copy(p))

        # empty out the in_queuea
        self.forwarder.in_queue = []