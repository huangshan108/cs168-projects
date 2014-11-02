import random
import copy

from BasicTest import *

class DuplicateAcksTest(BasicTest):
    counter = 0
    def handle_packet(self):
    	# print "counter: ", self.counter
        for p in self.forwarder.in_queue:
            if self.counter != 2:
                self.forwarder.out_queue.append(p)
            self.counter += 1
        # empty out the in_queue
        self.forwarder.in_queue = []