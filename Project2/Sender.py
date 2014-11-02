import sys
import getopt
import re

import Checksum
import BasicSender

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''
class Sender(BasicSender.BasicSender):
    def __init__(self, dest, port, filename, debug=False, sackMode=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.sock.settimeout(0.5)
        self.dataSize = 1400
        self.seqNum = -1
        self.windowSize = 5
        self.sentPackets = {}
        self.maxSize = 1472
        self.minSize = 1000
        self.duplicates = 0
        self.finalAckNum = None
        self.timeout = 0.5
        self.sackMode = sackMode
        self.sacks = set()

    # Main sending loop.
    def start(self):
        # sync with the receiver with "greeting message"
        firstPacket = self.make_packet("start", self.seqNum, "")
        self.send(firstPacket)
        print("Sender.py: Sending start|" + str(self.seqNum))
        self.sentPackets[self.seqNum] = firstPacket
        message = self.receive(self.timeout)
        # no response from receiver when trying to establish the connection
        if message == None:
            self.handle_start_timeout()
        #####################
        else:
            print("Sender.py: Received " + message)
        ######################
        self.seqNum += 1
        # got response from the receiver and the connection has been established,
        # start to send the data packet
        self.do_send(self.seqNum, self.seqNum + self.windowSize)
        while True:
            message = self.receive(self.timeout)              
            if message == None:
                print("Timeout")
                if self.finalAckNum != None and self.seqNum == self.finalAckNum:
                    break
                if self.sackMode:
                    self.do_send(self.seqNum, self.seqNum + self.windowSize, self.sacks)
                else:
                    self.do_send(self.seqNum, self.seqNum + self.windowSize)
                self.duplicates = 0
                continue
            print("Sender.py: Received " + message)
            if self.sackMode:
                nums = self.get_sack_nums(message)
                for num in nums:
                    self.sacks.add(num)
            returnedMessage = self.handle_new_ack(message)
            if returnedMessage == "Checksum":
                continue
            if returnedMessage == "Duplicate":
                self.handle_dup_ack(message)
                if self.duplicates == 3:
                    self.send(self.sentPackets[self.seqNum])
                    print("3 duplicates")
                    print("Sender.py: Sending data|" + str(self.seqNum))
                    self.duplicates = 0
                continue
            if returnedMessage == "OldAck":
                continue
            if returnedMessage == "Forward":
                self.duplicates = 0
                ackSeqNum = self.get_packet_seq_num(message)
                numPacketsToSend = ackSeqNum - self.seqNum
                self.seqNum = ackSeqNum
                if self.seqNum == self.finalAckNum:
                    break
                self.do_send(self.seqNum + self.windowSize - numPacketsToSend, self.seqNum + self.windowSize)
                continue
            if returnedMessage == "Unknown":
                print "Unknown Error"
                exit(1)
        
        endPacket = self.make_packet("end", self.seqNum, "")
        self.send(endPacket)
        print("Sender.py: Sending end|" + str(self.seqNum))
        while True:
            message = self.receive(self.timeout)
            if message == None:
                print("Timeout")
                self.send(endPacket)
                print("Sender.py: Sending end|" + str(self.seqNum))
                continue
            print("Sender.py: Received " + message)
            packetSeqNum = self.get_packet_seq_num(message)
            if packetSeqNum == self.seqNum + 1:
                break
        print "DONE!"
        exit()
            
        
        
    def do_send(self, starting_seq, end_seq, exclusion=[]):
        self.infile.seek(starting_seq*self.dataSize)
        for seqNum in range(starting_seq, end_seq):
            data = self.infile.read(self.dataSize)
            if self.sackMode and seqNum in exclusion:
                continue
            # we send 1400 bytes at a time/
            # if we finish sending the file
            if data == "":
                if self.finalAckNum == None:
                    self.finalAckNum = seqNum
                return
            if seqNum not in self.sentPackets:
                packet = self.make_packet("data", seqNum, data)
                self.sentPackets[seqNum] = packet
                self.send(packet)
                print("Sender.py: Sending data|" + str(seqNum))
            else:
                self.send(self.sentPackets[seqNum])
                print("Sender.py: Sending data|" + str(seqNum))
    
    # first greeting packet timeout
    def handle_start_timeout(self):
        while True:
            print("Timeout")
            self.send(self.sentPackets[self.seqNum])
            print("Sender.py: Sending start|" + str(self.seqNum))
            message = self.receive(self.timeout)
            # if we finally have a response, we can start to send the new ack
            if message != None and self.get_packet_seq_num(message) == self.seqNum + 1:
                print("Sender.py: Received " + message)
                return        

    def handle_new_ack(self, ack):
        # if the ack does not have a correct checksum, drop the packet
        # most likely we need to wait for the timeout to resend the packet again
        if Checksum.validate_checksum(ack) == False:
            return "Checksum"
        ackSeqNum = self.get_packet_seq_num(ack)
        # if the packets come out of order, drop ignore the acks before the window size
        if ackSeqNum < self.seqNum:
            return "OldAck"
        # if we got a duplicate ack with seqNum the same as the current seqNum (where the window starts)
        if ackSeqNum == self.seqNum:
            return "Duplicate"
        # since it's cumulative acks, we ignore everything as long as we get a ack with higher seqNum
        if ackSeqNum > self.seqNum:
            return "Forward"
        return "Unknown"
        
    def handle_dup_ack(self, ack):
        self.duplicates += 1

    def log(self, msg):
        if self.debug:
            print msg
    
    def get_ack_type(self, message):
        return self.split_packet(message)[0]
    
    def get_packet_seq_num(self, message):
        seqString = self.split_packet(message)[1]
        if self.sackMode:
            return int(seqString.split(";")[0])
        return int(seqString)
    
    def get_sack_nums(self, message):
        seqString = self.split_packet(message)[1]
        stringNums = re.findall(r'\d+', seqString)
        nums = [int(s) for s in stringNums] 
        return nums[1:]

    def get_ack_checksum(self, message):
        return int(self.split_packet(message)[3])

'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print "BEARS-TP Sender"
        print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        print "-p PORT | --port=PORT The destination port, defaults to 33122"
        print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"
        print "-k | --sack Enable selective acknowledgement mode"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:dk", ["file=", "port=", "address=", "debug=", "sack="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False
    sackMode = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True
        elif o in ("-k", "--sack="):
            sackMode = True

    s = Sender(dest, port, filename, debug, sackMode)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()