import sys
import getopt

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
        self.seqNum = 0
        self.windowSize = 5
        self.sentPackets = {}
        self.maxSize = 1472
        self.minSize = 1000
        self.duplicates = 0
        self.finalAckNum = None
        self.timeout = 0.5
        if sackMode:
            raise NotImplementedError #remove this line when you implement SACK

    # Main sending loop.
    def start(self):
        # sync with the receiver with "greeting message"
        firstPacket = self.make_packet("start", self.seqNum, "")
        self.send(firstPacket, (self.dest, self.dport))
        self.sentPackets[self.seqNum] = firstPacket
        message = self.receive(self.timeout)
        # no response from receiver when trying to establish the connection
        if message == None:
            self.handle_start_timeout()
        # got response from the receiver and the connection has been established,
        # start to send the data packet
        self.do_send(self.seqNum, self.seqNum + self.dataSize * self.windowSize)
        while True:
            message = self.receive(self.timeout)              
            if message == None:
                if self.finalAckNum != None and self.seqNum > self.finalAckNum:
                    break
                self.do_send(self.seqNum, self.seqNum + self.dataSize * self.windowSize)
                continue
            returnedMessage = self.handle_new_ack(message)
            if returnedMessage == "Checksum":
                continue
            if returnedMessage == "Duplicate":
                if self.duplicates == 3:
                    self.send(self.sentPackets[self.seqNum], dest)
                    self.duplicates = 0
                continue
            if returnedMessage == "OldAck":
                continue
            if returnedMessage == "Forward":
                numPacketsToSend = (ackSeqNum - self.seqNum)/self.dataSize
                self.do_send(self.seqNum + self.dataSize * (self.windowSize - numPacketsToSend), self.seqNum + self.windowSize * self.dataSize)
                continue
            if returnedMessage == "Unknown":
                print "Unknown Error"
                exit(1)
        
        endPacket = self.make_packet("end", self.seqNum, "1")
        self.send(endPacket, self.dest)
        while True:
            message = self.receive(self.timeout)
            if message == None:
                self.send(endPacket, self.dest)
                continue
            packetSeqNum = self.get_packet_seq_num(message)
            if packetSeqNum == self.seqNum + 1:
                break
        print "DONE!"
            
        
        
    def do_send(self, starting_seq, end_seq):
        self.infile.seek(starting_seq)
        for num in range(starting_seq/self.dataSize, end_seq/self.dataSize):
            seqNum = self.dataSize * num
            # we send 1400 bytes at a time/
            data = self.infile.read(self.dataSize)
            # if we finish sending the file
            if data == "":
                self.finalAckNum = (num - 1) * self.dataSize
                return
            if seqNum not in self.sentPackets:
                packet = self.make_packet("data", seqNum, data)
                self.sentPackets[seqNum] = packet
                self.send(packet)
            else:
                self.send(self.sentPackets[seqNum])
    
    # first greeting packet timeout
    def handle_start_timeout(self):
        while True:
            self.send(self.sentPackets[self.seqNum])
            message = self.receive(self.timeout)
            # if we finally have a response, we can start to send the new ack
            if message != None:
                break        
        self.handle_new_ack(message)

    def handle_new_ack(self, ack):
        ackType = self.get_ack_type(ack)
        if ackType == "sack":
            self.do_sack_case(ack)
        elif ackType == "ack":
            self.do_ack_case(ack)
        else:
            print("Error: Did not receive ack")
            exit(1)
            
    def do_ack_case(self, ack):
        ackChecksum = self.get_ack_checksum(ack)
        # if the ack does not have a correct checksum, drop the packet
        # most likely we need to wait for the timeout to resend the packet again
        if ackChecksum != Checksum.generate_checksum(ack):
            return "Checksum"
        ackSeqNum = self.get_packet_seq_num(ack)
        # if the packets come out of order, drop ignore the acks before the window size
        if ackSeqNum < self.seqNum:
            return "OldAck"
        # if we got a duplicate ack with seqNum the same as the current seqNum (where the window starts)
        if ackSeqNum == self.seqNum:
            self.handle_dup_ack(ack)
            return "Duplicate"
        # since it's cumulative acks, we ignore everything as long as we get a ack with higher seqNum
        if ackSeqNum > self.seqNum:
            self.duplicates = 0
            self.seqNum = ackSeqNum
            return "Forward"
        return "Unknown"
            
    def do_sack_case(self, ack):
        pass

    def handle_dup_ack(self, ack):
        self.duplicates += 1

    def log(self, msg):
        if self.debug:
            print msg
    
    def get_ack_type(self, message):
        return message[:message.find("|")]
    
    def get_packet_seq_num(self, message):
        return message[message.find("|") + 1, message.rfind("|")]
    
    def get_ack_checksum(self, message):
        return message[message.rfind("|") + 1:]


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