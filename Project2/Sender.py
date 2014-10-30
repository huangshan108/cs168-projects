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
        self.dataSize = self.dataSize
        self.seqNum = 0
        self.windowSize = 5
        self.sentPackets = {}
        self.maxSize = 1472
        self.minSize = 1000
        self.duplicates = 0
        if sackMode:
            raise NotImplementedError #remove this line when you implement SACK

    # Main sending loop.
    def start(self):
        # sync with the receiver with "greeting message"
        firstPacket = make_packet("start", self.seqNum, "")
        self.send(firstPacket, self.dest)
        self.sentPackets[self.seqNum] = firstPacket
        message = self.receive(self.timeout)
        # no response from receiver when trying to establish the connection
        if message == None:
            self.handle_first_packet_timeout()
        # got response from the receiver and the connection has been established,
        # start to send the data packet
        else:
            self.send_window()
        # TODO while loop to send the data
            

                               
    def handle_first_packet_timeout(self):
        while True:
            self.send(self.sentPackets[self.seqNum])
            message = self.receive(self.timeout)
            if message != None:
                self.do_send(self.seqNum, self.seqNum + self.windowSize * self.dataSize)
                return
        
    def do_send(self, starting_seq, end_seq):
        self.seek(starting_seq)
        for num in range(starting_seq/float(self.dataSize), end_seq/float(self.dataSize)):
            seqNum = self.dataSize * num
            # we send 1400 bytes at a time/
            data = self.infile.read(self.dataSize)
            # if we finish sending the file
            if data == "":
                return
            packet = self.make_packet("data", num, data)
            self.sentPackets[seqNum] = packet
                
    
    def handle_timeout(self):
        if self.seqNum == 0:
            while True:
                self.send(self.sentPackets[self.seqNum])
                message = self.receive(self.timeout)
                if message != None:
                    self.handle_new_ack(

    def handle_new_ack(self, ack):
        ackType = self.get_ack_type(ack)
        if ackType == "sack":
            self.do_sack_case(ack)
        elif ackType == "ack":
            self.do_ack_case(ack)
        else:
            print("Error: Did not receive ack")
            exit()
            
    def do_ack_case(self, ack):
        ackChecksum = self.get_ack_checksum(ack)
        # if the ack does not have a correct checksum, drop the packet
        # most likely we need to wait for the timeout to resend the packet again
        if ackChecksum != Checksum.generate_checksum(ack):
            return
        ackSeqNum = self.get_packet_seq_num(ack)
        # if the packets come out of order, drop ignore the acks before the window size
        if ackSeqNum < self.seqNum:
            return
        # if we got a duplicate ack with seqNum the same as the current seqNum (where the window starts)
        if ackSeqNum == self.seqNum:
            self.duplicates += 1
            if self.duplicates == 3:
                self.handle_dup_ack(ack)
        # since it's cumulative acks, we ignore everything as long as we get a ack with higher seqNum
        if ackSeqNum > self.seqNum:
            self.duplicates = 0
            numPacketsToSend = ackSeqNum - self.seqNum
            self.seqNum = ackSeqNum
            self.do_send(self.seqNum + self.windowSize * self.dataSize - newPacketNum, self.seqNum + self.windowSize * self.dataSize)
            
            
    
               
            
        
       
            
    

    def handle_dup_ack(self, ack):
        pass

    def log(self, msg):
        if self.debug:
            print msg
    
    def get_ack_type(message):
        return message[:message.find("|")]
    
    def get_packet_seq_num(message):
        return message[message.find("|") + 1, message.rfind("|")]
    
    def get_ack_checksum(message):
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
        exit()self.sock.settimeout(None)
        if sackMode:
            raise NotImplementedError #remove this line when you implement SACK

    # Main sending loop.
    def start(self):
        raise NotImplementedError

    def handle_timeout(self):
        pass

    def handle_new_ack(self, ack):
        pass

    def handle_dup_ack(self, ack):
        pass

    def log(self, msg):
        if self.debug:
            print msg


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