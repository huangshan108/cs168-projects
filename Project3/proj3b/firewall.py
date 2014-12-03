#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time
import sys
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.ip_to_geo = []
        self.rules = []
        self.log_rules = []
        self.inc_seq_num_mapping = {} #maps tuple of (int_port, ext_ip) to seqNum for incoming packets
        self.out_seq_num_mapping = {} #maps tuple of (int_port, ext_ip) to seqNum for outgoing packets
    
        self.request_dict = {}
        self.response_dict = {}
        self.http_request_done = set()
        self.http_response_done = set()
        # TODO: Load the firewall rules (from rule_filename) here.
        rule_file = open(config['rule'], "r")
        line = rule_file.readline()
        while line != "":
            if line[0] == "%":
                line = rule_file.readline()
                continue
            stripped_line = line.strip()
            if stripped_line:
                if stripped_line.upper().split()[0] == "LOG":
                    self.log_rules.append(stripped_line.upper().split())
                else:
                    self.rules.append(stripped_line.upper().split())
            line = rule_file.readline()
        rule_file.close()
        self.rules.reverse()
        self.log_rules.reverse()

        self.httplog = open('http.log', 'a')

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        
        IPHeaderNumWords = self.getIPHeaderLength(pkt)
        if IPHeaderNumWords < 5:
            return
        if len(pkt) < 20:
            return
        IPTotalLen = self.getIPTotalLength(pkt)
        if IPTotalLen != len(pkt):
            return
        IPSourceAddress = self.getIPSourceAsStr(pkt)
        IPDestAddress = self.getIPDestAsStr(pkt)
        protocolNum = self.getIPProtocol(pkt)
        protocol = None
        if protocolNum == 1:
            protocol = 'ICMP'
        elif protocolNum == 6:
            protocol = 'TCP'
        elif protocolNum == 17:
            protocol = 'UDP'
        else:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            return
        IPHeaderNumBytes = 4 * IPHeaderNumWords
        protocolHeader = pkt[IPHeaderNumBytes:]
        doPass = "PASS"
        port = None
        if protocol == 'ICMP':
            if len(protocolHeader) < 4:
                return
            typeNum = self.getICMPType(protocolHeader)
            if pkt_dir == PKT_DIR_INCOMING:
                doPass = self.scanRules(protocol, IPSourceAddress, False, typeNum)
            elif pkt_dir == PKT_DIR_OUTGOING:
                doPass = self.scanRules(protocol, IPDestAddress, False, typeNum)
        elif protocol == 'TCP':
            if len(protocolHeader) < 20:
                return
            if pkt_dir == PKT_DIR_INCOMING:
                port = self.getTCPSourcePort(protocolHeader)
                doPass = self.scanRules(protocol, IPSourceAddress, False, port)
                if port == 80:
                    TCPoffset = ord(protocolHeader[12]) >> 4
                    response = protocolHeader[TCPoffset*4:]
                    # print "response: ", response
                    # index = response.find("\r\n\r\n")
                    # if index != -1:
                    #     response = response[:index]
                    #     print "response: "
                    #     print response
            elif pkt_dir == PKT_DIR_OUTGOING:
                port = self.getTCPDestPort(protocolHeader)
                doPass = self.scanRules(protocol, IPDestAddress, False, port)
                # if port == 80:
                #     TCPoffset = ord(protocolHeader[12]) >> 4
                #     request = protocolHeader[TCPoffset*4:]
                #     index = request.find("\r\n\r\n")
                #     if index != -1:
                #         request = request[:index]
                #         print "request: "
                #         print request
        elif protocol == 'UDP':
            if len(protocolHeader) < 8:
                return
            if pkt_dir == PKT_DIR_INCOMING:
                port = self.getUDPSourcePort(protocolHeader)
                doPass = self.scanRules(protocol, IPSourceAddress, False, port)
            elif pkt_dir == PKT_DIR_OUTGOING:
                port = self.getUDPDestPort(protocolHeader)
                if port == 53:
                    DNSheader = protocolHeader[8:]
                    if len(DNSheader) < 12:
                        return
                    DNSquestion = self.getDNSQuestion(DNSheader)
                    DNSQDCount = self.getDNSQDCount(DNSheader)
                    DNSQNameBytes = self.getDNSQNameAsBytes(DNSquestion)
                    if DNSQNameBytes == None:
                        return
                    DNSLenName = self.getDNSQNameLength(DNSQNameBytes)
                    if len(DNSquestion) < DNSLenName + 4:
                        return
                    DNSQType = self.getDNSQType(DNSquestion, DNSLenName)
                    DNSQClass = self.getDNSQClass(DNSquestion, DNSLenName)
                    DNSNameStr = self.getDNSQNameAsString(DNSquestion)
                    if DNSNameStr == None:
                        return
                    if (DNSQType == 1 or DNSQType == 28) and DNSQClass == 1 and DNSQDCount == 1:
                        doPass = self.scanRules(protocol, IPDestAddress, True, port, DNSNameStr)
                    else:
                        doPass = self.scanRules(protocol, IPDestAddress, False, port)
                else:
                    doPass = self.scanRules(protocol, IPDestAddress, False, port)
        if doPass == "DROP":
            return
        elif doPass == "DENY":
            #do deny
            if protocol == 'TCP':
                newIPheader = self.consturctIPheaderTCPRST(pkt)
                TCPpsuedo = self.getTCPPseudoHeader(newIPheader)
                origTCPheader = protocolHeader
                newTCPheader = self.constructTCPheader(origTCPheader, TCPpsuedo)
                finalPacket = newIPheader + newTCPheader
                self.iface_int.send_ip_packet(finalPacket)
            else: #must be DNS packet
                DNSheader = protocolHeader[8:]
                newDNS = self.constructDNS(DNSheader)
                newUDP = self.constructUDPHeader(protocolHeader, len(newDNS))
                newIPheader = self.consturctIPheaderDNS(pkt, len(newDNS))
                finalPacket = newIPheader + newUDP + newDNS
                self.iface_int.send_ip_packet(finalPacket)
        elif doPass == "PASS":
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            if protocol != 'TCP':
                return
            extPort = None
            intPort = None
            ext_ip = None
            tryLog = False
            if pkt_dir == PKT_DIR_INCOMING:
                extPort = self.getTCPSourcePort(protocolHeader)
                intPort = self.getTCPDestPort(protocolHeader)
                ext_ip = self.getIPSourceAsStr(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                extPort = self.getTCPDestPort(protocolHeader) 
                intPort = self.getTCPSourcePort(protocolHeader)
                ext_ip = self.getIPDestAsStr(pkt)
            if extPort != 80:
                return
            TCPSyn = ord(protocolHeader[13]) & 0x02
            TCPHeaderLen = (ord(protocolHeader[12]) >> 4) * 4
            NumDataBytes = len(protocolHeader) - TCPHeaderLen
            TCPSeqNum = struct.unpack('!L', protocolHeader[4:8])[0]
            if TCPSyn != 0 and pkt_dir == PKT_DIR_INCOMING: #packet is syn, packet is incoming
                if (intPort, ext_ip) not in self.inc_seq_num_mapping:
                    self.inc_seq_num_mapping[(intPort,ext_ip)] = TCPSeqNum + 1
            elif TCPSyn != 0 and pkt_dir == PKT_DIR_OUTGOING:
                if (intPort, ext_ip) not in self.inc_seq_num_mapping:
                    self.out_seq_num_mapping[(intPort,ext_ip)] = TCPSeqNum + 1
            elif TCPSyn == 0 and pkt_dir == PKT_DIR_INCOMING:
                if NumDataBytes == 0:
                    if (intPort,ext_ip) in self.inc_seq_num_mapping:
                        del self.inc_seq_num_mapping[(intPort,ext_ip)]
                else:
                    if (intPort,ext_ip) not in self.inc_seq_num_mapping:
                        self.inc_seq_num_mapping[(intPort,ext_ip)] = (TCPSeqNum + NumDataBytes) % pow(2,32)
                        tryLog = True
                    current = self.inc_seq_num_mapping[(intPort,ext_ip)]
                    if current < 500000:
                        if TCPSeqNum > current and TCPSeqNum < pow(2,32) - (500000-current):
                            return
                    elif TCPSeqNum > self.inc_seq_num_mapping[(intPort,ext_ip)]:
                        return
                    elif TCPSeqNum == self.inc_seq_num_mapping[(intPort,ext_ip)]:
                        self.inc_seq_num_mapping[(intPort,ext_ip)] = (TCPSeqNum + NumDataBytes) % pow(2,32)
                        tryLog = True
            elif TCPSyn == 0 and pkt_dir == PKT_DIR_OUTGOING:
                if NumDataBytes == 0:
                    if (intPort,ext_ip) in self.out_seq_num_mapping:
                        del self.out_seq_num_mapping[(intPort,ext_ip)]
                else:
                    if (intPort,ext_ip) not in self.out_seq_num_mapping:
                        self.out_seq_num_mapping[(intPort,ext_ip)] = (TCPSeqNum + NumDataBytes) % pow(2,32)
                        tryLog = True
                    current = self.out_seq_num_mapping[(intPort,ext_ip)]
                    if current < 500000:
                        if TCPSeqNum > current and TCPSeqNum < pow(2,32) - (500000-current):
                            return
                    elif TCPSeqNum > self.out_seq_num_mapping[(intPort,ext_ip)]:
                        return
                    elif TCPSeqNum == self.out_seq_num_mapping[(intPort,ext_ip)]:
                        self.out_seq_num_mapping[(intPort,ext_ip)] = (TCPSeqNum + NumDataBytes) % pow(2,32)
                        tryLog = True

            if not tryLog:
                return
            HTTPheader = protocolHeader[TCPHeaderLen:]
            request, response = self.processTCPSegs(HTTPheader, intPort, ext_ip, pkt_dir)
            
            # do below after we get all tcp frags
            # print "request: "
            # print request
            # print "response: "
            # print response
            if request != None and response != None:
                host_header = self.getHostHeader(request)
                doLog = self.scanLogRules(ext_ip, host_header)
                # print "request: " 
                # print request
                # print "response: "
                # print response 
                # print "ext_ip: ", ext_ip
                # print "host_header: ", host_header
                # print "doLog: ", doLog
                # print
                if doLog == 'LOG':
                    self.logHTTP(request, response, ext_ip)
                
    # TODO: You can add more methods as you want.
    
    def getIPHeaderLength(self, IPheader):
        return ord(IPheader[0]) & 0x0f
    
    def getIPTotalLength(self, IPheader):
        return struct.unpack('!H', IPheader[2:4])[0]
    
    def getIPSourceAsStr(self, IPheader):
        return socket.inet_ntoa(IPheader[12:16])

    def getIPSourceAsBytes(self, IPheader):
        return IPheader[12:16]
    
    def getIPProtocol(self, IPheader):
        return ord(IPheader[9])

    def getIPProtocolAsBytes(self, IPheader):
        return IPheader[9]
        
    def getIPDestAsStr(self, IPheader):
        return socket.inet_ntoa(IPheader[16:20])

    def getIPDestAsBytes(self, IPheader):
        return IPheader[16:20]

    def getTCPSourcePort(self, TCPheader):
        return struct.unpack('!H', TCPheader[0:2])[0]

    def setTCPSourcePort(self, TCPheader, port):
        #port must be integer
        TCPheader[0] = chr(port & 0x00ff)
        TCPheader[1] = chr(port & 0xff00)
        
    def getTCPDestPort(self, TCPheader):
        return struct.unpack('!H', TCPheader[2:4])[0]

    def setTCPDestPort(self, TCPheader, port):
        #port must be integer
        TCPheader[2] = chr(port & 0x00ff)
        TCPheader[3] = chr(port & 0xff00)

    def setTCPRstFlag(self, TCPheader):
        TCP[13:14] = chr(ord(TCP[13:14]) | 0x04)

    def getTCPPseudoHeader(self, IPheader):
        #SourceIP and DestIP must be in byte format
        #return None if length is too long
        #assume TCPheader length is 20
        psuedoHeader = []
        source = self.getIPSourceAsBytes(IPheader)
        dest = self.getIPDestAsBytes(IPheader)
        psuedoHeader.append(source)
        psuedoHeader.append(dest)
        psuedoHeader.append('\x00')
        psuedoHeader.append(self.getIPProtocolAsBytes(IPheader))
        psuedoHeader.append(struct.pack('!H', 20))
        return "".join(psuedoHeader)

    def computeTCPChecksum(self, TCPheader, psuedoHeader):
        #assumes that payload has been removed from TCPheader
        if psuedoHeader == None:
            return None
        start = 0
        total = 0
        TCPheader = TCPheader + psuedoHeader
        while start < len(TCPheader)-1:
            total += struct.unpack('!H', TCPheader[start:start+2])[0]
            start += 2
        if len(TCPheader) & 1 != 0:
            total += ord(TCPheader[start])
        while total >> 16 != 0:
            carry = total >> 16
            result = total & 0xFFFF
            total = carry + result
        return ~total

    def computeIPChecksum(self, IPheader):
        #returns checksum as integer
        #also assumes checksum field of header is 0
        start = 0
        total = 0
        while start < len(IPheader)-1:
            total += struct.unpack('!H', IPheader[start:start+2])[0]
            start += 2
        if len(IPheader) % 2 != 0:
            total += ord(IPheader[start])
        while total >> 16 != 0:
            carry = total >> 16
            result = total & 0xFFFF
            total = carry + result
        return ~total

    def consturctIPheaderDNS(self, origIPheader, DNSNumBytes):
        #creates an IP header for the deny DNS rule
        header = list(origIPheader[0:20])
        header[0] = origIPheader[0] 
        header[1] = chr(5)
        header[2:4] = struct.pack('!H', 20+8+DNSNumBytes)#20 for ip and 8 for udp
        header[4:8] = struct.pack('!L', 0)
        header[8] = struct.pack('!B', 64)
        header[9] = origIPheader[9]
        header[10:12] = struct.pack('!H', 0)
        header[12:16] = origIPheader[16:20]
        header[16:20] = origIPheader[12:16]
        checksum = self.computeIPChecksum("".join(header)) & 0xffff
        header[10:12] = struct.pack('!H', checksum)
        return "".join(header)

    def consturctIPheaderTCPRST(self, origIPheader):
        #only works for TCP because of length
        header = list(origIPheader[0:20])
        header[0] = origIPheader[0] 
        header[1] = chr(5)
        header[2:4] = struct.pack('!H', 40)
        header[4:8] = struct.pack('!L', 0)
        header[8] = struct.pack('!B', 64)
        header[9] = origIPheader[9]
        header[10:12] = struct.pack('!H', 0)
        header[12:16] = origIPheader[16:20]
        header[16:20] = origIPheader[12:16]
        checksum = self.computeIPChecksum("".join(header)) & 0xffff
        header[10:12] = struct.pack('!H', checksum)
        return "".join(header)

    def constructTCPheader(self, origTCPheader, pseudoHeader):
        #creates RST TCP packet with empty payload
        header = list(origTCPheader[0:20])
        header[0:2] = origTCPheader[2:4]
        header[2:4] = origTCPheader[0:2]
        header[4:8] = struct.pack('!L', 1)
        ackNum = struct.unpack('!L', origTCPheader[4:8])[0]+1
        header[8:12] = struct.pack('!L', ackNum)
        header[12] = chr(0x50)
        header[13] = chr(0x14)
        header[14:16] = struct.pack('!H', 0)
        header[16:18] = struct.pack('!H', 0)
        header[18:20] = struct.pack('!H', 0)
        checksum = self.computeTCPChecksum("".join(header), pseudoHeader) & 0xffff
        header[16:18] = struct.pack('!H', checksum)
        return "".join(header)

    def getUDPSourcePort(self, UDPheader):
        return struct.unpack('!H', UDPheader[0:2])[0]
    
    def getUDPDestPort(self, UDPheader):
        return struct.unpack('!H', UDPheader[2:4])[0]
        
    def getUDPLength(self, UDPheader):
        return struct.unpack('!H', UDPheader[4:6])[0]
    
    def getUDPChecksum(self, UDPheader):
        return struct.unpack('!H', UDPheader[6:8])[0]
    
    def getICMPType(self, ICMPheader):
        return ord(ICMPheader[0])
    
    def getDNSQDCount(self, DNSheader):
        return struct.unpack('!H', DNSheader[4:6])[0]
    
    def getDNSQuestion(self, DNSheader):
        return DNSheader[12:]
    
    def getDNSQNameAsBytes(self, DNSquestion):
        #return the QName as a string of hex values (see spec)
        byteNum = 0
        try:
            while ord(DNSquestion[byteNum]) != 0:
                byteNum += ord(DNSquestion[byteNum]) + 1
        except IndexError:
            return None
        return DNSquestion[:byteNum+1]
    
    def getDNSQNameAsString(self, DNSquestion):
        byteNum = 0
        url = ""
        try:
            while ord(DNSquestion[byteNum]) != 0:
                for i in range(1, ord(DNSquestion[byteNum])+1):
                    url += chr(ord(DNSquestion[byteNum+i]))
                byteNum += ord(DNSquestion[byteNum]) + 1
                if ord(DNSquestion[byteNum]) != 0:
                    url += '.'
        except IndexError:
            return None
        return url

    def constructUDPHeader(self, origUDPheader, DNSNumBytes):
        header = list()
        header.append(origUDPheader[2:4]) #source port
        header.append(origUDPheader[0:2]) #dest port
        header.append(struct.pack('!H', 8+DNSNumBytes)) #length
        header.append(struct.pack('!H', 0)) #checksum
        return "".join(header)


    def constructDNS(self, DNSheader):
        header = list(DNSheader[:12])
        header[2] = chr(ord(DNSheader[2]) | 0x80)
        header[7] = chr(0x01)
        header[8:10] = struct.pack('!H', 0)
        header[10:12] = struct.pack('!H', 0)
        DNSQuestion = DNSheader[12:]
        DNSQNameBytes = self.getDNSQNameAsBytes(DNSQuestion)
        questionLength = 4 + len(DNSQNameBytes)
        question = list(DNSQuestion[:questionLength])
        answer = list()
        answer.append(DNSQNameBytes) #NAME
        answer.append(struct.pack('!H', 1)) #TYPE
        answer.append(struct.pack('!H', 1)) #CLASS
        answer.append(struct.pack('!L', 1)) #TTL
        answer.append(struct.pack('!H', 4)) #RDLength
        answer.append(socket.inet_aton('54.173.224.150'))
        result = "".join(header+question+answer)
        return result

    def getDNSQNameLength(self, DNSQName):
        #input: DNSQName as the result of function to call to getDNSQNameAsBytes()
        return len(DNSQName)
    
    def getDNSQType(self, DNSquestion, DNSQNameLength):
        #returns integer of QType
        return struct.unpack('!H', DNSquestion[DNSQNameLength:DNSQNameLength+2])[0]
    
    def getDNSQClass(self, DNSquestion, DNSQNameLength):
        #returns integer of QClass
        return struct.unpack('!H', DNSquestion[DNSQNameLength+2:DNSQNameLength+4])[0]
    
    def logHTTP(self, request, response, ext_tcp_ip = None):
        """
        sample input:

        request = "GET / HTTP/1.1\nHost: google.com\nUser-Agent: Web-sniffer/1.0.46 (+http://web-sniffer.net/ Accept-Encoding: gzip\nAccept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7 Cache-Control: no-cache\nAccept-Language: de,en;q=0.7,en-us;q=0.3\n"

        response = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.google.com/\nContent-Type: text/html; charset=UTF-8\nDate: Mon, 18 Nov 2013 23:58:12 GMT\nExpires: Wed, 18 Dec 2013 23:58:12 GMT\nCache-Control: public, max-age=2 592000\nServer: gws\nContent-Length: 219\nX-XSS-Protection: 1; mode=block\nX-Frame-Options: SAMEORIGIN Alternate-Protocol: 80:quic\n"
        """
        request = request.split('\n')
        response = response.split('\n')
        request_line = request[0]
        response_line = response[0]
        host_name = ext_tcp_ip
        method = request_line.split()[0]
        path = request_line.split()[1]
        version = request_line.split()[2]
        # print "response_line: ", response_line
        status_cdoe = response_line.split()[1]
        object_size = "-1"
        for field in request:
            if field.split()[0] == "Host:":
                host_name = field.split()[1]
                break
        for field in response:
            # print "split: ", field.split()
            if field.split() != [] and field.split()[0] == "Content-Length:":
                object_size = field.split()[1]
                break

        self.httplog.write(host_name + " " + method + " " + path + " " + version + " " + status_cdoe + " " + object_size + "\n")
        self.httplog.flush()

    # return "LOG" if we need to log this http packet
    # return None if we don't need to 
    def scanLogRules(self, ext_ip, host_header = None):
        for log_rule in self.log_rules:
            return_msg = self.handleHostname(ext_ip, host_header, log_rule)
            if return_msg == "not-match":
                continue
            else:
                return return_msg

    # return "PASS", "DROP", "DENY"
    # ip_or_dns: if ip, pass in the dot notation, not the ip_to_integer
    def scanRules(self, protocol_type, ip, dns_packet = False, port = None, dns_server = None):
        # print protocol_type
        protocol_type = protocol_type.upper()
        ip = ip.upper()
        for rule in self.rules:
            if dns_packet and "DNS" == rule[1]:
                return_msg = self.handleDNS(dns_server, rule)
                if return_msg == "not-match":
                    continue
                else:
                    return return_msg
            if protocol_type == rule[1]:
                return_msg_ip = self.handleIP(ip, rule)
                return_msg_port = self.handlePort(port, rule)
                if return_msg_ip == "not-match" or return_msg_port == "not-match":
                    continue
                else:
                    if return_msg_ip != return_msg_port:
                        sys.exit("return_msg_ip and return_msg_port should be the same!")
                    return return_msg_ip
        return "PASS"
    
    def handleIP(self, ip, rule):
        rule_ip = rule[2]
        if rule_ip == "ANY":
            return rule[0]
        # two bytes country code
        elif len(rule_ip) == 2:
            # print geoBinarySearch(ip_to_geo, convert_ip_to_integer(ip))
            if rule_ip == self.geoBinarySearch(self.ip_to_geo, self.convert_ip_to_integer(ip)):
                return rule[0]
            else:
                return "not-match"
        # match the ip directly
        elif rule_ip == ip:
            return rule[0]
        # rule is a ip and does not match. continue
        elif rule_ip.find("/") == -1:
            return "not-match"
        # rule is a ip prefix
        else:
            rule_ip, prefix = rule_ip.split("/")
            prefix = int(prefix)
            ip_bytes = ip.split(".")
            rule_ip_bytes = rule_ip.split(".")
            if prefix == 0:
                return rule[0] 
            for i in range(0, prefix / 8):
                if int(ip_bytes[i]) != int(rule_ip_bytes[i]):
                    return "not-match"
            if int(ip_bytes[prefix / 8]) >> (8 - prefix % 8) == int(rule_ip_bytes[prefix / 8]) >> (8 - prefix % 8):
                return rule[0]
            return "not-match"
    
    def handlePort(self, port, rule):
        rule_port = rule[3]
        if rule_port == "ANY":
            return rule[0]
        elif str(port) == rule_port:
            return rule[0]
        elif rule_port.find("-") == -1:
            return "not-match"
        else:
            starting_port, ending_port = rule_port.split("-")
            if port <= int(ending_port) and port >= int(starting_port):
                return rule[0]
            else:
                return "not-match"
    
    def handleDNS(self, dns, rule):
        dns_rule = rule[2]
        dns = dns.upper()
        if dns_rule[0] == "*":
            if len(dns) > len(dns_rule[1:]) and dns_rule[1:] == dns[(len(dns) - len(dns_rule[1:])):]:
                return rule[0]
            else:
                return "not-match"
        elif dns_rule == dns:
            return rule[0]
        return "not-match"
    
    def handleHostname(self, ext_ip, host_header, log_rule):
        match_dns = ""
        if host_header != None:
            match_dns = self.handleDNS(host_header.upper(), log_rule)
        match_ip = ""
        if ext_ip == log_rule[2]:
            match_ip = log_rule[0]
        else:
            match_ip = "not-match"
        if match_dns == "LOG" or match_ip == "LOG":
            return "LOG"
        return "not-match"

    # sample: (3360768000, 3360781839, 'AR')
    # IPaddress: the integer notation of an ip address
    def geoBinarySearch(self, IPList, IPaddress):
        low = 0
        high = len(IPList) - 1
        while low <= high:
            mid = (low + high) / 2
            if IPaddress >= IPList[mid][0] and IPaddress <= IPList[mid][1]:
                return IPList[mid][2]
            elif IPaddress < IPList[mid][0]:
                high = mid - 1
            else:
                low = mid + 1
        
    def convert_ip_to_integer(self, ip):
        (one, two, three, four) = ip.split(".")
        ip_integer = int(one) * 2 ** 24 + int(two) * 2 ** 16 + int(three) * 2 ** 8 + int(four)
        return ip_integer
    
    # return the host in header if one exists,
    # None if no thus field or field is empty
    def getHostHeader(self, request):
        beginning_index = request.find("Host: ")
        # print "beginning_index: ", beginning_index
        if beginning_index == -1:
            return None
        beginning_index += 5
        end_index = request.find("\n", beginning_index)
        temp = request[beginning_index:end_index].split()
        if temp == []:
            return
        return temp[0]

    def processTCPSegs(self, seg, int_port, ext_ip, pkt_dir):
        seg_key = (int_port, ext_ip)
        
        request = None
        response = None
        
        if pkt_dir == PKT_DIR_OUTGOING:
            if seg_key in self.http_request_done:
                return request, response
            header_str, is_end = self.parseHeaderSeg(seg)
            if seg_key in self.request_dict:
                self.request_dict[seg_key] += header_str
            else:
                self.request_dict[seg_key] = header_str
            if is_end:
                self.http_request_done.add(seg_key)
                if seg_key in self.http_response_done:
                    request = self.request_dict[seg_key]
                    response = self.response_dict[seg_key]
                    del self.request_dict[seg_key]
                    del self.response_dict[seg_key]
                    self.http_request_done.remove(seg_key)
                    self.http_response_done.remove(seg_key)
                    return request, response

        
        if pkt_dir == PKT_DIR_INCOMING:
            if seg_key in self.http_response_done:
                return request, response
            if seg_key not in self.request_dict:
                return request, response
            header_str, is_end = self.parseHeaderSeg(seg)

            if seg_key in self.response_dict:
                self.response_dict[seg_key] += header_str
            else:
                self.response_dict[seg_key] = header_str
            if is_end:
                self.http_response_done.add(seg_key)
                if seg_key in self.http_request_done:
                    request = self.request_dict[seg_key]
                    response = self.response_dict[seg_key]
                    del self.request_dict[seg_key]
                    del self.response_dict[seg_key]
                    self.http_request_done.remove(seg_key)
                    self.http_response_done.remove(seg_key)
                    return request, response

        return request, response

    def parseHeaderSeg(self, seg):
        index = seg.find("\r\n\r\n")
        if index == -1:
            return seg, False
        return seg[:index], True