#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import time
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.ip_to_geo = []
        self.rules = []
        
        # TODO: Load the firewall rules (from rule_filename) here.
        rule_file = open(config['rule'], "r")
        line = rule_file.readline()
        while line != "":
            if line[0] == "%":
                line = rule_file.readline()
                continue
            stripped_line = line.strip()
            if stripped_line:
                self.rules.append(stripped_line.upper().split())
            line = rule_file.readline()
        rule_file.close()
        self.rules.reverse()
        
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        geoip_file = open("geoipdb.txt", "r")
        line = geoip_file.readline().strip()
        while line != "":
            (starting_ip, ending_ip, county_code)  = line.split(" ")
            starting_ip_int = self.convert_ip_to_integer(starting_ip)
            ending_ip_int = self.convert_ip_to_integer(ending_ip)
            self.ip_to_geo.append((starting_ip_int, ending_ip_int, county_code))
            line = geoip_file.readline().strip()
        geoip_file.close()
            
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        
        IPHeaderNumWords = self.getIPHeaderLength(pkt)
        if IPHeaderNumWords < 5:
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
        IPHeaderNumBytes = 4 * IPHeaderNumWords
        protocolHeader = pkt[IPHeaderNumBytes:]
        doPass = True
        port = None
        print "This is a ", protocol, " packet."
        if protocol == 'ICMP':
            typeNum = self.getICMPType(protocolHeader)
            if pkt_dir == PKT_DIR_INCOMING:
                print "Incoming Packet with source IP: ", IPSourceAddress, " typeNum: ", typeNum
                doPass = self.scanRules(protocol, IPSourceAddress, False, typeNum)
            elif pkt_dir == PKT_DIR_OUTGOING:
                print "Outgoing Packet with dest IP: ", IPDestAddress, " typeNum: ", typeNum
                doPass = self.scanRules(protocol, IPDestAddress, False, typeNum)

        elif protocol == 'TCP':
            if pkt_dir == PKT_DIR_INCOMING:
                port = self.getTCPSourcePort(protocolHeader)
                print "Incoming Packet with source IP: ", IPSourceAddress, " port: ", port
                doPass = self.scanRules(protocol, IPSourceAddress, False, port)
            elif pkt_dir == PKT_DIR_OUTGOING:
                port = self.getTCPDestPort(protocolHeader)
                print "Incoming Packet with source IP: ", IPDestAddress, " port: ", port
                doPass = self.scanRules(protocol, IPDestAddress, False, port)
        elif protocol == 'UDP':
            if pkt_dir == PKT_DIR_INCOMING:
                port = self.getUDPSourcePort(protocolHeader)
                print "Incoming Packet with source IP: ", IPSourceAddress, " port: ", port
                doPass = self.scanRules(protocol, IPSourceAddress, False, port)
            elif pkt_dir == PKT_DIR_OUTGOING:
                port = self.getUDPDestPort(protocolHeader)
                if port == 53:
                    DNSheader = protocolHeader[8:]
                    DNSquestion = self.getDNSQuestion(DNSheader)
                    DNSQDCount = self.getDNSQDCount(DNSheader)
                    DNSQNameBytes = self.getDNSQNameAsBytes(DNSquestion)
                    DNSLenName = self.getDNSQNameLength(DNSQNameBytes)
                    DNSQType = self.getDNSQType(DNSquestion, DNSLenName)
                    DNSQClass = self.getDNSQClass(DNSquestion, DNSLenName)
                    DNSNameStr = self.getDNSQNameAsString(DNSquestion)
                    print "DNSQType: ", DNSQType, " DNSQClass: ", DNSQClass, "DNSQDCount: ", DNSQDCount
                    if (DNSQType == 1 or DNSQType == 28) and DNSQClass == 1 and DNSQDCount == 1:
                        print "[DNS]Incoming Packet with source IP: ", IPSourceAddress, " port: ", port, " DNSNameStr: ", DNSNameStr
                        doPass = self.scanRules(protocol, IPDestAddress, True, port, DNSNameStr)
                    else:
                        print "Incoming Packet with source IP: ", IPDestAddress, " port: ", port
                        doPass = self.scanRules(protocol, IPDestAddress, False, port)
                else:
                    print "Incoming Packet with source IP: ", IPDestAddress, " port: ", port
                    doPass = self.scanRules(protocol, IPDestAddress, False, port)

        print "doPass: ", doPass
        print
        if doPass == False:
            return
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)


    # TODO: You can add more methods as you want.
    
    def getIPHeaderLength(self, IPheader):
        return ord(IPheader[0]) & 0x0f
    
    def getIPTotalLength(self, IPheader):
        return struct.unpack('!H', IPheader[2:4])[0]
    
    def getIPSourceAsStr(self, IPheader):
        return socket.inet_ntoa(IPheader[12:16])
    
    def getIPProtocol(self, IPheader):
        return ord(IPheader[9])
        
    def getIPDestAsStr(self, IPheader):
        return socket.inet_ntoa(IPheader[16:20])
    
    def getTCPSourcePort(self, TCPheader):
        return struct.unpack('!H', TCPheader[0:2])[0]
        
    def getTCPDestPort(self, TCPheader):
        return struct.unpack('!H', TCPheader[2:4])[0]
    
    def getUDPSourcePort(self, UDPheader):
        return struct.unpack('!H', UDPheader[0:2])[0]
    
    def getUDPDestPort(self, UDPheader):
        return struct.unpack('!H', UDPheader[2:4])[0]
        
    def getUDPLength(self, UDPheader):
        return struct.unpack('!H', UDPheader[4:6])[0]
    
    def getUDPChecksum(self, UDPheader):
        return struct.unpack('!H', UDPheader[6:8])[0]
    
    def getICMPType(self, ICMPheader):
        return ICMPheader[0]
    
    def getDNSQDCount(self, DNSheader):
         return struct.unpack('!H', DNSheader[4:6])[0]
    
    def getDNSQuestion(self, DNSheader):
        return DNSheader[12:]
    
    def getDNSQNameAsBytes(self, DNSquestion):
        #return the QName as a string of hex values (see spec)
        byteNum = 0
        while ord(DNSquestion[byteNum]) != 0:
            byteNum += ord(DNSquestion[byteNum]) + 1
        return DNSquestion[:byteNum+1]
    
    def getDNSQNameAsString(self, DNSquestion):
        byteNum = 0
        url = ""
        while ord(DNSquestion[byteNum]) != 0:
            for i in range(1, ord(DNSquestion[byteNum])+1):
                url += chr(ord(DNSquestion[byteNum+i]))
            byteNum += ord(DNSquestion[byteNum]) + 1
            if ord(DNSquestion[byteNum]) != 0:
                url += '.'
        return url
        
    
    def getDNSQNameLength(self, DNSQName):
        #input: DNSQName as the result of function to call to getDNSQNameAsBytes()
        return len(DNSQName)
    
    def getDNSQType(self, DNSquestion, DNSQNameLength):
        #returns integer of QType
        return struct.unpack('!H', DNSquestion[DNSQNameLength:DNSQNameLength+2])[0]
    
    def getDNSQClass(self, DNSquestion, DNSQNameLength):
        #returns integer of QClass
        return struct.unpack('!H', DNSquestion[DNSQNameLength+2:DNSQNameLength+4])[0]
    
        
    # return True is packet should pass, False if we need to drop it
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
                    return return_msg_ip and return_msg_port
        return True
    
    def handleIP(self, ip, rule):
        rule_ip = rule[2]
        if rule_ip == "ANY":
            return "PASS" == rule[0]
        # two bytes country code
        elif len(rule_ip) == 2:
            # print geoBinarySearch(ip_to_geo, convert_ip_to_integer(ip))
            if rule_ip == self.geoBinarySearch(self.ip_to_geo, self.convert_ip_to_integer(ip)):
                return "PASS" == rule[0]
            else:
                return "not-match"
        # match the ip directly
        elif rule_ip == ip:
            return "PASS" == rule[0]
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
                return "PASS" == rule[0] 
            for i in range(0, prefix / 8):
                if int(ip_bytes[i]) != int(rule_ip_bytes[i]):
                    return "not-match"
            if int(ip_bytes[prefix / 8]) >> (8 - prefix % 8) == int(rule_ip_bytes[prefix / 8]) >> (8 - prefix % 8):
                return "PASS" == rule[0]
            return "not-match"
    
    def handlePort(self, port, rule):
        rule_port = rule[3]
        if rule_port == "ANY":
            return "PASS" == rule[0]
        elif str(port) == rule_port:
            return "PASS" == rule[0]
        elif rule_port.find("-") == -1:
            return "not-match"
        else:
            starting_port, ending_port = rule_port.split("-")
            if port <= int(ending_port) and port >= int(starting_port):
                return "PASS" == rule[0]
            else:
                return "not-match"
    
    def handleDNS(self, dns, rule):
        dns_rule = rule[2]
        dns = dns.upper()
        if dns_rule[0] == "*":
            if len(dns) > len(dns_rule[1:]) and dns_rule[1:] == dns[(len(dns) - len(dns_rule[1:])):]:
                return "PASS" == rule[0]
            else:
                return "not-match"
        elif dns_rule == dns:
            return "PASS" == rule[0]
        return "not-match"
    
    
    
    # template: (3360768000, 3360781839, 'AR')
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