#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

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
        pass

    # TODO: You can add more methods as you want.
    
    def getIPHeaderLength(self, IPheader):
        return IPheader[0] & 0x0f
    
    def getIPTotalLength(self, IPheader):
        return struct.unpack('!H', IPheader[2:4])[0]
    
    def getIPSourceAsStr(self, IPheader):
        return socket.inet_ntoa(IPheader[12:16])
    
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
    
    def getDNSQNameAsBytes(self, DNSquestion):
        #return the QName as a string of hex values (see spec)
        byteNum = 0
        while ord(DNSquestion[byteNum]) != 0:
            byteNum += ord(DNSquestion[byteNum]) + 1
        return DNSquestion[:byteNum+1]
    
    def getDNSQNameLength(self, DNSQName):
        #input: DNSQName as the result of function to call to getDNSQNameAsBytes()
        return len(DNSQName)
    
    def getDNSQType(self, DNSquestion, DNSQNameLength):
        #returns integer of QType
        return struct.unpack('!H', DNSquestion[DNSQNameLength:DNSQNameLength+2]
    
    def getDNSQClass(self, DNSquestion, DNSQNameLength):
        #returns integer of QClass
        return struct.unpack('!H', DNSquestion[DNSQNameLength+2:DNSQNameLength+4]
    
    
        
        
    def parseIPHeader():
        pass
        
    # return True is packet show pass, False if we need to drop it
    # ip_or_dns: if ip, pass in the dot notation, not the ip_to_integer
    def scanRules(protocol_type, ip_or_dns, dns_packet = False, port = None):
        protocol_type = protocol_type.upper()
        ip_or_dns = ip_or_dns.upper()
        for rule in rules:
            if protocol_type == rule[1]:
                if dns_packet:
                    return_msg = handleDNS(ip_or_dns, rules)
                    if return_msg == "continue":
                        continue
                    else:
                        return return_msg
                else:
                    return_msg_ip = handleIP(ip_or_dns, rule)
                    if return_msg_ip == "continue":
                        continue
                    elif return_msg_ip:
                        return_msg_port = handlePort(port, rule)
                        if return_msg_port == "continue":
                            continue
                        else:
                            return return_msg_port
                    return return_msg_ip
        return True
    
    def handleIP(ip, rule):
        rule_ip = rule[2]
        if rule_ip == "ANY":
            return "PASS" == rule[0]
        # two bytes country code
        elif len(rule_ip) == 2:
            # print geoBinarySearch(ip_to_geo, convert_ip_to_integer(ip))
            if rule_ip == geoBinarySearch(ip_to_geo, convert_ip_to_integer(ip)):
                return "PASS" == rule[0]
            else:
                return "continue"
        # match the ip directly
        elif rule_ip == ip:
            return "PASS" == rule[0]
        # rule is a ip and does not match. continue
        elif rule_ip.find("/") == -1:
            return "continue"
        # rule is a ip prefix
        else:
            rule_ip, prefix = rule_ip.split("/")
            prefix = int(prefix)
            ip_bytes = ip.split(".")
            rule_ip_bytes = rule_ip.split(".")
            for i in range(0, prefix / 8):
                if int(ip_bytes[i]) != int(rule_ip_bytes[i]):
                    return False
            return int(ip_bytes[prefix / 8]) >> (8 - prefix % 8) == int(rule_ip_bytes[prefix / 8]) >> (8 - prefix % 8)
    
    def handlePort(port, rule):
        rule_port = rule[3]
        if rule_port == "ANY":
            return "PASS" == rule[0]
        elif port == rule_port:
            return "PASS" == rule[0]
        elif rule_port.find("-") == -1:
            return "continue"
        else:
            starting_port, ending_port = rule_port.split("-")
            if port <= int(ending_port) and port >= int(starting_port):
                return "PASS" == rule[0]
            else:
                return "continue"
    
    def handleDNS(dns, rule):
        dns_rule = rule[3]
        if dns_rule[0] == "*":
            if len(dns) > len(dns[1:]) and dns_rule[1:] == dns[(len(dns) - len(dns_rule[1:])):]:
                return "PASS" == rule[0]
            else:
                return "continue"
        elif dns_rule == dns:
            return "PASS" == rule[0]
        return "continue"
    
    
    
    # template: (3360768000, 3360781839, 'AR')
    # IPaddress: the integer notation of an ip address
    def geoBinarySearch(self, IPaddress):
        mid = len(self.ip_to_geo)/2
        if IPaddress >= self.ip_to_geo[mid][0] and IPaddress <= self.ip_to_geo[mid][1]:
            return self.ip_to_geo[mid][2]
        elif IPaddress < self.ip_to_geo[mid][0]:
            return self.geoBinarySearch(self.ip_to_geo[:mid], IPaddress)
        else:
            return self.geoBinarySearch(self.ip_to_geo[mid+1:], IPaddress)
        
    def convert_ip_to_integer(self, ip):
        (one, two, three, four) = ip.split(".")
        ip_integer = int(one) * 2 ** 24 + int(two) * 2 ** 16 + int(three) * 2 ** 8 + int(four)
        return ip_integer
        
# TODO: You may want to add more classes/functions as well.
