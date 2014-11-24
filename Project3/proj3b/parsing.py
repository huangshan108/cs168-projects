ip_to_geo = []
rules = []
def load_geoipdb():
    geoip_file = open("geoipdb.txt", "r")
    line = geoip_file.readline().strip()
    while line != "":
        (starting_ip, ending_ip, county_code)  = line.split(" ")
        starting_ip_int = convert_ip_to_integer(starting_ip)
        ending_ip_int = convert_ip_to_integer(ending_ip)
        ip_to_geo.append((starting_ip_int, ending_ip_int, county_code))
        line = geoip_file.readline().strip()
    geoip_file.close()

def load_rules():
    rule_file = open("rules.conf", "r")
    line = rule_file.readline()
    while line != "":
        if line[0] == "%":
            line = rule_file.readline()
            continue
        stripped_line = line.strip()
        if stripped_line:
            rules.append(stripped_line.upper().split())
        line = rule_file.readline()
    rules.reverse()
    rule_file.close()

def scanRules(protocol_type, ip, dns_packet = False, port = None, dns_server = None):
    # print protocol_type
    protocol_type = protocol_type.upper()
    ip = ip.upper()
    for rule in rules:
        if dns_packet and "DNS" == rule[1]:
            return_msg = handleDNS(dns_server, rule)
            if return_msg == "not-match":
                continue
            else:
                return return_msg
        if protocol_type == rule[1]:
            return_msg_ip = handleIP(ip, rule)
            return_msg_port = handlePort(port, rule)
            if return_msg_ip == "not-match" or return_msg_port == "not-match":
                continue
            else:
                return return_msg_ip and return_msg_port
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
        # print "rule_ip: ", rule_ip
        # print "prefix: ", prefix
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

def handlePort(port, rule):
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

def handleDNS(dns, rule):
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
def geoBinarySearch(IPList, IPaddress):
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
    
def convert_ip_to_integer(ip):
    (one, two, three, four) = ip.split(".")
    ip_integer = int(one) * 2 ** 24 + int(two) * 2 ** 16 + int(three) * 2 ** 8 + int(four)
    return ip_integer


load_geoipdb()
load_rules()

# rules = [
#     ['PASS', 'ICMP', 'ANY', '8'],
#     ['DROP', 'ICMP', 'ANY', '0-1'],
#     ['DROP', 'ICMP', '4.4.4.4', 'ANY'],
#     ['DROP', 'ICMP', '128.0.0.0/1', 'ANY'],
#     ['DROP', 'ICMP', '64.96.0.0/11', 'ANY'],
#     ['DROP', 'ICMP', 'CH', 'ANY']
# ]

# def ICMPtest():
#     print "Running ICMP tests..."
#     # define new rules here
#     # in reverse order, as a format of a list, all caps!
#     # please make sure the most bottom one in the rule.config goes to the
#     # most top in the list below
    
#     # ip field in rules can be in one of the format of 10.0.0.1, 10.0.0.0/8, "AU"
#     # make sure no bad prefixes, like 1.0.0.0/3
#     # types are from 0-11

#     assert scanRules("ICMP", "10.0.0.1", False, 8) == True
#     assert scanRules("ICMP", "10.0.0.1", False, 1) == False
#     assert scanRules("ICMP", "4.4.4.4", False, 8) == True
#     assert scanRules("ICMP", "4.4.4.4", False, 9) == False
#     assert scanRules("ICMP", "7.7.7.7", False, 10) == True #pass by default
#     assert scanRules("ICMP", "128.1.2.3", False, 8) == True
#     assert scanRules("ICMP", "128.1.2.3", False, 11) == False
#     assert scanRules("ICMP", "64.100.2.3", False, 11) == False
#     assert scanRules('ICMP', '5.1.103.254', False, 6) == False
    
#     print "All ICMP tests Passed!"

# # rules for TCP tests
# rules += [
#     ['PASS', 'TCP', 'ANY', '8'],
#     ['DROP', 'TCP', 'ANY', '0-1'],
#     ['DROP', 'TCP', '4.4.4.4', 'ANY'],
#     ['DROP', 'TCP', '128.0.0.0/1', 'ANY'],
#     ['DROP', 'TCP', '64.96.0.0/11', 'ANY'],
#     ['DROP', 'TCP', 'CH', 'ANY']
# ]

# def TCPtest():
#     print "Running TCP tests..."
#     assert scanRules("TCP", "10.0.0.1", False, 8) == True
#     assert scanRules("TCP", "10.0.0.1", False, 1) == False
#     assert scanRules("TCP", "4.4.4.4", False, 8) == True
#     assert scanRules("TCP", "4.4.4.4", False, 9) == False
#     assert scanRules("TCP", "7.7.7.7", False, 10) == True #pass by default
#     assert scanRules("TCP", "128.1.2.3", False, 8) == True
#     assert scanRules("TCP", "128.1.2.3", False, 11) == False
#     assert scanRules("TCP", "64.100.2.3", False, 11) == False
#     assert scanRules('TCP', '5.1.103.254', False, 6) == False
    
#     print "All TCP tests Passed!"

# # rules for UDP tests
# rules += [
#     ['PASS', 'UDP', 'ANY', '8'],
#     ['DROP', 'UDP', 'ANY', '0-1'],
#     ['DROP', 'UDP', '4.4.4.4', 'ANY'],
#     ['DROP', 'UDP', '128.0.0.0/1', 'ANY'],
#     ['DROP', 'UDP', '64.96.0.0/11', 'ANY'],
#     ['DROP', 'UDP', 'CH', 'ANY']
# ]

# def UDPtest():
#     print "Running UDP tests..."
#     assert scanRules("UDP", "10.0.0.1", False, 8) == True
#     assert scanRules("UDP", "10.0.0.1", False, 1) == False
#     assert scanRules("UDP", "4.4.4.4", False, 8) == True
#     assert scanRules("UDP", "4.4.4.4", False, 9) == False
#     assert scanRules("UDP", "7.7.7.7", False, 10) == True #pass by default
#     assert scanRules("UDP", "128.1.2.3", False, 8) == True
#     assert scanRules("UDP", "128.1.2.3", False, 11) == False
#     assert scanRules("UDP", "64.100.2.3", False, 11) == False
#     assert scanRules('UDP', '5.1.103.254', False, 6) == False
    
#     print "All UDP tests Passed!"



# # rules for DNS tests
# # just to make things clear:
# # if rule is GOOGLE.COM, then WWW.GOOGLE.COM does not match with this rule
# # WWW.GOOGLE.COM only matches with *.GOOGLE.COM
# # even though GOOGLE.COM redirects to WWW.GOOGLE.COM
# rules += [
#     ['PASS', 'DNS', '*.BERKELEY.EDU'],
#     ['DROP', 'DNS', '*.EDU'],
#     ['DROP', 'DNS', 'WWW.YOUTUBE.COM'],
    
    
#     ['DROP', 'UDP', 'ANY', '5'],
#     ['DROP', 'UDP', '22.22.22.22', 'ANY'],
#     ['DROP', 'UDP', 'JP', 'ANY']
# ]

# def DNStest():
#     print "Running DNS tests..."
#     assert scanRules("UDP", "10.0.0.1", True, 8, 'STANFORD.EDU') == True
#     assert scanRules("UDP", "10.0.0.3", True, 2, 'STANFORD.EDU') == False
#     assert scanRules("UDP", "10.0.0.3", True, 2, 'CS.BERKELEY.EDU') == True
#     assert scanRules("UDP", "10.0.0.3", True, 1, 'CS.BERKELEY.EDU') == False
#     assert scanRules("UDP", "10.0.0.3", True, 2, 'YOUTUBE.COM') == True
#     assert scanRules("UDP", "10.0.0.3", True, 2, 'WWW.YOUTUBE.COM') == False
    
#     assert scanRules("UDP", "123.123.123.123", True, 5, 'BING.COM') == False # Dropped by UDP
#     assert scanRules("UDP", "22.22.22.22", True, 6, 'BING.COM') == False # Dropped by UDP
#     assert scanRules("UDP", "1.1.100.23", True, 6, 'BING.COM') == False # Dropped by UDP
#     print "All DNS tests Passed!"

# ICMPtest()
# UDPtest()
# TCPtest()
# DNStest()