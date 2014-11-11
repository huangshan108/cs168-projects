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

def convert_ip_to_integer(ip):
    (one, two, three, four) = ip.split(".")
    ip_integer = int(one) * 2 ** 24 + int(two) * 2 ** 16 + int(three) * 2 ** 8 + int(four)
    return ip_integer

def geoBinarySearch(IPList, IPaddress):
    mid = len(IPList)/2
    if IPaddress >= IPList[mid][0] and IPaddress <= IPList[mid][1]:
        return IPList[mid][2]
    elif IPaddress < IPList[mid][0]:
        return geoBinarySearch(IPList[:mid], IPaddress)
    else:
        return geoBinarySearch(IPList[mid+1:], IPaddress)

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



load_geoipdb()
load_rules()