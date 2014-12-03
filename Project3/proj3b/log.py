httplog = open('http.log', 'a')
def logHTTP(request, response):
	request = request.split('\n')
	response = response.split('\n')
	# print request
	# print response
	request_line = request[0]
	response_line = response[0]
	host_name = "external ip addr of TCP connection"
	method = request_line.split()[0]
	path = request_line.split()[1]
	version = request_line.split()[2]
	status_cdoe = response_line.split()[1]
	object_size = "-1"
	for field in request:
		if field.split()[0] == "Host:":
			host_name = field.split()[1]
			break;
	for field in response:
		if field.split()[0] == "Content-Length:":
			object_size = field.split()[1]
			break;

	httplog.write(host_name + " " + method + " " + path + " " + version + " " + status_cdoe + " " + object_size)
	httplog.flush()

request = "GET / HTTP/1.1\nHost: google.com\nUser-Agent: Web-sniffer/1.0.46 (+http://web-sniffer.net/ Accept-Encoding: gzip\nAccept-Charset: ISO-8859-1,UTF-8;q=0.7,*;q=0.7 Cache-Control: no-cache\nAccept-Language: de,en;q=0.7,en-us;q=0.3\n"
response = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.google.com/\nContent-Type: text/html; charset=UTF-8\nDate: Mon, 18 Nov 2013 23:58:12 GMT\nExpires: Wed, 18 Dec 2013 23:58:12 GMT\nCache-Control: public, max-age=2 592000\nServer: gws\nContent-Length: 219\nX-XSS-Protection: 1; mode=block\nX-Frame-Options: SAMEORIGIN Alternate-Protocol: 80:quic\n"

logHTTP(request, response)
def getHostHeader(request):
	beginning_index = request.find("Host: ")
	if beginning_index == -1:
		return None
	beginning_index += 5
	end_index = request.find("\n", beginning_index)
	temp = request[beginning_index:end_index].split()
	if temp == []:
		return
	return temp[0]


rules = []
log_rules = []
def load_rules():
    rule_file = open("rules.conf", "r")
    line = rule_file.readline()
    while line != "":
        if line[0] == "%":
            line = rule_file.readline()
            continue
        stripped_line = line.strip()
        if stripped_line:
            if stripped_line.upper().split()[0] == "LOG":
                log_rules.append(stripped_line.upper().split())
            else:
                rules.append(stripped_line.upper().split())
        line = rule_file.readline()
    rules.reverse()
    log_rules.reverse()
    rule_file.close()