from parsing import *


rules = []
rules = [
	['PASS', 'ICMP', 'ANY', '8'],
	['DROP', 'ICMP', 'ANY', '1'],
    ['DROP', 'ICMP', '4.4.4.4', 'ANY'],
    ['DROP', 'ICMP', '128.0.0.0/1', 'ANY'] 
]
def autotest():
	print "Running ICMP tests..."
	# define new rules here
	# in reverse order, as a format of a list, all caps!
	# please make sure the most bottom one in the rule.config goes to the
	# most top in the list below
	
	# ip field in rules can be in one of the format of 10.0.0.1, 10.0.0.0/8, "AU"
	# make sure no bad prefixes, like 1.0.0.0/3
	# types are from 0-11

	print "Got : Expected"
	print scanRules("ICMP", "10.0.0.1", False, 8), ": True"
	print scanRules("ICMP", "10.0.0.1", False, 1), ": False"
	print scanRules("ICMP", "4.4.4.4", False, 8), ": True"
	print scanRules("ICMP", "4.4.4.4", False, 9), ": False"
	print scanRules("ICMP", "7.7.7.7", False, 10), ": True" #pass by default
	print scanRules("ICMP", "128.1.2.3", False, 8), ": True"
	print scanRules("ICMP", "128.1.2.3", False, 11), ": False"


autotest()