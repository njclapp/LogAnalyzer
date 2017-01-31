#!/usr/bin/python3
#Log Analyzer for UFW.log files
import re

#loop through file for Date/Time, source IP(SRC),  and port scanned(DPT)
with open('ufw.txt', 'r') as f: #opens file as f and is used to loop through
	line = f.read()
	date = re.findall('\w\w\w\s\d\d\s\d\d:\d\d:\d\d', line, flags = 0)
	print(date)
	IP = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line, flags = 0)
	print(IP)
#write output file(ufwLog+currdate)

#elose ufw.log
f.close()
