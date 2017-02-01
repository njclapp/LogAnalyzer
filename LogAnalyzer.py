#!/usr/bin/python3
#Log Analyzer for UFW.log files
import re

#loop through file for Date/Time, source IP(SRC),  and port scanned(DPT)
with open('ufw.txt', 'r') as f: #opens file as f and is used to loop through
	line = f.read()
	date = re.findall('\w\w\w\s\d\d\s\d\d:\d\d:\d\d', line, flags = 0)
	IP = re.findall('\d[^\192]{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line, flags = 0)
	DPT = re.findall('DPT=(\d{1,5})', line, flags = 0)

#close ufw.log
f.close()

#Write output file
f = open('output.txt', 'w')
i = 0
while date != '':
	try:
		f.write(date[i]+'\t'+IP[i]+'\t'+DPT[i]+'\n\n')
		i+=1
	except IndexError:
		print("Done.")
		break

f.close()
