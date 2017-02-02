#!/usr/bin/python3
#Log Analyzer for UFW.log files
import re
import datetime

#loop through file for Date/Time, source IP(SRC),  and port scanned(DPT)
with open('ufw.txt', 'r') as f: #opens file as f and is used to loop through file
	line = f.read()
	date = re.findall('\w\w\w\s{1,}\d{1,}\s\d\d:\d\d:\d\d', line, flags = 0)
	IP = re.findall('SRC=(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})', line, flags = 0)
	DPT = re.findall('DPT=(\d{1,5})', line, flags = 0)

#Write output file
filestring = 'output'+str(datetime.date.today().strftime("%Y%m%d"))+'.txt' #automatically includes current date in filename
formatting = "{0:15s}		{1:15}		{2:5}" #spaces out date, IP, and DPT to make the output look nice

f = open(filestring, 'w')
i=0

while date != '': #note: when i hits '', it causes an IndexError which is handled by the except
	try:
		f.write(formatting.format(date[i], IP[i], DPT[i])+'\n')
		i+=1
	except IndexError: #used to overwrite error message that appears when 'i' hits the end of the list and tries to find an index that does not exist
		print("Done.")
		break
f.close()
