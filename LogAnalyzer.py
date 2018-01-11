#!/usr/bin/python3.5
#Log Analyzer for UFW.log files
import re
import datetime
import subprocess

#grep ufw.log for blocked IP addresses
w = open("ufw.txt","w")
subprocess.call(['grep BLOCK /var/log/ufw.log'], stdout=w, shell=True)
subprocess.call(['rm', '/var/log/ufw.log'])
subprocess.call(['mv', '/home/nate/LogAnalyzer/output*', '/home/nate/LogAnalyzer/reports/'])

#loop through file for Date/Time, source IP(SRC),  and port scanned(DPT)
with open('ufw.txt', 'r') as f: #opens file as f and is used to loop through file
	line = f.read()

	ftp = re.findall('DPT=21', line, flags = 0)
	ssh = re.findall('DPT=22', line, flags = 0)
	telnet = re.findall('DPT=23', line, flags = 0)
	dns = re.findall('DPT=53', line, flags = 0)
	http = re.findall('DPT=80', line, flags = 0)
	ntp = re.findall('DPT=123', line, flags = 0)
	l33t = re.findall('DPT=1337', line, flags = 0)

	date = re.findall('\w\w\w\s{1,}\d{1,}\s\d\d:\d\d:\d\d', line, flags = 0)
	IP = re.findall('SRC=(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})', line, flags = 0)
	DPT = re.findall('DPT=(\d{1,5})', line, flags = 0)

	other = len(date) - (len(ftp)+len(ssh)+len(telnet)+len(dns)+len(http)+len(ntp)+len(l33t))

#Write output file
yesterday = datetime.datetime.now() - datetime.timedelta(days=1) #since the cron is set for midnight, we have to subtract one day to make the log fit the date
filestring = 'output'+str(yesterday.strftime("%Y%m%d"))+'.txt' #automatically includes current date in filename
formatting = "{0:15s}		{1:15}		{2:5}" #spaces out date, IP, and DPT to make the output look nice

f = open(filestring, 'w')
i=0

f.write("FTP: "+ str(len(ftp)) + ' (' + str(float((len(ftp))/float(len(date))*100))[0:4] + '%)\n')
f.write("SSH: "+ str(len(ssh)) + ' (' + str(float((len(ssh))/float(len(date))*100))[0:4] + '%)\n')
f.write("Telnet: "+ str(len(telnet)) + ' (' + str(float((len(telnet))/float(len(date))*100))[0:4] + '%)\n')
f.write("DNS: "+ str(len(dns)) + ' (' + str(float((len(dns))/float(len(date))*100))[0:4] + '%)\n')
f.write("HTTP: "+ str(len(http)) + ' (' + str(float((len(http))/float(len(date))*100))[0:4] + '%)\n')
f.write("NTP: "+ str(len(ntp)) + ' (' + str(float((len(ntp))/float(len(date))*100))[0:4] + '%)\n')
f.write("l33t: "+ str(len(l33t)) + ' (' + str(float((len(l33t))/float(len(date))*100))[0:4] + '%)\n')
f.write("Other: "+ str(other) + ' (' + str(float(other)/float(len(date))*100)[0:4] + '%)\n')
f.write("Total: "+str(len(date)) + '\n\n')

while date != '': #note: when i hits '', it causes an IndexError which is handled by the except
	try:
		f.write(formatting.format(date[i], IP[i], DPT[i])+'\n')
		i+=1
	except IndexError: #used to overwrite error message that appears when 'i' hits the end of the list and tries to find an index that does not exist
		print("Done.")
		break
f.close()
