#!/usr/bin/python3
#Log Analyzer for UFW.log files
import re

#define lists
date = []
ip = []
port = []
#read ufw.log to memory
f =	open('ufw.txt', 'r')

#loop through file for Date/Time, source IP(SRC),  and port scanned(DPT)
for i in f:
	f.readline()
#write output file(ufwLog+currdate)

#close ufw.log
f.close()
