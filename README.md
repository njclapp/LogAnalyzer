# LogAnalyzer.py
This script is used to pull a ufw.log file and analyze it to show frequent offender IP addresses and ports scanned.

## To Use:

1. use root crontab to run this program at midnight: 

    0 0 * * * cd /home/$USER/LogAnalyzer && python /home/$USER/LogAnalyzer/LogAnalyzer.py

(change $USER to your username)

2. crontab will run LogAnalyzer.py to pull useful data from UFW.txt and put it in output[date].txt, while also clearing ufw.log
