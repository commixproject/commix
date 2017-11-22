#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys

from optparse import OptionGroup
from optparse import OptionParser

from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

# Use Colorama to make Termcolor work on Windows too :)
if settings.IS_WINDOWS:
  init()

"""
The commix's banner.
"""
def banner():
  print """                                      __           
   ___   ___     ___ ___     ___ ___ /\_\   __  _   
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  """ + Style.BRIGHT + Style.UNDERLINE + settings.VERSION + Style.RESET_ALL + """
/\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\\/>  </  
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\\/\_/\\_\\ """ + Fore.GREY + Style.UNDERLINE + settings.APPLICATION_URL + Style.RESET_ALL + """
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (""" + Fore.LIGHTRED_EX + settings.APPLICATION_TWITTER + Style.RESET_ALL + """)

+--
""" + Style.BRIGHT + settings.DESCRIPTION_FULL + Style.RESET_ALL + """
Copyright (c) """ + settings.YEAR + """ """ + settings.AUTHOR + Style.RESET_ALL + """ (""" + Fore.LIGHTRED_EX  + settings.AUTHOR_TWITTER + Style.RESET_ALL + """)
+--
"""

_ = os.path.normpath(sys.argv[0])

usage = "python %prog [option(s)]"

parser = OptionParser(usage=usage)

# General options
general = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "General" + Style.RESET_ALL, 
                        "These options relate to general matters. ")

general.add_option("-v",
                action="store",
                type="int",
                dest="verbose",
                help="Verbosity level (0-4, Default: 0).")

general.add_option("--install",
                action="store_true",
                dest="install",
                default=False,
                help="Install 'commix' to your system.")

general.add_option("--version",
                action="store_true",
                dest="version",
                help="Show version number and exit.")

general.add_option("--update", 
                action="store_true",
                dest="update",
                help="Check for updates (apply if any) and exit.")

general.add_option("--output-dir", 
                action="store",
                dest="output_dir",
                help="Set custom output directory path.")

general.add_option("-s", 
                action="store",
                dest="session_file",
                default=None,
                help="Load session from a stored (.sqlite) file.")

general.add_option("--flush-session",
                action="store_true",
                dest="flush_session",
                help="Flush session files for current target.")

general.add_option("--ignore-session", 
                action="store_true",
                dest="ignore_session",
                help="Ignore results stored in session file.")

general.add_option("-t",
                action="store",
                dest="traffic_file",
                default=None,
                help="Log all HTTP traffic into a textual file.")

general.add_option("--batch",
                action="store_true",
                dest="batch",
                default=False,
                help="Never ask for user input, use the default behaviour.")

general.add_option("--charset",
                action="store",
                dest="charset",
                default=None,
                help="Force character encoding used for data retrieval.")

general.add_option("--check-internet", 
                action="store_true",
                dest="check_internet",
                help="Check internet connection before assessing the target.")

# Target options
target = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Target" + Style.RESET_ALL, 
                     "This options has to be provided, to define the target URL. ")

target.add_option("-u","--url",
                action="store",
                dest="url",
                help="Target URL.")
                
target.add_option("--url-reload",
                action="store_true",
                dest="url_reload",
                default=False,
                help="Reload target URL after command execution.")

target.add_option("-l",
                dest="logfile",
                help="Parse target from HTTP proxy log file.")

target.add_option("-m",
                dest="bulkfile",
                help="Scan multiple targets given in a textual file.")

target.add_option("-r",
                dest="requestfile",
                help="Load HTTP request from a file.")

target.add_option("--crawl", 
                dest="crawldepth",
                type="int",
                help="Crawl the website starting from the target URL (1-2, Default: " + str(settings.DEFAULT_CRAWLDEPTH_LEVEL) + ").")

target.add_option("-x",
                dest="sitemap_url",
                help="Parse target(s) from remote sitemap(.xml) file.")

# Request options
request = OptionGroup(parser,  Style.BRIGHT + Style.UNDERLINE + "Request" + Style.RESET_ALL, 
                      "These options can be used to specify how to connect to the target URL.")


request.add_option("-d", "--data", 
                action="store",
                dest="data",
                default=False,
                help="Data string to be sent through POST.")

request.add_option("--host",
                action="store",
                dest="host",
                help="HTTP Host header.")

request.add_option("--referer",
                action="store",
                dest="referer",
                help="HTTP Referer header.")

request.add_option("--user-agent",
                action="store",
                dest="agent",
                default = settings.DEFAULT_USER_AGENT,
                help="HTTP User-Agent header.")

request.add_option("--random-agent",
                action="store_true",
                dest="random_agent",
                default=False,
                help="Use a randomly selected HTTP User-Agent header.")

request.add_option("--param-del",
                action="store",
                dest="pdel",
                help="Set character for splitting parameter values.")

request.add_option("--cookie",
                action="store",
                dest="cookie",
                help="HTTP Cookie header.")

request.add_option("--cookie-del",
                action="store",
                dest="cdel",
                help="Set character for splitting cookie values.")

request.add_option("-H","--header",
                action="store",
                dest="header",
                help="Extra header (e.g. 'X-Forwarded-For: 127.0.0.1').")

request.add_option("--headers",
                action="store",
                dest="headers",
                help="Extra headers (e.g. 'Accept-Language: fr\\nETag: 123').")

request.add_option("--proxy",
                action="store",
                dest="proxy",
                default=False,
                help="Use a HTTP proxy (e.g. '127.0.0.1:8080').")
                
request.add_option("--tor",
                action="store_true",
                dest="tor",
                default=False,
                help="Use the Tor network.")

request.add_option("--tor-port",
                action="store",
                dest="tor_port",
                default=False,
                help="Set Tor proxy port (Default: 8118).")

request.add_option("--tor-check",
                action="store_true",
                dest="tor_check",
                default=False,
                help="Check to see if Tor is used properly.")

request.add_option("--auth-url",
                action="store",
                dest="auth_url",
                help="Login panel URL.")

request.add_option("--auth-data",
                action="store",
                dest="auth_data",
                help="Login parameters and data.")

request.add_option("--auth-type",
                action="store",
                dest="auth_type",
                help="HTTP authentication type (e.g. 'Basic' or 'Digest').")

request.add_option("--auth-cred",
                action="store",
                dest="auth_cred",
                help="HTTP authentication credentials (e.g. 'admin:admin').")

request.add_option("--ignore-401",
                action="store_true",
                dest="ignore_401",
                default=False,
                help="Ignore HTTP error 401 (Unauthorized).")

request.add_option("--force-ssl",
                action="store_true",
                dest="force_ssl",
                default=False,
                help="Force usage of SSL/HTTPS.")

request.add_option("--ignore-redirects",
                action="store_true",
                dest="ignore_redirects",
                default=False,
                help="Ignore redirection attempts.")

request.add_option("--retries",
                action="store",
                dest="retries",
                default=False,
                type="int",
                help="Retries when the connection timeouts (Default: 3).")

# Enumeration options
enumeration = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Enumeration" + Style.RESET_ALL, 
                        "These options can be used to enumerate the target host.")

enumeration.add_option("--all", 
                action="store_true",
                dest="enum_all",
                default=False,
                help="Retrieve everything.")

enumeration.add_option("--current-user", 
                action="store_true",
                dest="current_user",
                default=False,
                help="Retrieve current user name.")

enumeration.add_option("--hostname", 
                action="store_true",
                dest="hostname",
                default=False,
                help="Retrieve current hostname.")

enumeration.add_option("--is-root", 
                action="store_true",
                dest="is_root",
                default=False,
                help="Check if the current user have root privileges.")

enumeration.add_option("--is-admin", 
                action="store_true",
                dest="is_admin",
                default=False,
                help="Check if the current user have admin privileges.")

enumeration.add_option("--sys-info", 
                action="store_true",
                dest="sys_info",
                default=False,
                help="Retrieve system information.")

enumeration.add_option("--users", 
                action="store_true",
                dest="users",
                default=False,
                help="Retrieve system users.")

enumeration.add_option("--passwords", 
                action="store_true",
                dest="passwords",
                default=False,
                help="Retrieve system users password hashes.")

enumeration.add_option("--privileges", 
                action="store_true",
                dest="privileges",
                default=False,
                help="Retrieve system users privileges.")

enumeration.add_option("--ps-version", 
                action="store_true",
                dest="ps_version",
                default=False,
                help="Retrieve PowerShell's version number.")

# File access options
file_access = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "File access" + Style.RESET_ALL, 
                        "These options can be used to access files on the target host.")

file_access.add_option("--file-read", 
                action="store",
                dest="file_read",
                help="Read a file from the target host.")

file_access.add_option("--file-write", 
                action="store",
                dest="file_write",
                help="Write to a file on the target host.")

file_access.add_option("--file-upload", 
                action="store",
                dest="file_upload",
                help="Upload a file on the target host.")

file_access.add_option("--file-dest", 
                action="store",
                dest="file_dest",
                help="Host's absolute filepath to write and/or upload to.")

# Modules options
modules = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Modules" + Style.RESET_ALL, 
                        "These options can be used increase the detection and/or injection capabilities.")
modules.add_option("--icmp-exfil", 
                action="store",
                dest="ip_icmp_data",
                default=False,
                help="The 'ICMP exfiltration' injection module.           (e.g. 'ip_src=192.168.178.1,ip_dst=192.168.178.3').")

modules.add_option("--dns-server", 
                action="store",
                dest="dns_server",
                default=False,
                help="The 'DNS exfiltration' injection module.        (Domain name used for DNS exfiltration attack).")

modules.add_option("--shellshock", 
                action="store_true",
                dest="shellshock",
                default=False,
                help="The 'shellshock' injection module.")

# Injection options
injection = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Injection" + Style.RESET_ALL, 
                        "These options can be used to specify which parameters to inject and to provide custom injection payloads.")

injection.add_option("-p", 
                action="store",
                dest="test_parameter",
                help="Testable parameter(s).")

injection.add_option("--skip", 
                action="store",
                dest="skip_parameter",
                help="Skip testing for given parameter(s).")

injection.add_option("--suffix", 
                action="store",
                dest="suffix",
                help="Injection payload suffix string.")

injection.add_option("--prefix", 
                action="store",
                dest="prefix",
                help="Injection payload prefix string.")

injection.add_option("--technique", 
                action="store",
                dest="tech",
                help="Specify injection technique(s) to use.")

injection.add_option("--skip-technique", 
                action="store",
                dest="skip_tech",
                help="Specify injection technique(s) to skip.")

injection.add_option("--maxlen", 
                action="store",
                dest="maxlen",
                default=settings.MAXLEN,
                help="Set the max length of output for time-related injection techniques (Default: " + str(settings.MAXLEN) + " chars).")

injection.add_option("--delay", 
                action="store",
                dest="delay",
                help="Seconds to delay between each HTTP request.")

injection.add_option("--time-sec", 
                action="store",
                dest="timesec",
                help="Seconds to delay the OS response (Default 1).")

injection.add_option("--tmp-path", 
                action="store",
                dest="tmp_path",
                default=False,
                help="Set the absolute path of web server's temp directory.")

injection.add_option("--web-root", 
                action="store",
                dest="web_root",
                default=False,
                help="Set the web server document root directory (e.g. '/var/www').")

injection.add_option("--alter-shell", 
                action="store",
                dest="alter_shell",
                default = "",
                help="Use an alternative os-shell (e.g. 'Python').")

injection.add_option("--os-cmd", 
                action="store",
                dest="os_cmd",
                default=False,
                help="Execute a single operating system command.")

injection.add_option("--os",
                action="store", 
                dest="os",
                default=False,
                help="Force back-end operating system (e.g. 'Windows' or 'Unix').")

injection.add_option("--tamper", 
                action="store",
                dest="tamper",
                default=False,
                help="Use given script(s) for tampering injection data.")

injection.add_option("--msf-path", 
                action="store",
                dest="msf_path",
                default=False,
                help="Set a local path where metasploit is installed.")

injection.add_option("--backticks", 
                action="store_true",
                dest="enable_backticks",
                default=False,
                help="Use backticks instead of \"$()\", for commands substitution.")

# Detection options
detection = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Detection" + Style.RESET_ALL, "These options can be "
                        "used to customize the detection phase.")

detection.add_option("--level", 
                dest="level", 
                type="int",
                default=1,
                help="Level of tests to perform (1-3, Default: " + str(settings.DEFAULT_INJECTION_LEVEL) + ").")

detection.add_option("--skip-calc", 
                action="store_true",
                dest="skip_calc",
                default=False,
                help="Skip the mathematic calculation during the detection phase.")

detection.add_option("--skip-empty", 
                action="store_true",
                dest="skip_empty",
                default=False,
                help="Skip testing the parameter(s) with empty value(s).")

detection.add_option("--failed-tries", 
                action="store",
                dest="failed_tries",
                default=20,
                help="Set a number of failed injection tries, in file-based technique.")

# Miscellaneous options
misc = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Miscellaneous" + Style.RESET_ALL)

misc.add_option("--dependencies", 
                action="store_true",
                dest="noncore_dependencies",
                default=False,
                help="Check for third-party (non-core) dependencies.")

misc.add_option("--purge-output", 
                action="store_true",
                dest="purge_output",
                default=False,
                help="Safely remove all content from output directory.")

misc.add_option("--skip-waf", 
                action="store_true",
                dest="skip_waf",
                default=False,
                help="Skip heuristic detection of WAF/IPS/IDS protection.")

misc.add_option("--mobile", 
                action="store_true",
                dest="mobile",
                default=False,
                help="Imitate smartphone through HTTP User-Agent header.")

misc.add_option("--offline", 
                action="store_true",
                dest="offline",
                default=False,
                help="Work in offline mode.")

misc.add_option("--wizard", 
                action="store_true",
                dest="wizard",
                default=False,
                help="Simple wizard interface for beginner users.")

misc.add_option("--disable-coloring",
                action="store_true",
                dest="disable_coloring",
                default=False,
                help="Disable console output coloring.")

parser.add_option_group(general)
parser.add_option_group(target)
parser.add_option_group(request)
parser.add_option_group(enumeration)
parser.add_option_group(file_access)
parser.add_option_group(modules)
parser.add_option_group(injection)
parser.add_option_group(detection)
parser.add_option_group(misc)

"""
Dirty hack from sqlmap [1], to display longer options without breaking into two lines.
[1] https://github.com/sqlmapproject/sqlmap/blob/fdc8e664dff305aca19acf143c7767b9a7626881/lib/parse/cmdline.py
"""
def _(self, *args):
    _ = parser.formatter._format_option_strings(*args)
    if len(_) > settings.MAX_OPTION_LENGTH:
        _ = ("%%.%ds.." % (settings.MAX_OPTION_LENGTH - parser.formatter.indent_increment)) % _
    return _

parser.formatter._format_option_strings = parser.formatter.format_option_strings
parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser, type(parser))

option = parser.get_option("-h")
option.help = option.help.capitalize().replace("Show this help message and exit", "Show help and exit.")
(options, args) = parser.parse_args()

# Checkall the banner
if not options.version:
    banner()

"""
The "os_shell" available options.
"""
def os_shell_options():
      print """
---[ """ + Style.BRIGHT + Fore.BLUE + """Available options""" + Style.RESET_ALL + """ ]---     
Type '""" + Style.BRIGHT + """?""" + Style.RESET_ALL + """' to get all the available options.
Type '""" + Style.BRIGHT + """back""" + Style.RESET_ALL + """' to move back from the current context.
Type '""" + Style.BRIGHT + """quit""" + Style.RESET_ALL + """' (or use <Ctrl-C>) to quit commix.
Type '""" + Style.BRIGHT + """reverse_tcp""" + Style.RESET_ALL + """' to get a reverse TCP connection.
Type '""" + Style.BRIGHT + """bind_tcp""" + Style.RESET_ALL + """' to set a bind TCP connection.
"""

"""
The "reverse_tcp" available options.
"""
def reverse_tcp_options():
      print """
---[ """ + Style.BRIGHT + Fore.BLUE + """Available options""" + Style.RESET_ALL + """ ]---     
Type '""" + Style.BRIGHT + """?""" + Style.RESET_ALL + """' to get all the available options.
Type '""" + Style.BRIGHT + """set""" + Style.RESET_ALL + """' to set a context-specific variable to a value.
Type '""" + Style.BRIGHT + """back""" + Style.RESET_ALL + """' to move back from the current context.
Type '""" + Style.BRIGHT + """quit""" + Style.RESET_ALL + """' (or use <Ctrl-C>) to quit commix.
Type '""" + Style.BRIGHT + """os_shell""" + Style.RESET_ALL + """' to get into an operating system command shell.
Type '""" + Style.BRIGHT + """bind_tcp""" + Style.RESET_ALL + """' to set a bind TCP connection.
"""

"""
The "bind_tcp" available options.
"""
def bind_tcp_options():
      print """
---[ """ + Style.BRIGHT + Fore.BLUE + """Available options""" + Style.RESET_ALL + """ ]---     
Type '""" + Style.BRIGHT + """?""" + Style.RESET_ALL + """' to get all the available options.
Type '""" + Style.BRIGHT + """set""" + Style.RESET_ALL + """' to set a context-specific variable to a value.
Type '""" + Style.BRIGHT + """back""" + Style.RESET_ALL + """' to move back from the current context.
Type '""" + Style.BRIGHT + """quit""" + Style.RESET_ALL + """' (or use <Ctrl-C>) to quit commix.
Type '""" + Style.BRIGHT + """os_shell""" + Style.RESET_ALL + """' to get into an operating system command shell.
Type '""" + Style.BRIGHT + """reverse_tcp""" + Style.RESET_ALL + """' to get a reverse TCP connection.
"""

"""
The available mobile user agents.
"""
def mobile_user_agents():

    print """---[ """ + Style.BRIGHT + Fore.BLUE + """Available Mobile HTTP User-Agent headers""" + Style.RESET_ALL + """ ]---     
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' for BlackBerry 9900 HTTP User-Agent header.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' for Samsung Galaxy S HTTP User-Agent header.
Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' for HP iPAQ 6365 HTTP User-Agent header.
Type '""" + Style.BRIGHT + """4""" + Style.RESET_ALL + """' for HTC Sensation HTTP User-Agent header.
Type '""" + Style.BRIGHT + """5""" + Style.RESET_ALL + """' for Apple iPhone 4s HTTP User-Agent header.
Type '""" + Style.BRIGHT + """6""" + Style.RESET_ALL + """' for Google Nexus 7 HTTP User-Agent header.
Type '""" + Style.BRIGHT + """7""" + Style.RESET_ALL + """' for Nokia N97 HTTP User-Agent header.
"""

    while True:
      question_msg = "Which mobile HTTP User-Agent header do you want to use? "
      sys.stdout.write(settings.print_question_msg(question_msg))
      mobile_user_agent = sys.stdin.readline().replace("\n","").lower()
      try:
        if int(mobile_user_agent) in range(0,len(settings.MOBILE_USER_AGENT_LIST)):
          return settings.MOBILE_USER_AGENT_LIST[int(mobile_user_agent)]
        elif mobile_user_agent.lower() == "q":
          raise SystemExit()
        else:
          err_msg = "'" + mobile_user_agent + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass
      except ValueError:
        err_msg = "'" + mobile_user_agent + "' is not a valid answer."  
        print settings.print_error_msg(err_msg)
        pass     

"""
The tab compliter (shell options).
"""
def tab_completer(text, state):
    set_options = [option.upper() for option in settings.SET_OPTIONS if option.startswith(text.upper())]
    shell_options = [option for option in settings.SHELL_OPTIONS if option.startswith(text.lower())]
    available_options = shell_options + set_options
    try:
      return available_options[state]
    except IndexError:
      return None

"""
Check if enumeration options are enabled.
"""
def enumeration_options():
  if options.hostname or \
     options.current_user or \
     options.is_root or \
     options.is_admin or \
     options.sys_info or \
     options.users or \
     options.privileges or \
     options.passwords or \
     options.ps_version :
    return True

"""
Check if file access options are enabled.
"""
def file_access_options():
  if options.file_write or \
     options.file_upload or\
     options.file_read:
    return True

#eof
