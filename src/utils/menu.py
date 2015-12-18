#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'doc/COPYING' for copying permission.
"""

import os
import sys

from optparse import OptionGroup
from optparse import OptionParser

from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
The commix's banner.
"""
def banner():
  print """                                       __           
   ___    ___     ___ ___     ___ ___ /\_\   __  _  
  /'___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\   
 /\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\\/>  </  
 \ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\\/\_/\\_\\
  \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ { """ + Style.BRIGHT + Fore.RED + settings.VERSION  + settings.COMMIT_ID + Style.RESET_ALL + """ }

+--
""" + Style.BRIGHT + settings.DESCRIPTION + Style.RESET_ALL + """
Copyright (c) """ + settings.YEAR + """ """ + settings.AUTHOR + """ (""" + settings.TWITTER + Style.RESET_ALL + """)
+--
"""

_ = os.path.normpath(sys.argv[0])

usage = "python %prog [options]"

parser = OptionParser(usage=usage)

# General options
general = OptionGroup(parser, Style.BRIGHT + "General" + Style.RESET_ALL, 
                        "These options relate to general matters. ")

general.add_option("--verbose",
                action="store_true",
                dest="verbose",
                default=False,
                help="Enable the verbose mode.")

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

# Target options
target = OptionGroup(parser, Style.BRIGHT + "Target" + Style.RESET_ALL, 
                     "This options has to be provided, to define the target URL. ")

target.add_option("--url",
                action="store",
                dest="url",
                help="Target URL.")
                
target.add_option("--url-reload",
                action="store_true",
                dest="url_reload",
                default=False,
                help="Reload target URL after command execution.")

# Request options
request = OptionGroup(parser,  Style.BRIGHT + "Request" + Style.RESET_ALL, 
                      "These options can be used to specify how to connect to the target URL.")

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
                default = settings.APPLICATION + "/" + settings.VERSION + settings.COMMIT_ID,
                help="HTTP User-Agent header.")

request.add_option("--random-agent",
                action="store_true",
                dest="random_agent",
                default = False,
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

request.add_option("--headers",
                action="store",
                dest="headers",
                help="Extra headers (e.g. 'Header1:Value1\\nHeader2:Value2').")

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
                help="HTTP authentication type (e.g. 'basic').")

request.add_option("--auth-cred",
                action="store",
                dest="auth_cred",
                help="HTTP Authentication credentials (e.g. 'admin:admin').")

# Enumeration options
enumeration = OptionGroup(parser, Style.BRIGHT + "Enumeration" + Style.RESET_ALL, 
                        "These options can be used to enumerate the target host.")

enumeration.add_option("--current-user", 
                action="store_true",
                dest="current_user",
                default = False,
                help="Retrieve current user name.")

enumeration.add_option("--hostname", 
                action="store_true",
                dest="hostname",
                default = False,
                help="Retrieve current hostname.")

enumeration.add_option("--is-root", 
                action="store_true",
                dest="is_root",
                default = False,
                help="Check if the current user have root privileges.")

enumeration.add_option("--is-admin", 
                action="store_true",
                dest="is_admin",
                default = False,
                help="Check if the current user have admin privileges.")

enumeration.add_option("--sys-info", 
                action="store_true",
                dest="sys_info",
                default = False,
                help="Retrieve system information.")

enumeration.add_option("--users", 
                action="store_true",
                dest="users",
                default = False,
                help="Retrieve system users.")

enumeration.add_option("--passwords", 
                action="store_true",
                dest="passwords",
                default = False,
                help="Retrieve system users password hashes.")

enumeration.add_option("--privileges", 
                action="store_true",
                dest="privileges",
                default = False,
                help="Retrieve system users privileges.")

# File access options
file_access = OptionGroup(parser, Style.BRIGHT + "File access" + Style.RESET_ALL, 
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
modules = OptionGroup(parser, Style.BRIGHT + "Modules" + Style.RESET_ALL, 
                        "These options can be used increase the detection and/or injection capabilities.")
modules.add_option("--icmp-exfil", 
                action="store",
                dest="ip_icmp_data",
                default = False,

                help="The 'icmp exfiltration' injection technique        (e.g. 'ip_src=192.168.178.1,ip_dst=192.168.178.3').")

modules.add_option("--shellshock", 
                action="store_true",
                dest="shellshock",
                default = False,
                help="The 'shellshock' injection technique.")

# Injection options
injection = OptionGroup(parser, Style.BRIGHT + "Injection" + Style.RESET_ALL, 
                        "These options can be used to specify which parameters to inject and to provide custom injection payloads.")

injection.add_option("--data", 
                action="store",
                dest="data",
                help="POST data to inject (use '" +settings.INJECT_TAG+ "' tag to specify the testable parameter).")

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

injection.add_option("--maxlen", 
                action="store",
                dest="maxlen",
                default=settings.MAXLEN,
                help="The length of the output on time-based technique (Default: " +str(settings.MAXLEN)+ " chars).")

injection.add_option("--delay", 
                action="store",
                dest="delay",
                help="Set Time-delay for time-based and file-based techniques (Default: " +str(settings.DELAY)+ " sec).")

injection.add_option("--tmp-path", 
                action="store",
                dest="tmp_path",
                default = False,
                help="Set remote absolute path of temporary files directory (Default: " + settings.TMP_PATH + ").")

injection.add_option("--root-dir", 
                action="store",
                dest="srv_root_dir",
                default = False,
                help="Set remote absolute path of web server's root directory (Default: " + settings.SRV_ROOT_DIR + ").")

injection.add_option("--alter-shell", 
                action="store",
                dest="alter_shell",
                help="Use an alternative os-shell (e.g. Python).")

injection.add_option("--os-cmd", 
                action="store",
                dest="os_cmd",
                default = False,
                help="Execute a single operating system command.")

injection.add_option("--base64", 
                action="store_true",
                dest="base64",
                default = False,
                help="Encode the operating system command to Base64 format.")

parser.add_option_group(general)
parser.add_option_group(target)
parser.add_option_group(request)
parser.add_option_group(enumeration)
parser.add_option_group(file_access)
parser.add_option_group(modules)
parser.add_option_group(injection)
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

"""
The available options.
"""
def shell_options():
      print """
  ---[ """ + Style.BRIGHT + Fore.BLUE + """Available options""" + Style.RESET_ALL + """ ]---     
  Type '""" + Style.BRIGHT + """?""" + Style.RESET_ALL + """' to get all the available options.
  Type '""" + Style.BRIGHT + """back""" + Style.RESET_ALL + """' to go back to the injection process.
  Type '""" + Style.BRIGHT + """quit""" + Style.RESET_ALL + """' (or use <Ctrl-C>) to quit commix.
  Type '""" + Style.BRIGHT + """os_shell""" + Style.RESET_ALL + """' to get into an operating system command shell.
  Type '""" + Style.BRIGHT + """reverse_tcp""" + Style.RESET_ALL + """' to get a reverse TCP connection.

  """
  
"""
The tab compliter.
"""
def tab_completer(text, state):
    shell_options = [option for option in settings.SHELL_OPTIONS if option.startswith(text)]
    try:
        return shell_options[state]
    except IndexError:
        return None

#eof
