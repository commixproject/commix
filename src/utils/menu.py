#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
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

from src.utils import colors
from src.utils import settings


def banner():
  print """                                       __           
   ___    ___     ___ ___     ___ ___ /\_\   __  _  
  /'___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\   
 /\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\\/>  </  
 \ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\\/\_/\\_\\
  \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ { """ + colors.RED + settings.VERSION  + settings.COMMIT_ID + colors.RESET + """ }

+--
""" + colors.BOLD + settings.DESCRIPTION + colors.RESET + """
Copyright (c) """ + settings.YEAR + """ """ + settings.AUTHOR + """ (""" + settings.TWITTER + colors.RESET +""")
+--
"""


_ = os.path.normpath(sys.argv[0])

usage = "python %prog [options]"

parser = OptionParser(usage=usage)

parser.add_option("--verbose",
		action="store_true",
		dest="verbose",
		default=False,
                help="Enable the verbose mode.")

parser.add_option("--install",
		action="store_true",
		dest="install",
		default=False,
                help="Install 'commix' to your system.")

parser.add_option("--version",
		action="store_true",
		dest="version",
		help="Show version number and exit.")

parser.add_option("--update", 
		action="store_true",
		dest="update",
		help="Check for updates (apply if any) and exit.")

# Target options
target = OptionGroup(parser, colors.BOLD + "Target" + colors.RESET, 
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
request = OptionGroup(parser,  colors.BOLD + "Request" + colors.RESET, 
		      "These options can be used, to specify how to connect to the target URL.")

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
		default="Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
		help="HTTP User-Agent header.")

request.add_option("--cookie",
                action="store",
		dest="cookie",
                help="HTTP Cookie header.")

request.add_option("--headers",
                action="store",
		dest="headers",
                help="Extra headers (e.g. 'Header1:Value1\\nHeader2:Value2').")

request.add_option("--proxy",
		action="store",
		dest="proxy",
		default=False,
                help="Use a HTTP proxy (e.g. '127.0.0.1:8080').")

request.add_option("--auth-url",
                action="store",
		dest="auth_url",
		help="Login panel URL.")

request.add_option("--auth-data",
                action="store",
		dest="auth_data",
                help="Login parameters and data.")

request.add_option("--auth-cred",
                action="store",
		dest="auth_cred",
                help="HTTP Basic Authentication credentials (e.g. 'admin:admin').")

# Injection options
injection = OptionGroup(parser, colors.BOLD + "Injection" + colors.RESET, 
			"These options can be used, to specify which parameters to inject and to provide custom injection payloads.")

injection.add_option("--data", 
		action="store",
		dest="data",
		help="POST data to inject (use 'INJECT_HERE' tag).")

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
		help="Specify a certain injection technique : 'classic', 'eval-based', 'time-based' or 'file-based'.")

injection.add_option("--maxlen", 
		action="store",
		dest="maxlen",
		default="10000",
		help="The length of the output on time-based technique (Default: 10000 chars).")

injection.add_option("--delay", 
		action="store",
		dest="delay",
		help="Set Time-delay for time-based and file-based techniques (Default: 1 sec).")

injection.add_option("--base64", 
		action="store_true",
		dest="base64_trick",
		default = False,
		help="Use Base64 (enc)/(de)code trick to prevent false-positive results.")

injection.add_option("--tmp-path", 
		action="store",
		dest="tmp_path",
		default = False,
		help="Set remote absolute path of temporary files directory.")

injection.add_option("--icmp-exfil", 
		action="store",
		dest="ip_icmp_data",
		default = False,
		help="Use the ICMP exfiltration technique (e.g. 'ip_src=192.168.178.1,ip_dst=192.168.178.3').")

parser.add_option_group(target)
parser.add_option_group(request)
parser.add_option_group(injection)

# Dirty hack from SQLMAP, to display longer options without breaking into two lines.
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

#eof
