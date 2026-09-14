#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import glob
from src.utils import settings
from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP as SUPPRESS
from src.thirdparty.colorama import Fore, Style, init

# Use Colorama to make Termcolor work on Windows too :)
if settings.IS_WINDOWS:
  init()

"""
The commix's banner.
"""
def banner():
  settings.print_data_to_stdout(r"""                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  """ + settings.COLOR_VERSION + r"""
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ """ + Fore.GREY + Style.UNDERLINE + settings.APPLICATION_URL + Style.RESET_ALL + r"""
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (""" + Fore.LIGHTRED_EX + settings.APPLICATION_X_ACCOUNT + Style.RESET_ALL + """)

""" + Style.BRIGHT + settings.DESCRIPTION_FULL + Style.RESET_ALL + """
Copyright © """ + settings.YEAR + """ """ + settings.AUTHOR + Style.RESET_ALL + """ (""" + Fore.LIGHTRED_EX  + settings.AUTHOR_X_ACCOUNT + Style.RESET_ALL + """)
""")

_ = os.path.normpath(sys.argv[0])

usage = "python %prog [option(s)]"

parser = OptionParser(usage=usage)

# General options
general = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "General" + Style.RESET_ALL,
                        "These options relate to general matters. ")

general.add_option("-v",
                default=0,
                action="store",
                type="int",
                dest="verbose",
                help="Verbosity level (0-4, Default: 0).")

general.add_option("--install",
                action="store_true",
                dest="install",
                default=False,
                help="Install " + settings.APPLICATION + " to your system.")

general.add_option("--version",
                action="store_true",
                dest="version",
                default=False,
                help="Show version number and exit.")

general.add_option("--update",
                action="store_true",
                dest="update",
                default=False,
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
                default=False,
                help="Flush session files for current target.")

general.add_option("--ignore-session",
                action="store_true",
                dest="ignore_session",
                default=False,
                help="Ignore results stored in session file.")

general.add_option("-t",
                action="store",
                dest="traffic_file",
                default=None,
                help="Log all HTTP traffic into a textual file.")

general.add_option("--time-limit",
                dest="time_limit",
                type=float,
                help="Run with a time limit in seconds (e.g. 3600).")

general.add_option("--batch",
                action="store_true",
                dest="batch",
                default=False,
                help="Never ask for user input, use the default behaviour.")

general.add_option("--skip-heuristics",
                action="store_true",
                dest="skip_heuristics",
                default=False,
                help="Skip heuristic detection for code injection.")

general.add_option("--codec",
                action="store",
                dest="codec",
                default=None,
                help="Force codec for character encoding (e.g. 'ascii').")

general.add_option("--charset",
                action="store",
                dest="charset",
                default=None,
                help="Time-related injection charset (e.g. '0123456789abcdef').")

general.add_option("--check-internet",
                action="store_true",
                dest="check_internet",
                default=False,
                help="Check internet connection before assessing the target.")

general.add_option("--answers",
                dest="answers",
                help="Set predefined answers (e.g. 'quit=N,follow=N').")

general.add_option("--abort-on-empty",
                action="store_true",
                dest="abort_on_empty",
                default=False,
                help="Abort data retrieval on empty results.")

general.add_option("--report-json",
                action="store",
                dest="report_json",
                default=None,
                help="Store run results to a JSON file.")

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
                default=0,
                dest="crawldepth",
                type="int",
                help="Crawl the website starting from the target URL (Default: 1).")

target.add_option("--crawl-exclude",
                dest="crawl_exclude",
                default=None,
                help="Regexp to exclude pages from crawling (e.g. 'logout').")

target.add_option("--scope",
                dest="scope",
                default=None,
                help="Regexp to filter targets (e.g. '(www)?\\.target\\.(com|net|org)').")

target.add_option("--forms",
                dest="forms",
                action="store_true",
                default=False,
                help="Parse and test forms on target URL (requires '--crawl').")

target.add_option("-x",
                dest="sitemap_url",
                help="Parse target(s) from remote sitemap(.xml) file.")

target.add_option("--method",
                dest="method",
                help="Force usage of given HTTP method (e.g. 'PUT').")

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

request.add_option("--mobile",
                action="store_true",
                dest="mobile",
                default=False,
                help="Imitate smartphone through HTTP User-Agent header.")

request.add_option("--param-del",
                action="store",
                dest="pdel",
                help="Set character for splitting parameter values.")

request.add_option("--cookie",
                action="store",
                dest="cookie",
                help="HTTP Cookie header.")

request.add_option("--load-cookies",
                action="store",
                dest="load_cookies",
                help="File containing cookies in Netscape/wget format.")

request.add_option("--live-cookies",
                action="store",
                dest="live_cookies",
                help="Live cookies file used for loading up-to-date values.")

request.add_option("--cookie-del",
                action="store",
                dest="cdel",
                help="Set character for splitting cookie values.")

request.add_option("--http1.0",
                action="store_true", 
                dest="http10", 
                default=False,
                help="Force requests to use the HTTP/1.0 protocol.")

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
                help="Use a proxy to connect to the target URL.")

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
                help="HTTP authentication type (Basic, Digest, Bearer).")

request.add_option("--auth-cred",
                action="store",
                dest="auth_cred",
                help="HTTP authentication credentials (e.g. 'admin:admin').")

request.add_option("--abort-code",
                action="store",
                dest="abort_code",
                default=False,
                help="Abort on (problematic) HTTP error code(s) (e.g. 401).")

request.add_option("--ignore-code",
                action="store",
                dest="ignore_code",
                default=False,
                help="Ignore (problematic) HTTP error code(s) (e.g. 401).")

request.add_option("--force-ssl",
                action="store_true",
                dest="force_ssl",
                default=False,
                help="Force usage of SSL/HTTPS.")

request.add_option("--chunked",
                action="store_true",
                dest="chunked",
                default=False,
                help="Use HTTP chunked transfer encoded (POST) requests.")

request.add_option("--ignore-proxy",
                action="store_true",
                dest="ignore_proxy",
                default=False,
                help="Ignore system default proxy settings.")

request.add_option("--ignore-redirects",
                action="store_true",
                dest="ignore_redirects",
                default=False,
                help="Ignore redirection attempts.")

request.add_option("--timeout",
                action="store",
                dest="timeout",
                default=settings.TIMEOUT,
                type="int",
                help="Seconds to wait before timeout connection (Default: " + str(settings.TIMEOUT) + ").")

request.add_option("--retries",
                action="store",
                dest="retries",
                default=settings.MAX_RETRIES,
                type="int",
                help="Retries when the connection timeouts (Default: " + str(settings.MAX_RETRIES) + ").")

request.add_option("--delay",
                default=0,
                action="store",
                type="int",
                dest="delay",
                help="Seconds to delay between each HTTP request.")

request.add_option("--drop-set-cookie",
                action="store_true",
                dest="drop_set_cookie",
                default=False,
                help="Ignore Set-Cookie header from response.")

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

file_access.add_option("--file-dest",
                action="store",
                dest="file_dest",
                help="Host's absolute filepath to write to.")

# Modules options
modules = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Modules" + Style.RESET_ALL,
                        "These options can be used increase the detection and/or injection capabilities.")

modules.add_option("--shellshock",
                action="store_true",
                dest="shellshock",
                default=False,
                help="The 'shellshock' injection module.")

# Injection options
optimization = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Optimization" + Style.RESET_ALL,
                        "These options can be used to optimize the performance.")

optimization.add_option("-o",
                action="store_true",
                dest="optimize",
                default=False,
                help="Turn on all optimization switches.")

optimization.add_option("--no-keep-alive",
                action="store_true",
                dest="no_keep_alive",
                default=False,
                help="Disable persistent HTTP(s) connections (Keep-Alive).")

optimization.add_option("--threads",
                default=None,
                action="store",
                type="int",
                dest="threads",
                help="Max number of concurrent HTTP requests (default 1, max 10).")

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
                default="",
                dest="tech",
                help="Specify injection technique(s) to use.")

injection.add_option("--eval",
                action="store",
                default=None,
                dest="eval_sink",
                metavar="LANG",
                help="Test for code injection (e.g. 'php').")

injection.add_option("--skip-technique",
                action="store",
                dest="skip_tech",
                help="Specify injection technique(s) to skip.")

injection.add_option("--oob",
                action="store_true",
                dest="oob",
                default=False,
                help="Use an out-of-band (OAST) channel over HTTP(S).")

injection.add_option("--oob-server",
                action="store",
                dest="oob_server",
                help="Self-hosted interactsh server to use.")

injection.add_option("--oob-token",
                action="store",
                dest="oob_token",
                help="Auth token for the out-of-band server.")

injection.add_option("--oob-transport",
                action="store",
                dest="oob_transport",
                help="Client the target reaches the out-of-band server with (e.g. 'dns', 'curl').")

injection.add_option("--oob-scheme",
                action="store",
                dest="oob_scheme",
                help="Scheme the target reaches the out-of-band server on ('http' or 'https').")

injection.add_option("--oob-poll",
                action="store",
                dest="oob_poll",
                default=settings.OOB_POLL_INTERVAL,
                help="Seconds between out-of-band server polls (Default: " + str(settings.OOB_POLL_INTERVAL) + ").")

injection.add_option("--oob-timeout",
                action="store",
                dest="oob_timeout",
                default=settings.OOB_TIMEOUT,
                help="Seconds to wait for an interaction (Default: " + str(settings.OOB_TIMEOUT) + ").")

injection.add_option("--maxlen",
                action="store",
                dest="maxlen",
                default=settings.MAXLEN,
                help="Set the max length of output for time-related injection techniques (Default: " + str(settings.MAXLEN) + " chars).")

injection.add_option("--time-sec",
                default=0,
                action="store",
                type="float",
                dest="timesec",
                help="Seconds to delay the OS response.")

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

injection.add_option("--interpreter",
                action="store",
                dest="interpreter",
                default = "",
                help="Construct detection and exploitation payloads using an alternative interpreter (e.g. 'Python') instead of native OS shell syntax.")

injection.add_option("--os-cmd",
                action="store",
                dest="os_cmd",
                default=False,
                help="Execute a single operating system command.")

injection.add_option("--os-shell",
                action="store_true",
                dest="os_shell",
                default=False,
                help="Prompt for a command shell.")

injection.add_option("--os",
                action="store",
                dest="os",
                default=False,
                help="Force back-end operating system (e.g. 'Windows' or 'Unix-like').")

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

# Detection options
detection = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Detection" + Style.RESET_ALL, "These options can be "
                        "used to customize the detection phase.")

detection.add_option("--level",
                type="int",
                dest="level",
                default=False,
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
                type="int",
                dest="failed_tries",
                # Left unset, so the technique can count the boundaries it is actually going to
                # try. A fixed number here is a count of command separators, which says nothing
                # about how many combinations the sink in hand leaves to get through.
                default=None,
                help="Set a number of failed injection tries, in file-based technique.")

detection.add_option("--smart",
                action="store_true",
                dest="smart",
                default=False,
                help="Perform thorough tests only if positive heuristic(s).")

# Miscellaneous options
misc = OptionGroup(parser, Style.BRIGHT + Style.UNDERLINE + "Miscellaneous" + Style.RESET_ALL)

misc.add_option("--ignore-dependencies",
                action="store_true",
                dest="ignore_dependencies",
                default=False,
                help="Ignore all required third-party library dependencies.")

misc.add_option("--list-tampers",
                action="store_true",
                dest="list_tampers",
                default=False,
                help="Display list of available tamper scripts.")

misc.add_option("--alert",
                action="store",
                dest="alert",
                default=False,
                help="Run host OS command(s) when injection point is found.")

misc.add_option("--no-logging",
                action="store_true",
                dest="no_logging",
                default=False,
                help="Disable logging to a file.")

misc.add_option("--purge",
                action="store_true",
                dest="purge",
                default=False,
                help="Safely remove all content from commix data directory.")

misc.add_option("--skip-waf",
                action="store_true",
                dest="skip_waf",
                default=False,
                help="Skip heuristic detection of WAF/IPS protection.")

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

 # Hidden options
parser.add_option("--smoke-test",
                    action="store_true",
                    dest="smoke_test",
                    help=SUPPRESS)

parser.add_option("--ignore-stdin",
                    action="store_true",
                    dest="ignore_stdin",
                    default=False,
                    help=SUPPRESS)

parser.add_option_group(general)
parser.add_option_group(target)
parser.add_option_group(request)
parser.add_option_group(enumeration)
parser.add_option_group(file_access)
parser.add_option_group(modules)
parser.add_option_group(optimization)
parser.add_option_group(injection)
parser.add_option_group(detection)
parser.add_option_group(misc)

"""
Truncate long option strings so they don't wrap onto a second line.
"""
def _(self, *args):
    _ = parser.formatter._format_option_strings(*args)
    if len(_) > settings.MAX_OPTION_LENGTH:
        _ = ("%%.%ds.." % (settings.MAX_OPTION_LENGTH - parser.formatter.indent_increment)) % _
    return _

parser.formatter._format_option_strings = parser.formatter.format_option_strings
parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)

option = parser.get_option("-h")
option.help = option.help.capitalize().replace("Show this help message and exit", "Show help and exit.")
# Listed by its short form alone, the way every other switch is, while '--help' keeps working.
option._long_opts = []
# The language is optional: '--eval' on its own stands for every one that is supported, and the
# parser needs a value either way.
for _index, _argument in enumerate(sys.argv):
  if _argument == "--eval":
    sys.argv[_index] = "--eval=" + settings.EVAL_ALL_LANGUAGES

(options, args) = parser.parse_args()

# Remember whether '--web-root' was explicitly supplied on the CLI
settings.USER_APPLIED_WEB_ROOT = bool(options.web_root)

# Remember whether '--retries' was explicitly supplied, since it carries a default of its own
settings.USER_APPLIED_RETRIES = any(_ in sys.argv for _ in ("--retries",)) or any(_.startswith("--retries=") for _ in sys.argv)

# Remember whether '--auth-cred'/'--auth-type' were explicitly supplied on the CLI
settings.USER_APPLIED_COOKIE = options.cookie or ""
settings.USER_APPLIED_DATA = options.data or ""
settings.USER_APPLIED_AUTH_CRED = bool(options.auth_cred)
settings.USER_APPLIED_AUTH_TYPE = bool(options.auth_type)

# And the three a stored finding also carries, so resuming one can say when it disagrees
settings.USER_APPLIED_INTERPRETER = bool(options.interpreter)
settings.USER_APPLIED_TIMESEC = bool(options.timesec)
settings.USER_APPLIED_TMP_PATH = bool(options.tmp_path)

# Apply '--ignore-redirects' before the very first request is made
settings.FOLLOW_REDIRECT = not options.ignore_redirects

# Checkall the banner
if not options.version:
    banner()

# argv input errors
settings.sys_argv_errors()

COMMON_OPTIONS = (
    (("?",), "show this help"),
    (("back",), "return to the previous menu"),
    (("quit", "exit"), "exit Commix (<Ctrl-C> asks what to do instead)"),
)

OS_SHELL_OPTIONS = COMMON_OPTIONS + (
    (("<command>",), "execute it as an OS command on the target host"),
    (("download",), "download a file from the target host (download <remote> <local>)"),
    (("upload",), "upload a file to the target host (upload <local> <remote>)"),
    (("use reverse_tcp",), "Switch to the reverse TCP mode"),
    (("use bind_tcp",), "Switch to the bind TCP mode"),
)

REVERSE_TCP_OPTIONS = COMMON_OPTIONS + (
    (("set payload",), "Select a reverse TCP payload"),
    (("set",), "set a context option"),
    (("show options",), "show the current context options"),
    (("run",), "Generate and send the selected payload"),
    (("use os_shell",), "Switch to the (default) OS shell mode"),
    (("use bind_tcp",), "Switch to the bind TCP mode"),
)

BIND_TCP_OPTIONS = COMMON_OPTIONS + (
    (("set payload",), "Select a bind TCP payload"),
    (("set",), "set a context option"),
    (("show options",), "show the current context options"),
    (("run",), "Generate and send the selected payload"),
    (("use os_shell",), "Switch to the (default) OS shell mode"),
    (("use reverse_tcp",), "Switch to the reverse TCP mode"),
)


"""
Render a command reference table, msfconsole-style: a title/underline, then an
aligned "Command  Description" table.
"""
def _print_options(context, options):
    title = "Available Commands"

    rows = [
        (", ".join(commands), description[0].upper() + description[1:])
        for commands, description in options
    ]

    command_width = max(len("Command"), max(len(command) for command, _ in rows))

    message = (
        title + "\n"
        + "=" * len(title) + "\n\n"
        + "    " + "Command".ljust(command_width) + "   Description\n"
        + "    " + ("-" * len("Command")).ljust(command_width) + "   " + "-" * len("Description") + "\n"
    )

    for command, description in rows:
        message += (
            "    "
            + command.ljust(command_width)
            + "   " + description + "\n"
        )

    settings.print_data_to_stdout(message.rstrip() + "\n")

"""
Render a Name/Description table, msfconsole-style (like a "show" listing).
"""
def print_module_table(title, items):
    name_width = max(len("Name"), max(len(name) for name, _ in items))

    message = (
        title + "\n"
        + "=" * len(title) + "\n\n"
        + "    " + "Name".ljust(name_width) + "   Description\n"
        + "    " + ("-" * len("Name")).ljust(name_width) + "   " + "-" * len("Description") + "\n"
    )

    for name, description in items:
        message += (
            "    "
            + name.ljust(name_width)
            + "   " + description[0].upper() + description[1:] + "\n"
        )

    settings.print_data_to_stdout(message.rstrip() + "\n")

"""
Render a "show options"-style table: Name / Current Setting / Required / Description.
"""
def print_options_table(title, rows):
    name_width = max(len("Name"), max(len(name) for name, _, _, _ in rows))
    current_width = max(len("Current Setting"), max(len(current) for _, current, _, _ in rows))
    required_width = len("Required")

    # One row of the options table, laid out under its headings.
    def render_row(name, current, required, description):
        return (
            "    "
            + name.ljust(name_width) + "   "
            + current.ljust(current_width) + "   "
            + required.ljust(required_width) + "   "
            + description + "\n"
        )

    message = (
        title + "\n"
        + "=" * len(title) + "\n\n"
        + render_row("Name", "Current Setting", "Required", "Description")
        + render_row("-" * len("Name"), "-" * len("Current Setting"), "-" * len("Required"), "-" * len("Description"))
    )

    for name, current, required, description in rows:
        message += render_row(name, current if current else "", "yes" if required else "no", description)

    settings.print_data_to_stdout(message.rstrip() + "\n")


# The smartphones on offer, numbered for the answer that picks one.
def _print_mobile_user_agents(devices, default_index):
    message = ""
    for index, (device, _) in enumerate(devices):
        message += (
            "["
            + Style.BRIGHT
            + str(index + 1)
            + Style.RESET_ALL
            + "] "
            + device
            + (" (default)" if index == default_index else "")
            + "\n"
        )

    settings.print_data_to_stdout(message.rstrip())


# The options the 'os_shell' mode offers.
def os_shell_options():
    _print_options("os_shell", OS_SHELL_OPTIONS)


# The options the 'reverse_tcp' mode offers.
def reverse_tcp_options():
    _print_options("reverse_tcp", REVERSE_TCP_OPTIONS)


# The options the 'bind_tcp' mode offers.
def bind_tcp_options():
    _print_options("bind_tcp", BIND_TCP_OPTIONS)


# The smartphones on offer, for the User-Agent to imitate one.
def mobile_user_agents(devices, default_index):
    _print_mobile_user_agents(devices, default_index)

"""
The tab compliter (shell options).
"""
def tab_completer(text, state):
    try:
        import readline
        line = readline.get_line_buffer().lstrip().lower()
    except Exception:
        line = ""

    # Right after "set payload ", complete the currently-active shell's module paths
    # (accepts both the bare name and the "bind_tcp/"/"reverse_tcp/"-prefixed form).
    if line.startswith("set payload "):
        module_paths = []
        try:
            if settings.BIND_TCP:
                from src.core.shells.bind_tcp import BIND_TCP_MODULES
                module_paths = list(BIND_TCP_MODULES.keys())
            elif settings.REVERSE_TCP:
                from src.core.shells.reverse_tcp import REVERSE_TCP_MODULES
                module_paths = list(REVERSE_TCP_MODULES.keys())
        except Exception:
            module_paths = []

        prefix, bare_text = "", text
        for mode_prefix in ("bind_tcp/", "reverse_tcp/"):
            if text.startswith(mode_prefix):
                prefix, bare_text = mode_prefix, text[len(mode_prefix):]
                break

        available_options = [prefix + path for path in module_paths if path.startswith(bare_text)]

    # Right after "set ", the option names make sense, plus "payload" - not the full command list.
    elif line.startswith("set "):
        available_options = [option.upper() for option in settings.SET_OPTIONS if option.upper().startswith(text.upper())]
        if "payload".startswith(text.lower()):
            available_options.append("payload")

    # Only one side of a transfer is local: the source of "upload", the destination of "download".
    elif line.startswith("upload ") or line.startswith("download "):
        local_arg = 1 if line.startswith("upload ") else 2
        available_options = []
        if len(line.split(" ")) - 1 == local_arg:
            available_options = [path + ("/" if os.path.isdir(path) else "") for path in glob.glob(text + "*")]

    # Right after "use ", complete "os_shell"/"bind_tcp"/"reverse_tcp".
    elif line.startswith("use "):
        use_targets = ["os_shell", "bind_tcp", "reverse_tcp"]
        available_options = [target for target in use_targets if target.startswith(text.lower())]

    else:
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
  if any((options.hostname, options.current_user, options.is_root, options.is_admin, options.sys_info, options.users, options.privileges, options.passwords, options.ps_version)):
    return True

"""
Check if file access options are enabled.
"""
def file_access_options():
  if any(v is not None for v in (options.file_write, options.file_read)):
    return True

# eof
