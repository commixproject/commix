	                                       __
	   ___    ___     ___ ___     ___ ___ /\_\   __  _ 
	  /'___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\
	 /\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
	 \ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\
	  \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ { v0.1b }

	+--
	Automated All-in-One OS Command Injection and Exploitation Tool
	Copyright (c) 2015 Anastasios Stasinopoulos (@ancst)
	+--

#General Information
Commix (short for [comm]and [i]njection e[x]ploiter) has a simple environment and it can be used, from web developers, penetration testers or even security researchers to test web applications with the view to find bugs, errors or vulnerabilities related to command injection attacks. By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or string. Commix is written in Python programming language.

#Disclaimer
The tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes!!

#Requirements
[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program.

#Installation

Download commix by cloning the Git repository:

    git clone https://github.com/stasinopoulos/commix.git commix

Commix comes packaged on the official repositories of the following Linux distributions, so you can use the package manager to install it!

- [ArchAssault](https://archassault.org/)
- [BlackArch](http://blackarch.org/)

#Usage
    Usage : python commix.py [options]

####Options
    -h, --help            Show help and exit.
    --verbose             Enable the verbose mode.
    --install             Install 'commix' to your system.
    --version             Show version number and exit.
    --update              Check for updates (apply if any) and exit.

####Target
    This options has to be provided, to define the target URL.

    --url=URL           Target URL
    --url-reload        Reload target URL after command execution.

####Request
    These options can be used, to specify how to connect to the target
    URL.

    --host=HOST         HTTP Host header.
    --referer=REFERER   HTTP Referer header.
    --user-agent=AGENT  HTTP User-Agent header.
    --cookie=COOKIE     HTTP Cookie header.
    --random-agent      Use a randomly selected HTTP User-Agent header.
    --headers=HEADERS   Extra headers (e.g. 'Header1:Value1\nHeader2:Value2').
    --proxy=PROXY       Use a HTTP proxy (e.g. '127.0.0.1:8080').
    --auth-url=AUTH_..  Login panel URL.
    --auth-data=AUTH..  Login parameters and data.
    --auth-type=AUTH..  HTTP authentication type (e.g. 'basic').
    --auth-cred=AUTH..  HTTP Authentication credentials (e.g. 'admin:admin').

####Enumeration
    These options can be used, to enumerate the target host.

    --current-user      Retrieve current user name.
    --hostname          Retrieve current hostname.
    --is-root           Check if the current user have root privs.
    --sys-info          Retrieve system information.
    --users             Retrieve system users.
    --passwords         Retrieve system users password hashes.
    --privileges        Retrieve system users privileges.

####File access
    These options can be used to access files on the target host.

    --file-read=FILE..  Read a file from the target host.
    --file-write=FIL..  Write to a file on the target host.
    --file-upload=FI..  Upload a file on the target host.
    --file-dest=FILE..  Host's absolute filepath to write and/or upload to.

####Modules:
    These options can be used increase the detection and/or injection
    capabilities.

    --icmp-exfil=IP_..  The ICMP exfiltration technique (e.g.
                        'ip_src=192.168.178.1,ip_dst=192.168.178.3').


####Injection
    These options can be used, to specify which parameters to inject and
    to provide custom injection payloads.

    --data=DATA         POST data to inject (use 'INJECT_HERE' tag to specify
                        the testable parameter).
    --suffix=SUFFIX     Injection payload suffix string.
    --prefix=PREFIX     Injection payload prefix string.
    --technique=TECH    Specify a certain injection technique : 'classic',
                        'eval-based', 'time-based' or 'file-based'.
    --maxlen=MAXLEN     The length of the output on time-based technique
                        (Default: 10000 chars).
    --delay=DELAY       Set Time-delay for time-based and file-based
                        techniques (Default: 1 sec).
    --base64            Use Base64 (enc)/(de)code trick to prevent false-
                        positive results.
    --tmp-path=TMP_P..  Set remote absolute path of temporary files directory.
    --root-dir=SRV_R..  Set remote absolute path of web server's root
                        directory (Default: /var/www/).
    --icmp-exfil=IP_..  Use the ICMP exfiltration technique (e.g.
                        'ip_src=192.168.178.1,ip_dst=192.168.178.3').
    --alter-shell=AL..  Use an alternative os-shell (e.g. Python).
    --os-cmd=OS_CMD     Execute a single operating system command.

####Usage Examples
So, do you want to get some ideas on how to use commix? Just go and check '[usage examples](https://github.com/stasinopoulos/commix/wiki/Usage-Examples)' wiki page, where there are several test cases / attack scenarios.

####Upload Shells
Commix enables you to upload web-shells (e.g metasploit PHP meterpreter) easily on target host. For more, check '[upload shells](https://github.com/stasinopoulos/commix/wiki/Upload-shells)' wiki page.

####Modules Development
Do you want to increase the capabilities of the commix tool and/or to adapt it to our needs? You can easily develop and import our own modules. For more, check '[module development](https://github.com/stasinopoulos/commix/wiki/Module-Development)' wiki page.

####Command Injection Testbeds
A collection of pwnable VMs, that includes web apps vulnerable to command injections.
- [Damn Vulnerable Web App] (http://www.dvwa.co.uk/)
- [OWASP: Mutillidae] (https://www.owasp.org/index.php/Category:OWASP_Mutillidae)
- [bWAPP: bee-box (v1.6)] (http://www.itsecgames.com/)
- [Persistence] (https://www.vulnhub.com/entry/persistence-1,103/)
- [Pentester Lab: Web For Pentester] (https://www.vulnhub.com/entry/pentester-lab-web-for-pentester,71/)
- [Pentester Academy: Command Injection ISO: 1] (https://www.vulnhub.com/entry/command-injection-iso-1,81/)
- [SpiderLabs: MCIR (ShelLOL)](https://github.com/SpiderLabs/MCIR/tree/master/shellol)
- [Kioptrix: Level 1.1 (#2)](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)
- [Kioptrix: 2014 (#5)](https://www.vulnhub.com/entry/kioptrix-2014-5,62/)
- [w3af-moth] (https://github.com/andresriancho/w3af-moth/)

####Exploitation Demos
- [Exploiting DVWA (1.0.8) command injection flaws.](https://www.youtube.com/watch?v=PT4uSTCxKJU)
- [Exploiting bWAPP command injection flaws (normal & blind).](https://www.youtube.com/watch?v=zqI8NcHfboo)
- [Exploiting 'Persistence' blind command injection flaw.](https://www.youtube.com/watch?v=aVTGqiyVz5o)
- [Upload a PHP shell (i.e. Metasploit PHP Meterpreter) on target host.](https://www.youtube.com/watch?v=MdzGY2ws2zY)
- [Upload a Weevely PHP web shell on target host.](https://www.youtube.com/watch?v=cy7AW6OQBmU)

####Bugs and Enhancements
For bug reports or enhancements, please open an issue [here](https://github.com/stasinopoulos/commix/issues).

####Supported Platforms
- Linux
- Mac OS X

[![][img]][txt]
[img]: https://cdn3.iconfinder.com/data/icons/peelicons-vol-1/50/Twitter-32.png (Follow @commixproject :))
[txt]: http://www.twitter.com/commixproject
