	                                       __
	   ___    ___     ___ ___     ___ ___ /\_\   __  _ 
	  /'___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\
	 /\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
	 \ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\
	  \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ { v0.3b }

	+--
	Automated All-in-One OS Command Injection and Exploitation Tool
	Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst)
	+--
	
[![GPLv3 License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/stasinopoulos/commix/blob/master/readme/COPYING)
[![Twitter](https://img.shields.io/badge/Twitter-commixproject-blue.svg)](http://www.twitter.com/commixproject)

![Logo](http://i.imgur.com/xcNYrfv.png)

####General Information
Commix (short for [comm]and [i]njection e[x]ploiter) has a simple environment and it can be used, from web developers, penetration testers or even security researchers to test web applications with the view to find bugs, errors or vulnerabilities related to command injection attacks. By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or string. Commix is written in Python programming language.

####Disclaimer
The tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes!!

####Requirements
[Python](http://www.python.org/download/) version **2.6.x** or **2.7.x** is required for running this program.

####Installation
Download commix by cloning the Git repository:

    git clone https://github.com/stasinopoulos/commix.git commix

Commix comes packaged on the official repositories of the following Linux distributions, so you can use the package manager to install it!

- [ArchAssault](https://archassault.org/)
- [BlackArch](http://blackarch.org/)

Commix also comes pre-installed, on the following penetration testing frameworks:
- [The Penetration Testers Framework (PTF)](https://github.com/trustedsec/ptf)
- [PentestBox](https://tools.pentestbox.com/)
- [Weakerthan](http://www.weaknetlabs.com/)
- [CTF-Tools](https://github.com/zardus/ctf-tools)

####Usage
To get a list of all options and switches use:

    python commix.py -h

Do you want to have a quick look of all available options and switches? Check the '[usage](https://github.com/stasinopoulos/commix/wiki/Usage)' wiki page.

####Usage Examples
So, do you want to get some ideas on how to use commix? Just go and check the '[usage examples](https://github.com/stasinopoulos/commix/wiki/Usage-Examples)' wiki page, where there are several test cases and attack scenarios.

####Upload Shells
Commix enables you to upload web-shells (e.g metasploit PHP meterpreter) easily on target host. For more, check the '[upload shells](https://github.com/stasinopoulos/commix/wiki/Upload-shells)' wiki page.

####Modules Development
Do you want to increase the capabilities of the commix tool and/or to adapt it to our needs? You can easily develop and import our own modules. For more, check the '[module development](https://github.com/stasinopoulos/commix/wiki/Module-Development)' wiki page.

####Command Injection Testbeds
A collection of pwnable VMs, that includes web applications vulnerable to command injection attacks.
- [Damn Vulnerable Web App (DVWA) ](http://www.dvwa.co.uk/)
- [Xtreme Vulnerable Web Application (XVWA) ](https://github.com/s4n7h0/xvwa)
- [OWASP: Mutillidae](https://www.owasp.org/index.php/Category:OWASP_Mutillidae)
- [bWAPP: bee-box (v1.6)](http://www.itsecgames.com/)
- [Persistence](https://www.vulnhub.com/entry/persistence-1,103/)
- [Pentester Lab: Web For Pentester](https://www.vulnhub.com/entry/pentester-lab-web-for-pentester,71/)
- [Pentester Lab: CVE-2014-6271/Shellshock](https://www.vulnhub.com/entry/pentester-lab-cve-2014-6271-shellshock,104/)
- [Pentester Lab: Rack Cookies and Commands injection](https://pentesterlab.com/exercises/rack_cookies_and_commands_injection/)
- [Pentester Academy: Command Injection ISO: 1](https://www.vulnhub.com/entry/command-injection-iso-1,81/)
- [SpiderLabs: MCIR (ShelLOL)](https://github.com/SpiderLabs/MCIR/tree/master/shellol)
- [Kioptrix: Level 1.1 (#2)](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)
- [Kioptrix: 2014 (#5)](https://www.vulnhub.com/entry/kioptrix-2014-5,62/)
- [Acid Server: 1](https://www.vulnhub.com/entry/acid-server-1,125/)
- [Flick: 2](https://www.vulnhub.com/entry/flick-2,122/)
- [w3af-moth](https://github.com/andresriancho/w3af-moth/)
- [commix-testbed](https://github.com/stasinopoulos/commix-testbed)

####Exploitation Demos (Video)
A collection of video demos, about the exploitation abilities of commix.
- [Exploiting DVWA (1.0.8) command injection flaws.](https://www.youtube.com/watch?v=PT4uSTCxKJU)
- [Exploiting bWAPP command injection flaws (normal & blind).](https://www.youtube.com/watch?v=zqI8NcHfboo)
- [Exploiting 'Persistence' blind command injection flaw.](https://www.youtube.com/watch?v=aVTGqiyVz5o)
- [Exploiting shellshock command injection flaws.](https://www.youtube.com/watch?v=5NvopJsCj4w)
- [Upload a PHP shell (i.e. Metasploit PHP Meterpreter) on target host.](https://www.youtube.com/watch?v=MdzGY2ws2zY)
- [Upload a Weevely PHP web shell on target host.](https://www.youtube.com/watch?v=cy7AW6OQBmU)
- [Exploiting cookie-based command injection flaws.](https://www.youtube.com/watch?v=ae4DOS-3vm8)
- [Exploiting user-agent-based command injection flaws.](https://www.youtube.com/watch?v=g3hSFOFRJrc)
- [Exploiting referer-based command injection flaws.](https://www.youtube.com/watch?v=uMt9_jDaJUI)
- [Rack cookies and commands injection.](https://www.youtube.com/watch?v=Bq7xYRC2nI4) 

####Bugs and Enhancements
For bug reports or enhancements, please open an issue [here](https://github.com/stasinopoulos/commix/issues).

####Supported Platforms
- Linux
- Mac OS X
- Windows (experimental)

####Presentations and White Papers
For presentations and white papers published in conferences, check the '[Presentations](https://github.com/stasinopoulos/commix/wiki/Presentations)' wiki page.

