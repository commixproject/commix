	                                       __
	   ___    ___     ___ ___     ___ ___ /\_\   __  _
	  /'___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\
	 /\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
	 \ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\
	  \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ { v0.7b }

	+--
	Automated All-in-One OS Command Injection and Exploitation Tool
	Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst)
	+--

[![GPLv3 License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/stasinopoulos/commix/blob/master/readme/COPYING)
[![Twitter](https://img.shields.io/badge/Twitter-commixproject-blue.svg)](http://www.twitter.com/commixproject)

![Logo](http://i.imgur.com/xcNYrfv.png)

#### General Information

**Commix** (short for [**comm**]and [**i**]njection e[**x**]ploiter) has a simple environment and it can be used, from web developers, penetration testers or even security researchers to test web applications with the view to find bugs, errors or vulnerabilities related to **[command injection](https://www.owasp.org/index.php/Command_Injection)** attacks. By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or string. Commix is written in Python programming language.

#### Disclaimer

The tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes!

#### Requirements

**[Python](http://www.python.org/download/)** version **2.6.x** or **2.7.x** is required for running this program.

#### Installation

Download commix by cloning the Git repository:

    git clone https://github.com/stasinopoulos/commix.git commix

Commix comes packaged on the **official repositories** of the following Linux distributions, so you can use the **package manager** to install it!

- [ArchAssault](https://archassault.org/)
- [BlackArch](http://blackarch.org/)
- [Kali Linux](https://www.kali.org/)
- [Weakerthan](http://www.weaknetlabs.com/)

Commix also comes **pre-installed**, on the following penetration testing frameworks:

- [The Penetration Testers Framework (PTF)](https://github.com/trustedsec/ptf)
- [CTF-Tools](https://github.com/zardus/ctf-tools)
- [PentestBox](https://tools.pentestbox.com/)

#### Usage

To get a list of all options and switches use:

    python commix.py -h

Do you want to have a quick look of all available options and switches? Check the '**[usage](https://github.com/stasinopoulos/commix/wiki/Usage)**' wiki page.

#### Usage Examples

So, do you want to get some ideas on how to use commix? Just go and check the '**[usage examples](https://github.com/stasinopoulos/commix/wiki/Usage-Examples)**' wiki page, where there are several test cases and attack scenarios.

#### Upload Shells

Commix enables you to upload web-shells (e.g metasploit PHP meterpreter) easily on target host. For more, check the '**[upload shells](https://github.com/stasinopoulos/commix/wiki/Upload-shells)**' wiki page.

#### Modules Development

Do you want to increase the capabilities of the commix tool and/or to adapt it to our needs? You can easily develop and import our own modules. For more, check the '**[module development](https://github.com/stasinopoulos/commix/wiki/Module-Development)**' wiki page.

#### Command Injection Testbeds

Do you want to test or evaluate the exploitation abilities of commix? Cool! Check the '**[command injection testbeds](https://github.com/stasinopoulos/commix/wiki/Command-Injection-Testbeds)**' wiki page which includes a collection of pwnable web applications and/or VMs (that includes web applications) vulnerable to command injection attacks.

#### Exploitation Demos

If you want to see a collection of demos, about the exploitation abilities of commix, take a look at the '**[exploitation demos](https://github.com/stasinopoulos/commix/wiki/Exploitation-Demos)**' wiki page.

#### Bugs and Enhancements

For bug reports or enhancements, please open an issue **[here](https://github.com/stasinopoulos/commix/issues)**.

#### Supported Platforms

- Linux
- Mac OS X
- Windows (experimental)

#### Presentations and White Papers

For presentations and white papers published in conferences, check the '**[presentations](https://github.com/stasinopoulos/commix/wiki/Presentations)**' wiki page.

