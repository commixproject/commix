<p align="center">
  <img alt="CommixProject" src="https://camo.githubusercontent.com/41258687d868cf76951a37f6be7961c4c862dfb3/687474703a2f2f692e696d6775722e636f6d2f6c4b6762336c712e706e67" height="142" />
  <p align="center">
    <a href="https://api.travis-ci.org/commixproject/commix"><img alt="Build Status" src="https://api.travis-ci.org/commixproject/commix.svg?branch=master"></a>
    <a href="https://github.com/commixproject/commix/releases/tag/v2.3-20180307"><img alt="Version 2.3" src="https://img.shields.io/badge/Version-2.3-green.svg"></a>
    <a href="http://www.python.org/download/"><img alt="Python 2.6-2.7" src="https://img.shields.io/badge/Python-2.6--2.7-yellow.svg"></a>
    <a href="https://github.com/commixproject/commix/blob/master/readme/COPYING"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-red.svg"></a>
    <a href="http://www.twitter.com/commixproject"><img alt="Twitter" src="https://img.shields.io/badge/Twitter-@commixproject-blue.svg"></a>
  </p>
</p>

## General Information

**Commix** (short for [**comm**]and [**i**]njection e[**x**]ploiter) is an automated tool written by **[Anastasios Stasinopoulos](https://github.com/stasinopoulos)** (**[@ancst](https://twitter.com/ancst)**) that can be used from web developers, penetration testers or even security researchers in order to test web-based applications with the view to find bugs, errors or vulnerabilities related to **[command injection](https://www.owasp.org/index.php/Command_Injection)** attacks. By using this tool, it is very easy to find and exploit a command injection vulnerability in a certain vulnerable parameter or HTTP header.

## Disclaimer

This tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes!

## Requirements

**[Python](http://www.python.org/download/)** version **2.6.x** or **2.7.x** is required for running this program.

## Installation

Download commix by cloning the Git repository:

    git clone https://github.com/commixproject/commix.git commix

Commix comes packaged on the **official repositories** of the following Linux distributions, so you can use the **package manager** to install it!

- [ArchStrike](https://archstrike.org/)
- [BlackArch Linux](http://blackarch.org/)
- [BackBox](https://backbox.org/)
- [Kali Linux](https://www.kali.org/)
- [Parrot Security OS](https://www.parrotsec.org/)
- [Weakerthan Linux](http://www.weaknetlabs.com/)

Commix also comes **as a plugin**, on the following penetration testing frameworks:

- [TrustedSec's Penetration Testers Framework (PTF)](https://github.com/trustedsec/ptf)
- [OWASP Offensive Web Testing Framework (OWTF)](https://github.com/owtf/owtf)
- [CTF-Tools](https://github.com/zardus/ctf-tools)
- [PentestBox](https://tools.pentestbox.com/)
- [PenBox](https://github.com/x3omdax/PenBox)
- [Katoolin](https://github.com/LionSec/katoolin)
- [Aptive's Penetration Testing tools](https://github.com/Aptive/penetration-testing-tools)
- [Homebrew Tap - Pen Test Tools ](https://github.com/sidaf/homebrew-pentest)

## Supported Platforms

- Linux
- Mac OS X
- Windows (experimental)

## Usage

To get a list of all options and switches use:

    python commix.py -h

**Q**: Where can I check all the available options and switches? 

**A**: Check the '**[usage](https://github.com/commixproject/commix/wiki/Usage)**' wiki page.

## Usage Examples

**Q**: Can I get some basic ideas on how to use commix? 

**A**: Just go and check the '**[usage examples](https://github.com/commixproject/commix/wiki/Usage-Examples)**' wiki page, where there are several test cases and attack scenarios.

## Upload Shells

**Q**: How easily can I upload web-shells on a target host via commix? 

**A**: Commix enables you to upload web-shells (e.g metasploit PHP meterpreter) easily on target host. For more, check the '**[upload shells](https://github.com/commixproject/commix/wiki/Upload-shells)**' wiki page.

## Modules Development

**Q**: Do you want to increase the capabilities of the commix tool and/or to adapt it to our needs?

**A**: You can easily develop and import our own modules. For more, check the '**[module development](https://github.com/commixproject/commix/wiki/Module-Development)**' wiki page.

## Command Injection Testbeds

**Q**: How can I test or evaluate the exploitation abilities of commix?

**A**: Check the '**[command injection testbeds](https://github.com/commixproject/commix/wiki/Command-Injection-Testbeds)**' wiki page which includes a collection of pwnable web applications and/or VMs (that include web applications) vulnerable to command injection attacks.

## Exploitation Demos

**Q**: Is there a place where I can check for demos of commix?

**A**: If you want to see a collection of demos, about the exploitation abilities of commix, take a look at the '**[exploitation demos](https://github.com/commixproject/commix/wiki/Exploitation-Demos)**' wiki page.

## Bugs and Enhancements

**Q**: I found a bug / I have to suggest a new feature! What can I do?

**A**: For bug reports or enhancements, please open an issue **[here](https://github.com/commixproject/commix/issues)**.

## Presentations and White Papers
**Q**: Is there a place where I can find presentations and/or white papers regarding commix?

**A**: For presentations and/or white papers published in conferences, check the '**[presentations](https://github.com/commixproject/commix/wiki/Presentations)**' wiki page.

## Support and Donations
**Q**: Except for tech stuff (bug reports or enhancements) is there any other way that I can support the development of commix?

**A**: Sure! Commix is the outcome of many hours of work and total personal dedication. Feel free to '**[donate](https://www.paypal.com/gr/webapps/mpp/send-money-online)**' via PayPal to `donations@commixproject.com` and instantly prove your feelings for it! :).