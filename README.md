<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

`English` • [`Ελληνικά`](doc/translations/README-gr-GR.md) • [`Español`](doc/translations/README-es-ES.md) • [`Français`](doc/translations/README-fr-FR.md) • [`فارسی`](doc/translations/README-fa-FA.md) • [`Bahasa Indonesia`](doc/translations/README-idn-IDN.md) • [`Türkçe`](doc/translations/README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://github.com/commixproject/commix/actions/workflows/builds.yml/badge.svg"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/python-3.7+-yellow.svg"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/license-GPLv3-red.svg"></a>
  <a href="https://x.com/commixproject"><img alt="X" src="https://img.shields.io/badge/x-@commixproject-blue.svg"></a>
</p>

**Commix** (short for [**comm**]and [**i**]njection e[**x**]ploiter) is an open source penetration testing tool, written by **[Anastasios Stasinopoulos](https://github.com/stasinopoulos)** (**[@ancst](https://x.com/ancst)**), that automates the detection and exploitation of **[command](https://owasp.org/www-community/attacks/Command_Injection)** (and **[code](https://owasp.org/www-community/attacks/Code_Injection)**) injection vulnerabilities.

![Screenshot](https://commixproject.com/images/background.png)

You can visit the [collection of screenshots](https://github.com/commixproject/commix/wiki/Screenshots) demonstrating some of the features on the wiki.

> [!IMPORTANT]
> **This project is in active development.** Expect breaking changes between revisions. Review the
> [changelog](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md) before updating.
>
> Commix is primarily built to be used as a standalone CLI tool, and it executes operating system
> commands on the targets it tests. **Running commix as a service may pose security risks.** 
>
> It is recommended to use it with caution, and only against systems you own or have explicit
> authorisation to test.

## Features

* **Four injection techniques** - classic (results-based), time-based (blind), file-based (semi-blind, with a tempfile-based variant for write-restricted targets), and out-of-band (OAST) over HTTP/S and DNS.
* **Code injection** - `--eval` tests the string a target evaluates as code, in PHP or Python, over the same four techniques.
* **Broad injection surface** - GET/POST parameters, HTTP headers, cookies, and JSON/XML request bodies, plus the `shellshock` module for CGI targets.
* **Interactive shells** - an `os_shell` on the target, built-in `reverse_tcp` and `bind_tcp` modes, and file `download`/`upload` over the established shell.
* **Enumeration and file access** - current user, hostname, privileges, system information, users and password hashes; read from and write to files on the target host.
* **Filter and WAF evasion** - Multiple combinable tamper scripts, applied in a deterministic order.
* **Flexible targeting** - a single URL, a crawl, HTML forms, a sitemap, a proxy log, a bulk file, a raw HTTP request file, or piped `stdin`.
* **Resumable scans** - results are stored per target in a session file, and can be exported to JSON.
* **Wide back-end support** - PHP, Python, Perl, Ruby, ASP.NET, JSP and CGI.

## Installation

You can download commix on any platform by cloning the official Git repository :

    $ git clone https://github.com/commixproject/commix.git commix

Alternatively, you can download the latest [tarball](https://github.com/commixproject/commix/tarball/master) or [zipball](https://github.com/commixproject/commix/zipball/master).

> [!NOTE]
> **[Python](https://www.python.org/downloads/)** (version **3.7** or later) is required for running
> commix. All other dependencies are bundled, so no additional installation step is needed.

## Usage

To get a list of all options and switches use:

    $ python3 commix.py -h

Test a single injectable parameter, then drop into a shell on the target :

    $ python3 commix.py --url="http://www.target.com/vuln.php?addr=127.0.0.1" --os-shell

Prove execution out-of-band, where the response carries nothing back :

    $ python3 commix.py --url="http://www.target.com/vuln.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> Out-of-band (OAST) detection with `--oob` uses the public `oast.fun` interactsh server by default,
> so interaction metadata for your target leaves your network. Point `--oob-server` at a self-hosted
> instance to keep it in-house. For a detailed guide, refer to the
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) wiki page.

Scan a list of targets unattended and write the results to a file :

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

To get an overview of commix available options, switches and/or basic ideas on how to use commix, check **[usage](https://github.com/commixproject/commix/wiki/Usage)**, **[usage examples](https://github.com/commixproject/commix/wiki/Usage-examples)** and **[filters bypasses](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)** wiki pages.

## Links

* User's manual: https://github.com/commixproject/commix/wiki
* Issues tracker: https://github.com/commixproject/commix/issues
