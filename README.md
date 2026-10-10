<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

`English` • [`Ελληνικά`](doc/translations/README-gr-GR.md) • [`Español`](doc/translations/README-es-ES.md) • [`Français`](doc/translations/README-fr-FR.md) • [`فارسی`](doc/translations/README-fa-FA.md) • [`Bahasa Indonesia`](doc/translations/README-idn-IDN.md) • [`Türkçe`](doc/translations/README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://img.shields.io/github/actions/workflow/status/commixproject/commix/builds.yml?branch=master&label=Builds%20Tests&style=for-the-badge&logo=githubactions&logoColor=white"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/Python-3.7%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-6A1B9A.svg?style=for-the-badge&logo=gnu&logoColor=white"></a>
  <a href="https://x.com/commixproject"><img alt="Follow @commixproject" src="https://img.shields.io/badge/Follow-@commixproject-000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
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

* **Four injection techniques** - results-based, boolean-based, time-based and file-based, chosen with `--technique` or by the type they report with `--type` - see [techniques](https://github.com/commixproject/commix/wiki/Techniques) for what each one asks of a target.
* **Out-of-band, when nothing comes back at all** - `--oob` proves execution and carries the command's output over HTTP/S or DNS, reaching the server through whichever client the target happens to have - see [out-of-band client](https://github.com/commixproject/commix/wiki/Usage#out-of-band-client) for the ones it tries and how to pin one.
* **Code injection** - [`--eval`](https://github.com/commixproject/commix/wiki/Usage#test-for-code-injection) tests what a target evaluates as code, in `PHP`, `Python`, `Ruby`, `JavaScript` or `PowerShell`, over those same techniques.
* **Wherever input lands** - GET/POST parameters, [HTTP headers and cookies](https://github.com/commixproject/commix/wiki/Usage#request-options), JSON/XML/GraphQL bodies, plus the `shellshock` module for CGI targets.
* **From proof to shell** - [`--os-shell`](https://github.com/commixproject/commix/wiki/Getting-shells), built-in `reverse_tcp` and `bind_tcp` upgradeable to a full PTY, file transfer, Windows registry read/write, and enumeration through to password hashes with a dictionary attack offered against them.
* **Filter and WAF evasion** - combinable tamper scripts, applied in a deterministic order - see [filters bypass examples](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).
* **Targets in any shape** - a URL, a crawl, HTML forms, a sitemap, an OpenAPI (Swagger) description, a proxy log, a bulk file, a raw HTTP request, or piped `stdin` - see [target options](https://github.com/commixproject/commix/wiki/Usage#target-options).
* **Resumable and scriptable** - [per-target session files](https://github.com/commixproject/commix/wiki/Usage#resume-from-stored-session-data), JSON/CSV/HAR output, reusable option profiles, and `--proof`, which re-proves any finding with an experiment of its own.
* **Unix-like and Windows** - PHP, Python, Perl, Ruby, ASP.NET, JSP and CGI back ends - see [Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance) for how the payloads differ.

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

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/GET/classic.php?addr=127.0.0.1" --os-shell

Prove execution out-of-band, where the response carries nothing back :

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/POST/blind.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> The client is picked by what the target has, so a host stripped of the usual HTTP clients is still
> in reach - pin one with `--oob-transport` where its egress is already known. By default `--oob` uses
> the public `oast.fun` interactsh server, so interaction metadata for your target leaves your
> network; point `--oob-server` at a self-hosted instance to keep it in-house. For a detailed guide,
> refer to the
> [**`out-of-band-oob-channel`**](https://github.com/commixproject/commix/wiki/Techniques#out-of-band-oob-channel) wiki page.

Scan a list of targets unattended and write the results to a file :

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

To get an overview of commix available options, switches and/or basic ideas on how to use commix, check **[usage](https://github.com/commixproject/commix/wiki/Usage)**, **[usage examples](https://github.com/commixproject/commix/wiki/Usage-examples)** and **[filters bypasses](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)** wiki pages.

## Links

* User's manual: https://github.com/commixproject/commix/wiki
* Issues tracker: https://github.com/commixproject/commix/issues
