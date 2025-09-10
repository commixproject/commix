## Version 4.1 (TBA)
* Revised: Refactored User-Agent strings to be loaded from external files rather than being hardcoded.
* Revised: Improved handling of URL redirections and associated HTTP responses.
* Revised: Improved prompts when merging or applying server-set cookies.
* Added: New switch `--http1.0` to force all outgoing requests to use `HTTP/1.0` protocol.
* Revised: Enhanced validation of user-specified parameters by detecting and reporting those that are not part of any recognized testable source.
* Revised: Enhanced injection logic with better handling of custom injection marker (i.e. asterisk `*`) and improved tracking of tested parameters.
* Revised: Improved detection of custom injection marker (i.e. asterisk `*`) across HTTP input vectors (e.g., URL params, POST data, cookies, headers).
* Revised: Improved heuristics for processing custom HTTP headers to correctly handle injection markers (i.e. asterisk `*`).
* Revised: Enhanced target encoding detection with improved charset extraction and prioritization from HTTP headers and HTML meta tags.
* Added: Ability to verify target URL content stability by comparing responses across delayed requests.
* Revised: Improved session handler for enhanced stability and data integrity.
* Revised: Improved semiblind ("file-based") technique with filename customization prompt (random or user-defined).
* Fixed: Improved handling of non-ASCII characters in URL path and query components.
* Fixed: Improved handling of HTTP errors missing response codes during authentication.
* Fixed: Improved handling of `URLError` without HTTP response.
* Fixed: Minor bug fix for missing `.txt` files during setup/install.
* Revised: Minor code refactoring to enhance the authentication process with detailed HTTP traffic inspection.
* Fixed: Improved handling of terminal input to prevent encoding errors.
* Fixed: Minor bug-fix in parsing improperly padded `Base64` in Authorization headers.
* Revised: Minor code refactoring to enhance file I/O reliability.
* Revised: Minor code refactoring to ensure compliance with PEP 440 versioning standards.
* Revised: Improved key transformation for nested structures using bracket notation and dot syntax.
* Fixed: Minor bug-fix in parsing improperly escaped characters in JSON objects.
* Fixed: Minor bug-fix in parsing empty or invalid JSON object.
* Added: New tamper script "randomcase.py" that replaces each character in a user-supplied OS command with a random case.
* Revised: Minor code refactoring regarding multiple tamper scripts.
* Revised: Minor code refactoring regarding payloads for time-related techniques (i.e. "time-based", "tempfile-based").
* Revised: Improvement regarding tamper script "backticks.py" for supporting time-related techniques (i.e. "time-based", "tempfile-based").

## Version 4.0 (2024-12-20)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Minor bug-fix regarding tamper script "backticks.py"
* Revised: Improvements regarding shell options `reverse_tcp`, `bind_tcp`.
* Revised: Major code refactoring regarding session handler.
* Revised: Minor improvement regarding options `--prefix`, `--suffix`.
* Revised: Improvement regarding writing text to the stdout (console) stream.
* Fixed: Minor bug-fix regarding combining custom injection marker (i.e. asterisk `*`) with `-p` option.
* Revised: Improvement regarding specifying multiple injection points by appending custom injection marker (i.e. asterisk `*`).
* Fixed: Minor bug-fix regarding crawler (i.e. option `--crawl`).
* Updated: Six (third party) module has been updated (Python 3.12 support).
* Revised: Minor improvement regarding determining (passively) the target's underlying operating system.
* Revised: Minor improvement for enabling end-users to choose whether to skip or continue testing the remaining parameters, if one is found vulnerable.
* Revised: Minor improvements regarding semiblind (i.e. "file-based") technique.
* Fixed: Minor bug-fix regarding option `--output-dir`.
* Revised: Improvement regarding option `--skip` for excluding certain parameter(s) from testing.
* Revised: Improvement regarding specifying which parameter(s) to test (i.e. `-p` option).
* Revised: Improvement regarding processing / ignoring custom injection marker (i.e. asterisk `*`).
* Revised: Improvement regarding forcing usage of provided HTTP method (e.g. `PUT`).
* Revised: Improvement regarding parsing raw HTTP request from a file (i.e. `-r` option).
* Revised: Improvement regarding parsing JSON nested objects.
* Revised: Improvement regarding (basic) heuristic detection of WAF/IPS protection.
* Revised: Improvement regarding option `--ignore-code` for ignoring multiple (problematic) HTTP error codes.
* Added: New option `--abort-code` for aborting on (problematic) HTTP error code(s) (e.g. 401)
* Added: New option `--time-limit` for running with a time limit in seconds (e.g. 3600).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.9...v4.0)._

## Version 3.9 (2024-01-19)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Minor improvement regarding logging user-supplied command(s) (i.e. `--os-cmd` option) to a file.
* Revised: Improvement regarding parsing HTTP requests through Tor HTTP proxy (i.e. `--tor` switch).
* Added: New (hidden) option `--ignore-stdin` regarding ignoring STDIN input. (via @n00b-bot)
* Revised: Minor improvement regarding successfully completing the scanning process (i.e. in case that parameters with anti-CSRF tokens are omitted). (via @xerxoria)
* Revised: Minor improvement regarding Windows-based payloads for semiblind (i.e. "file-based") technique (i.e. command execution output).
* Revised: Minor improvement in semiblind (i.e. "file-based") technique, regarding defining the URL where the execution output of an injected payload is shown.
* Added: New switch `--ignore-proxy` to ignore the system default HTTP proxy.
* Revised: Minor improvement regarding parsing HTTP requests through HTTP proxy (i.e. `--proxy` option).
* Added: New switch `--smart` for conducting through tests only in case of positive heuristic(s).
* Added: Translation for [README.md](https://github.com/commixproject/commix/blob/master/doc/translations/README-tr-TR.md) in Turkish. (via @Kazgangap)
* Revised: Minor improvement regarding parsing SOAP/XML POST data.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.8...v3.9)._

## Version 3.8 (2023-08-14)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Minor improvement regarding parsing raw HTTP request from a file (i.e. `-r` option).
* Revised: Minor improvement regarding dynamic code evaluation technique (i.e. command execution output).
* Added: Translation for [README.md](https://github.com/commixproject/commix/blob/master/doc/translations/README-fa-FA.md) in Farsi(Persian) (via @verfosec)
* Fixed: Minor bug-fix regarding `--skip-empty` flag, for skipping the testing of the parameter(s) with empty value(s).
* Revised: Minor improvement regarding tamper script "uninitializedvariable.py", for adding randomly generated uninitialized bash variables between the characters of each command of the generated payloads.
* Revised: Minor improvement regarding skipping further tests involving target that an injection point has already been detected.
* Revised: Minor code refactoring regarding multiple tamper scripts (i.e. "backslashes.py", "dollaratsigns.py", "doublequotes.py", "singlequotes.py", "uninitializedvariable.py").
* Added: New tamper script "rev.py" that reverses (characterwise) the user-supplied operating system commands.
* Fixed: Minor bug-fix regarding checking for similarity in provided parameter(s) name(s) and value(s).
* Fixed: Minor bug-fix regarding forcing usage of SSL/HTTPS requests toward the target (i.e. `--force-ssl` flag).
* Fixed: Minor bug-fix regarding setting custom output directory path (i.e. `--output-dir` option).
* Added: Support for `Bearer` HTTP authentication type.
* Revised: Minor improvement regarding tamper script "xforwardedfor.py" (that appends a fake HTTP header `X-Forwarded-For`).
* Fixed: Minor bug-fix regarding not ignoring specified injection technique(s) when `--ignore-session` or `--flush-session` options are set.
* Replaced: The `--dependencies` option has been replaced with `--ignore-dependencies`, regarding ignoring all required third-party library dependencies.
* Added: New option `--alert` to run host OS command(s) when injection point is found.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.7...v3.8)._

## Version 3.7 (2023-02-17)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Added: Translation for [README.md](https://github.com/commixproject/commix/blob/master/doc/translations/README-idn-IDN.md) in Indonesian (via @galihap76)
* Revised: Improvements regarding parsing HTTP requests through HTTP proxy (i.e. `--proxy` option).
* Revised: Improvements regarding identifying injection marker (i.e. asterisk `*`) in provided parameter values (e.g. GET, POST or HTTP headers). 
* Added: New option ` --crawl-exclude` regarding setting regular expression for excluding pages from crawling (e.g. `logout`).
* Revised: Improvement regarding `--crawl` option, for skipping further tests involving target that an injection point has already been detected.
* Added: Support regarding combining `--crawl` option with scanning multiple targets given from piped-input (i.e. `stdin`).
* Revised: Minor improvement regarding adding PCRE `/e` modifier (i.e. dynamic code evaluation technique).
* Revised: Minor bug-fix regarding logging all HTTP traffic into a textual file (i.e. `-t` option).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.6...v3.7)._

## Version 3.6 (2022-11-18)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Improvements regarding dynamic code evaluation heuristic check.
* Revised: Minor improvement regarding session handler.
* Revised: Minor improvement regarding `--wizard` option.
* Added: New tamper script "printf2echo.py" that replaces the printf-based ASCII to Decimal `printf "%d" "'$char'"` with `echo -n $char | od -An -tuC | xargs`.
* Revised: Minor improvement regarding parsing HTTP requests through HTTP proxy (i.e. `--proxy` option).
* Revised: Minor improvement regarding handling HTTP Error 401 (Unauthorized).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.5...v3.6)._

## Version 3.5 (2022-07-03)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Improvements regarding Windows-based payloads for every supported technique.
* Revised: Improvement regarding alternative shell (i.e.`--alter-shell`) for generating Python 3x payloads.
* Removed: The depricated modules "ICMP exfiltration" and "DNS exfiltration" have been removed.
* Revised: Improvement regarding identifying injection marker (i.e. asterisk `*`) in provided options.
* Revised: Improvement regarding shellshock module.
* Added: Support regarding parsing target(s) from piped-input (i.e. `stdin`).
* Added: New option `--answers` to set user answers to asked questions during commix run.
* Added: Support regarding combining `--crawl` option with scanning multiple targets given in a textual file (i.e. via option `-m`).
* Added: Support for normalizing crawling results.
* Revised: Improvement regarding crawler.
* Revised: Minor bug-fix regarding `--file-upload` option.
* Revised: Minor improvement regarding identifying `Hex` and/or `Base64` encoded parameter(s) value(s).
* Added: New option `--no-logging` for disabling logging to a file.
* Revised: Minor improvement regarding redirect handler.
* Updated: Minor update regarding scanning multiple targets given in a textual file (i.e. via option `-m`).
* Added: Support for heuristic detection regarding command injections. 
* Revised: Ιmprovement regarding `--level` option, which not only adds more injection points (i.e. Cookies, HTTP headers) but also performs more tests for each injection point.
* Revised: Improvement regarding injecting into custom HTTP Header(s).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.4...v3.5)._

## Version 3.4 (2022-02-25)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Fixed: Bug-fix regarding forcing usage of provided HTTP method (e.g. `PUT`).
* Fixed: Bug-fix regarding parsing raw HTTP headers from a file (i.e. `-r` option).
* Fixed: Minor bug-fix regarding parsing JSON objects.
* Added: New option `--drop-set-cookie` for ignoring `Set-Cookie` HTTP header from response.
* Added: Support for checking for not declared cookie(s).
* Added: New (hidden) option `--smoke-test` that runs the basic smoke testing.
* Revised: Improvement regarding mechanism which nagging if used "dev" version is > 30 days old.
* Revised: Improvements regarding dynamic code evaluation heuristic check.
* Replaced: The `--encoding` option has been replaced with `--codec`.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.3...v3.4)._

## Version 3.3 (2021-09-13)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Fixed: Minor bug-fix regarding scanning multiple targets given in a textual file (i.e. via option `-m`).
* Removed: The "Regsvr32.exe application whitelisting bypass" attack vector has been removed.
* Updated: Minor update regarding web delivery script (i.e. Python meterpreter reverse TCP shell).
* Replaced: The `--backticks` switch has been replaced with "backticks.py" tamper script.
* Added: New tamper script "backticks.py" that uses backticks instead of `$()`, for commands substitution.
* Added: New option ( `--skip-heuristic`) for skipping dynamic code evaluation heuristic check.
* Added: Support for parsing custom wordlists regarding HTTP authentication (i.e. `Basic`, `Digest`) dictionary-based cracker.
* Revised: Improvements regarding dynamic code evaluation heuristic check.
* Fixed: Minor bug-fix regarding parsing SOAP/XML data via `--data` option.
* Revised: Minor improvement regarding parsing GraphQL JSON objects.
* Added: The .bat files command separator (i.e. [`%1a`](http://seclists.org/fulldisclosure/2016/Nov/67)) has been added.
* Added: New option `--method` to force usage of provided HTTP method (e.g. `PUT`).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.2...v3.3)._

## Version 3.2 (2021-04-12)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Added: New tamper script "slash2env.py" that replaces slashes (`/`) with environment variable value `${PATH%%u*}`.
* Revised: Minor improvement regarding session handler for supporting Python 3.4+.
* Revised: Minor improvement regarding `--web-root` option.
* Added: New tamper script "uninitializedvariable.py" that adds uninitialized bash variables between the characters of each command of the generated payloads.
* Revised: Improvement regarding decompressing `deflate`, `x-gzip` and `gzip` HTTP responses.
* Fixed: Bug-fix regarding several charset-related unhandled exceptions.
* Revised: Improvements regarding dynamic code evaluation heuristic check.
* Fixed: Bug-fix regarding HTTP authentication (i.e. `Basic`, `Digest`) dictionary-based cracker.
* Fixed: Bug-fix regarding logging all HTTP traffic into a textual file.
* Revised: Improvement regarding crawler.
* Fixed: Multiple bug-fixes regarding supporting Python 3.9.
* Revised: Improvement regarding mechanism which nagging if used version is > 30 days old.
* Fixed: Multiple bug-fixes regarding the shellshock module.
* Revised: Improvement regarding Python 3.4+ for using the `html.unescape()` function for converting HTML entities to plain-text representations.
* Updated: Minor update regarding smartphones to imitate, through HTTP User-Agent header.
* Fixed: Bug-fix regarding setting suitable HTTP header User-Agent, when combining `--random-agent` or `--mobile` switch with `-r` option.
* Fixed: Bug-fix regarding `Hex` encoding/decoding.
* Added: New option ( `--timeout`) for setting a number of seconds to wait before timeout connection (default 30).
* Revised: Increased default timeout to 30 seconds.
* Fixed: Bug-fix regarding Basic HTTP authentication.
* Fixed: Bug-fix regarding connection problems (via @fuero).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.1...v3.2)._

## Version 3.1 (2020-06-17)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Added: A script "setup.py" has been added (i.e. easier installation).
* Revised: Improvement regarding checking if the provided value has boundaries (e.g. `param=/value/`).
* Revised: Improvement regarding dynamic code evaluation technique's heuristic checks.
* Revised: Improvement regarding identifying the indicated web-page charset.
* Revised: Minor improvement regarding verbose mode (i.e. debug messages).
* Fixed: Bug-fix regarding Basic HTTP authentication.
* Revised: Minor improvement regarding redirection mechanism.
* Fixed: Bug-fix regarding defining custom injection marker (i.e. asterisk `*`) in nested JSON objects.
* Revised: Minor improvement regarding Flatten_json (third party) module.
* Revised: Minor improvement regarding parsing nested JSON objects.
* Added: New tamper script "doublequotes.py" that adds double-quotes (`""`) between the characters of the generated payloads.
* Fixed: Bug-fix regarding parsing raw HTTP headers from a file (i.e. `-r` option).
* Revised: Improvements regarding data in the detailed message about occurred unhandled exception.
* Revised: Minor bug-fixes and improvements regarding HTTP authentication dictionary-based cracker.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v3.0-20191111...v3.1)._

## Version 3.0 (2019-11-11)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Improvement regarding identifying the indicated web-page charset.
* Added: Support for Python 3.x
* Updated: Beautiful Soup (third party) module has been updated.
* Added: Six (third party) module has been added.
* Revised: Improvement regarding parsing nested JSON objects that contain boolean values.
* Replaced: The `--ignore-401` option has been replaced with `--ignore-code` option.
* Added: New option `--ignore-code` for ignoring (problematic) HTTP error code (e.g. 401).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.9-20190626...v3.0-20191111)._

## Version 2.9 (2019-06-26)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Fixed: Bug-fix regarding parsing hostname and port from URL.
* Revised: Improvement regarding automatically decoding `deflate` and `gzip` HTTP responses.
* Fixed: Bug-fix regarding parsing HTTP header values that contain multiple `":"`.
* Revised: Improvement regarding updating "Content-Length" HTTP header, in case it's provided by user (i.e. `-r`, `--header`, `--header` options).
* Revised: Improvement regarding parsing raw HTTP headers from a file (i.e. `-r` option).
* Revised: Improvement regarding parsing nested JSON objects.
* Added: Flatten_json (third party) module has been added.
* Revised: Bug-fixes and improvements regarding parsing JSON objects.
* Added: GPL Cooperation Commitment ([COMMITMENT.txt](https://github.com/commixproject/commix/blob/master/COMMITMENT.txt)) has been added.
* Updated: Minor update regarding HTTP authentication (i.e. `Basic`, `Digest`).
* Revised: Minor improvements regarding preventing false negative results, due to parameters tampering during the detection phase.
* Revised: Minor improvements regarding "reverse_tcp" and "bind_tcp" shell options.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.8-20190326...v2.9-20190626)._

## Version 2.8 (2019-03-26)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Updated: Minor update regarding accepting overly long result lines.
* Revised: Minor bug-fixes and improvements regarding `--file-upload` option.
* Revised: Minor bug-fixes and improvements regarding HTTP authentication dictionary-based cracker.
* Revised: Minor bug-fixes and improvements regarding HTTP authentication (i.e. `Basic`, `Digest`).
* Fixed: Minor bug-fix regarding ignoring HTTP Error 401 (Unauthorized) (for `--ignore-401` option).
* Added: Support for writing crawling results to a temporary file (for eventual further processing with other tools).
* Added: Support for Windows "Python" on "reverse_tcp" shell option.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.7-20181218...v2.8-20190326)._

## Version 2.7 (2018-12-18)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: The suffixes list has been shortly revised.
* Updated: With each commix run end users are obligated to agree with the "Legal disclaimer" prelude message.
* Fixed: Minor improvent regarding local HTTP server (for `--file-upload` option).
* Added: A list of extensions to exclude from crawling.
* Revised: Minor improvements regarding crawler.
* Revised: Minor update of redirection mechanism.
* Revised: Minor improvement regarding identifying the target web server.
* Revised: Minor improvement regarding identifying corrupted .pyc file(s).
* Added: New tamper script "dollaratsigns.py" that adds dollar-sign followed by an at-sign (`$@`) between the characters of the generated payloads.
* Fixed: Bug-fix regarding proxying SSL/TLS requests.
* Revised: Minor improvement regarding checking for potentially miswritten (illegal '=') short option.
* Revised: Minor improvement regarding checking for illegal (non-console) quote and comma characters.
* Revised: Minor improvement regarding merging of tamper script arguments.
* Revised: Minor improvement regarding ignoring the parameter(s) that carrying anti-CSRF token(s) in all scanning attempts.
* Updated: Beautiful Soup (third party) module has been updated.
* Added: New tamper script "xforwardedfor.py" that appends a fake HTTP header `X-Forwarded-For`.
* Fixed: Minor bug-fix regarding loading tamper scripts. 
* Revised: Minor improvement regarding `INJECT_HERE` tag (i.e. declaring injection position) to be case insensitive.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.6-20180921...v2.7-20181218)._

## Version 2.6 (2018-09-21)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Minor improvement in session handler regarding IPv6 targets.
* Added: New option `--list-tampers` for listing available tamper scripts.
* Revised: Minor improvement regarding resolving target hostname.
* Added: Support for "Ncat" on "reverse_tcp" and "bind_tcp" shell options.
* Added: Support for "Bash" (via `/dev/tcp`) on "reverse_tcp" shell option.
* Added: Support for "Netcat-Openbsd" (i.e. nc without -e) on "reverse_tcp" and "bind_tcp" shell options.
* Added: Support for "Socat" on "reverse_tcp" and "bind_tcp" shell options.
* Revised: Minor improvement regarding counting the total of HTTP(S) requests, for the identified injection point(s) during the detection phase.
* Fixed: Minor bug-fix regarding providing the target host's root directory.
* Added: New tamper script "sleep2timeout.py" that uses "timeout" function for time-based attacks.
* Added: New tamper script "sleep2usleep.py" that replaces `sleep` with `usleep` command in the time-related generated payloads.
* Replaced: The `--purge-output` option has been replaced with `--purge` option.
* Fixed: Minor bug-fix regarding performing injections through cookie parameters.
* Revised: Minor improvement regarding ignoring the Google Analytics cookie in all scanning attempts.
* Fixed: Minor bug-fix regarding "bind_tcp" shell option.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.5-20180713...v2.6-20180921)._

## Version 2.5 (2018-07-13)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions.
* Revised: Improvement regarding identifying the appropriate format parameters, in the provided POST data.
* Added: Support regarding recognition of generic "your ip has been blocked" messages.
* Added: Support regarding checking for potential browser verification protection mechanism.
* Added: Support regarding checking for potential CAPTCHA protection mechanism.
* Revised: The separators list, has been shortly revised.
* Revised: Minor improvement regarding the extracted HTTP response headers.
* Added: New tamper script "nested.py" that adds double quotes around of the generated payloads.
* Fixed: Minor bug-fix regarding performing injections through HTTP Headers (e.g. User-Agent, Referer, Host etc).
* Fixed: Major bug-fixes regarding testing time-related payloads (i.e. "time-based", "tempfile-based").
* Added: New tamper script "backslashes.py" that adds back slashes (`\`) between the characters of the generated payloads.
* Fixed: Minor bug-fix regarding unicode decode exception error due to invalid codec, during connection on target host.
* Revised: Improvement regarding combining tamper script "multiplespaces.py" with other space-related tamper script(s).
* Added: New tamper script "multiplespaces.py" that adds multiple spaces around OS commands.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.4-20180521...v2.5-20180713)._

## Version 2.4 (2018-05-21)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions. 
* Fixed: Minor bug-fix regarding ignoring invalid and/or empty tamper scripts. 
* Updated: Colorama (third party) module has been updated.
* Revised: Minor improvement regarding keeping the git folder 'clean' (via @g0tmi1k).
* Fixed: Minor bug-fix regarding loading multiple tamper scripts (during the exploitation phase). 
* Added: New tamper script "caret.py" that adds the caret symbol (`^`) between the characters of the generated payloads.
* Added: New tamper script "singlequotes.py" that adds single quotes (`'`) between the characters of the generated payloads.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.3-20180307...v2.4-20180521)._

## Version 2.3 (2018-03-07)
* Fixed: Multiple bug-fixes regarding several reported unhandled exceptions. 
* Revised: Minor improvement regarding testing the Host HTTP header.
* Added: Support for Host HTTP header command injections.
* Revised: Minor improvement regarding testing SOAP/XML POST data.
* Added: Support for automatically creating a Github issue with unhandled exception information.
* Revised: Improvement for masking sensitive data in the detailed message about occurred unhandled exception.
* Added: Support for returning detailed message about occurred unhandled exception.
* Revised: The `--charset` option has been revised to force the usage of custom charset in order to speed-up the data retrieval process (during time-related injections).
* Replaced: The `--charset` option has been replaced with `--encoding` option.
* Revised: Improvement regarding batch mode, for testing the payloads for both OS - if it's not able to identify the target OS.
* Added: Support for SOAP/XML POST data.
* Fixed: Bug-fix regarding the SSL implementation (via @TD4B). 
* Revised: Improvement regarding testing json-formated POST data with empty value(s).
* Revised: Minor improvement regarding verbose mode for removing the first and/or last line of the html content (in case there are/is empty).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.2-20171212...v2.3-20180307)._

## Version 2.2 (2017-12-12)
* Revised: Minor improvement in "updater", for supporting verbose mode.
* Fixed: Minor bug-fix regarding cookie-based command injections.
* Revised: Minor improvement regarding option `-p` for bypassing the dependence on value of `--level` (in case of user-defined HTTP headers).
* Revised: Minor improvement regarding option `-p` for testing user-defined HTTP headers.
* Added: New option `--failed-tries` for setting a number of failed injection tries, in semiblind (i.e. "file-based") technique.
* Revised: Minor improvement regarding session handler.
* Revised: Minor improvement regarding checking stored time-related payloads (i.e. "time-based", "tempfile-based").
* Revised: Minor improvement regarding Python version check (no more crashes on Python >= "3" and < "2.6").
* Revised: Minor improvement in "updater", for checking commit hash number.
* Added: New option `--skip` regarding excluding certain parameter(s) from testing.
* Added: New option `--skip-technique` regarding excluding certain injection technique(s) from testing.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.1-20171003...v2.2-20171212)._

## Version 2.1 (2017-10-03)
* Added: New option `--header` for providing a single extra HTTP header (e.g. `X-Forwarded-For: 127.0.0.1`).
* Added: New option `--check-internet` that checks internet connection before assessing the target.
* Fixed: Minor bug-fix regarding performing injections through HTTP Headers (i.e. Cookie, User-Agent, Referer).
* Revised: Minor improvement regarding checking stored payloads and enabling appropriate tamper scripts during the exploitation phase.
* Added: New tamper script "space2vtab.py" that replaces every space (`%20`) with vertical tab (`%0b`).
* Replaced: The tamper script "space2tab.py" has been replaced with "space2htab.py".
* Fixed: Minor bug-fix regarding checking for similarity in provided parameter name and value (GET, POST).
* Added: New option `--backticks` that uses backticks instead of `$()`, for commands substitution.
* Revised: Minor improvement in Netcat shells, for giving to the end-user the choice of using the `/bin` standard subdirectory.
* Added: New option `--disable-coloring` that disables console output coloring.
* Added: New option `--check-tor` that checks if Tor is used properly.
* Fixed: Minor improvement for fetching random HTTP User-Agent header in initial request, when `--random-agent` is used.
* Revised: Minor improvement regarding options `--purge-output` and `--wizard`, were added in the mandatory options list.
* Fixed: Major bug-fix regarding connection problem over HTTPS.
* Added: New option `--purge-output` to turn on safe removal of all content(s) from output directory.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v2.0-20170714...v2.1-20171003)._

## Version 2.0 (2017-07-14)
* Revised: Minor improvement for automatically increasing default `--time-sec` value when `--tor` used.
* Fixed: Minor improvement for not re-testing Tor SOCKS proxy settings (in case of multiple targets).
* Revised: Multiple minor eye-candy revisions have been performed.
* Fixed: Major improvement regarding not sending requests with GET HTTP mothod in case of POST HTTP method, in injection levels 2, 3.
* Updated: The `--sys-info` option has been enriched with distribution description and release information.  
* Revised: Minor improvement in dynamic code evaluation, regarding the users extraction payload. 
* Fixed: Minor fix regarding not raising the detection phase in the case of 4xx and/or 5xx HTTP error codes.
* Revised: Minor improvement regarding not re-performing requests in case of stored session.
* Revised: Minor improvement in time-related techinques for checking the reliability of the used payload (in case of a false positive result).
* Updated: Minor update in the list of the User-Agents (regarding the `--random-agent` option).
* Added: New option `--mobile` that imitates smartphone through HTTP User-Agent header.
* Added: New option `--retries` that retries request(s) when the connection timeouts.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.9-20170502...v2.0-20170714)._

## Version 1.9 (2017-05-02)
* Revised: Minor improvement in results-based techniques, for delaying the OS responses depending on the user-supplied time delay.
* Revised: The time-related payloads (i.e. "time-based", "tempfile-based"), have been shortly revised.
* Revised: Minor improvement in semiblind (i.e. "file-based") technique, for delaying the OS responses depending on the user-supplied time delay.
* Fixed: Minor improvement in semiblind (i.e. "file-based") technique, regarding the directory path that the output file is saved.
* Added: New option `--ignore-redirects` that ignoring redirection attempts.
* Added: New functionality for identifying and following URL redirections.
* Fixed: Minor improvement for adding `/` at the end of the user provided root dir (in case it does not exist).
* Revised: The semiblind (i.e. "file-based") payload for deleting files with execution output, has been shortly revised.
* Replaced: The `--root-dir` option has been replaced with `--web-root` option.
* Added: New option `--wizard` that shows a simple wizard interface for beginner users.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.8-20170315...v1.9-20170502)._

## Version 1.8 (2017-03-15)
* Added: New feauture for installing Unicorn tool (if not installed on host).
* Removed: The pre-installed version of Unicorn tool has been removed.
* Added: New feauture for checking and updating current version of Unicorn tool.
* Revised: The `--delay` option has been revised to delay between each HTTP request.
* Replaced: The `--delay` option has been replaced with `--time-sec` option.
* Fixed: Minor improvement regarding gnureadline module for better support on MacOS X hosts.
* Added: New option `--charset` that forces character encoding used for data retrieval.
* Added: New prefix (`'%26`) and suffix (`%26'`) have been added.
* Fixed: Removal of unnecessary command substitution in semiblind technique (i.e. "file-based").
* Updated: The Unicorn tool has been updated to version 2.4.2.
* Added: Support for the Regsvr32.exe Application Whitelisting Bypass technique.
* Fixed: Minor improvement for checking for established TCP connections.
* Fixed: Minor improvement for not reopening meterpreter sessions (in case of user abortion).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.7-20170203...v1.8-20170315)._

## Version 1.7 (2017-02-03)
* Fixed: Minor improvement regarding unverified SSL context(s).
* Added: New values ("URIPATH", "SRVPORT") have been added to "Set" option.
* Revised: Minor improvements regarding "reverse_tcp" and "bind_tcp" shell options.
* Fixed: Minor improvement for checking missing mandatory option(s).
* Fixed: Minor improvement regarding the file path of the null device.
* Fixed: Minor improvement regarding automated scan level increasing.
* Fixed: Improvement regarding skipping the testing of problematic URL(s) and proceeding with next ones (in case of scanning multiple targets). 
* Fixed: Improvement regarding printing current assessment state in case of user abortion. 
* Revised: Minor improvement for proceeding with semiblind technique (i.e. "file-based"), once the user provides the path of web server's root directory.
* Fixed: Minor fix regarding the lack of http/s to the user-defined URL(s).
* Added: New option `--skip-empty` for skipping the testing of the parameter(s) with empty value(s).
* Fixed: Improvement regarding testing the parameter(s) with empty value(s).
* Added: New CGI shellscript path `/cgi-bin/cgiCmdNotify` (vulnerable to shellshock) has been added.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.6-20161228...v1.7-20170203)._

## Version 1.6 (2016-12-28)
* Fixed: Improvement regarding json-formated POST data, where whitespace before (and/or after) the `":"` exists.
* Fixed: Minor fix regarding empty value(s) in provided parameter(s).
* Added: New option `--batch` that never asks for user input (using the default behaviour).
* Added: New option `-x` for parsing target(s) from remote sitemap(.xml) file.
* Added: New option `--offline` for working in offline mode.
* Fixed: Improvement regarding the IP address grabbing (in case of internet in-accessibility).
* Fixed: Improvement regarding HTTPS based websites, for which scanning fails.
* Added: New option `-r` for loading HTTP request from a file.
* Fixed: Improvement regarding the response time estimimation, in which the target URL was requested without its POST data.
* Added: New option `-m` for scanning multiple targets given in a textual file.
* Fixed: Minor fix regarding the newline display in dynamic code evaluation (i.e. "eval-based") and semiblind technique (i.e. "file-based").
* Revised: The dynamic code evaluation (i.e. "eval-based") payloads have been shortly revised.
* Added: The executed command and the execution results output has been added to log file.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.5-20161117...v1.6-20161228)._

## Version 1.5 (2016-11-17)
* Fixed: Minor improvement in the "ICMP exfiltration" module.
* Fixed: Minor improvement for choosing default value when pressing enter.
* Added: New tamper script "hexencode.py" that encodes the payload to `Hex` format.
* Fixed: Minor improvements in executed commands history.
* Added: New verbosity level (4) for printing the HTTP response page content.
* Added: New option `-t` for logging all HTTP traffic into a textual file.
* Added: New option `--msf-path` for specifying a path where metasploit is installed.
* Added: New verbosity level (3) for printing the HTTP response headers.
* Added: New verbosity level (2) for printing the performed HTTP requests headers.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.4-20161017...v1.5-20161117)._

## Version 1.4 (2016-10-17)
* Added: Support on crawler for checking target for the existence of 'sitemap.xml'.
* Revised: The payload for Ruby reverse-shell has been shortly revised.
* Added: Support for bind TCP shell (via "bind_tcp" option).
* Added: New option `--crawl` (1,2) for crawling of a given website, starting from the target url.
* Updated: The Unicorn tool has been updated to version 2.3.5.
* Added: The project's official URL has been added in the menu banner.
* Fixed: Minor improvements in tab completion.
* Fixed: Minor improvement in the function that checks for updates on start up.
* Fixed: Minor improvements in enumeration options (added failure messages).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.3-20160914...v1.4-20161017)._

## Version 1.3 (2016-09-14)
* Fixed: Minor improvements in "reverse_tcp" option.
* Added: Support for the metasploit "web_delivery" script.
* Added: Support for generating Python/PHP meterpreter reverse TCP payloads via metasploit.
* Fixed: Minor improvements for enumeration options (if `--url-reload` is used).
* Added: The ability for generating and injecting native x86 shellcode (Powershell).
* Added: New option `--skip-calc` that skips the mathematic calculation during the detection phase.
* Fixed: Minor improvement in Shellshock module for ignoring junk output on response.
* Fixed: Minor improvement in Shellshock module for finding RCE results on page's response.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.2-20160812...v1.3-20160914)._

## Version 1.2 (2016-08-12)
* Added: The ability for setting custom (PHP / Python) working directory.
* Fixed: License file minor inaccurancy issue has been fixed.
* Revised: The Windows-based payloads for every supported technique, had been shortly revised.
* Revised: The dynamic code evaluation technique (i.e. "eval-based") has been shortly revised.
* Added: New tamper script "space2tab.py" that replaces every space (`%20`) with horizontal tab (`%09`).
* Added: The ability for generating powershell attack vectors via TrustedSec's Magic Unicorn.
* Added: The ability for checking if there is a new version available.
* Added: The ability for target application extension recognition (i.e. PHP, ASP etc).
* Fixed: Minor improvement for finding the URL part (i.e. `scheme:[//host[:port]][/]path`).
* Fixed: Minor fix for conflicted shells (i.e. regular, alternative) from session file.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.1-20160714...v1.2-20160812)._

## Version 1.1 (2016-07-14)
* Added: The ".gitignore" file has been added.
* Added: Support for injections against ASP.NET applications.
* Added: Support for warning detection regarding `create_function()` function.
* Fixed: Minor improvent of the HTTP server for `--file-upload` option.
* Fixed: Minor fix for conflicted executed commands from session file in HTTP Headers.
* Added: The ability to store injection level into session files for current target. 
* Added: Support for automated enabling of an HTTP server for `--file-upload` option.
* Fixed: Minor fix for "Python-urllib" User-Agent exposure.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v1.0-20160614...v1.1-20160714)._

## Version 1.0 (2016-06-14)
* Revised: Time-related statistical analysis for recognition of unexpected time delays due to unstable requests.
* Added: A list of pages / scripts potentially vulnerable to shellshock.
* Added: The ability to check if the url is probable to contain script(s) vulnerable to shellshock.
* Revised: Multiple eye-candy revisions have been performed.
* Fixed: HTTPS requests fixation, if the `--proxy` option is enabled.
* Fixed: Multiple fixes regarding the shellshock module have been performed.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.9b-20160607...v1.0-20160614)._

## Version 0.9b (2016-06-07)
* Added: The ability to re-perform the injection request if it has failed.
* Fixed: The shell output in semiblind technique (i.e. "file-based") has been fixed not to concat new lines.
* Revised: The ability to execute multiple tamper scripts combined or the one after the other.
* Added: New tamper script "space2plus.py" that replaces every space (`%20`) with plus (`+`).
* Added: New state ("checking") and the color of that state has been setted.
* Replaced: The `--base64` option has been replaced with "base64encode.py" tamper script.
* Added: New tamper script "space2ifs.py" that replaces every space (`%20`) with `$IFS` (bash) variable.
* Added: New option `--tamper` that supports tamper injection scripts.
* Added: Support for verbosity levels (currently supported levels: 0,1).
* Fixed: Minor rearrangement of prefixes and separators has been implemented.
* Revised: The "time-based" (blind) technique for \*nix targets has been shortly revised.
* Revised: The source code has been revised to support `print_state_msg` (i.e. error, warning, success etc) functions.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.8b-20160506...v0.9b-20160607)._

## Version 0.8b (2016-05-06)
* Fixed: The `--file-read` option to ignore the carriage return (`\r`) character in a text file.
* Added: The ability to check for empty value(s) in the defined GET, POST, Cookie data and skip.
* Replaced: The `INJECT_HERE` tag has been replaced with the custom injection marker (i.e. asterisk `*`).
* Added: New option `--level` (1-3) that specifies level of tests to perform.
* Added: New option `-p` that specifies a comma-separated list of GET and POST parameter.
* Added: The ability to check every parameter in the provided cookie data.
* Added: The ability to check every GET parameter in the defined URL and/or every POST provided data.
* Added: New option `--all` that enables all supported enumeration options.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.7b-20160418...v0.8b-20160506)._

## Version 0.7b (2016-04-18)
* Fixed: HTTP proxy logs parser to accept GET HTTP requests.
* Fixed: HTTP proxy logs parser to recognise provided HTTP authentication credentials.
* Added: Support for verbose mode in HTTP authentication (i.e. `Basic`, `Digest`) dictionary-based cracker.
* Added: The ability to store valid (Digest) credentials into session files for current target.
* Added: Dictionary-based cracker for `Digest` HTTP authentication credentials.
* Added: Support for `Digest` HTTP authentication type.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.6b-20160401...v0.7b-20160418)._

## Version 0.6b (2016-04-01)
* Added: The ability to store valid (`Basic`) credentials into session files for current target.
* Added: New option `--ignore-401` that ignores HTTP Error 401 (Unauthorized) and continues tests without providing valid credentials.
* Added: Dictionary-based cracker for `Basic` HTTP authentication credentials.
* Added: Identifier for HTTP authentication type (currently only `Basic` type is supported).
* Added: New option `--skip-waf` that skips heuristic detection of WAF/IPS/IDS protection.
* Added: Support for verbose mode in the "DNS exfiltration" injection technique (module).
* Added: New option `--dns-server` that supports the "DNS exfiltration" injection technique (module).
* Added: New option `--dependencies` that checks (non-core) third party dependenices.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.5b-20160316...v0.6b-20160401)._

## Version 0.5b (2016-03-16)
* Fixed: The payload(s) for dynamic code evaluation (i.e. "eval-based"), if there is not any separator.
* Added: Support for verbose mode in the "ICMP exfiltration" injection technique (module). 
* Added: Check if the user-defined os name, is different than the one identified by heuristics.
* Added: New option `--os` that forces a user-defined os name.
* Added: Support for testing custom HTTP headers (via `--headers` parameter).

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.4.1b-20160226...v0.5b-20160316)._

## Version 0.4.1b (2016-02-26)
* Added: Support for storing and retrieving executed commands from session file.
* Added: New option `-s` for loading session from session file.
* Added: New option `--ignore-session` for ignoring results stored in session file.
* Added: New option `--flush-session` for flushing session files for current target.
* Added: Support to resume to the latest injection points from session file.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.4b-20160204...v0.4.1b-20160226)._

## Version 0.4b (2016-02-04)
* Added: Payload mutation if WAF/IPS/IDS protection is detected.
* Added: Check for existence of WAF/IPS/IDS protection (via error pages).
* Added: The "set" option in "reverse_tcp" which sets a context-specific variable to a value.
* Added: New option `--force-ssl` for forcing usage of SSL/HTTPS requests.

_Note: For more check the [detailed changeset](https://github.com/commixproject/commix/compare/v0.3b-20160115...v0.4b-20160204)._

## Version 0.3b (2016-01-15)
* Added: Time-related false-positive identification, which identifies unexpected time delays due to unstable requests.
* Added: New option `-l`, that parses target and data from HTTP proxy log file (i.e. Burp or WebScarab).
* Added: Check if Powershell is enabled in target host, if the applied option's payload is requiring the use of PowerShell.
* Added: New option `--ps-version`, that checks PowerShell's version number.
* Replaced: Some powershell-based payloads, have been replaced by new (more solid) ones, so to avoid "Microsoft-IIS" server's incompatibilities.
* Added: Support (in MacOSX platforms) for a tab completion in shell options.
* Added: Undocumented parameter `-InputFormat none` so to avoid "Microsoft-IIS" server's hang.
* Added: Ability for identification of "Microsoft-IIS" servers.
* Added: Statistical checks for time-related techniques (i.e. "time-based", "tempfile-based").
* Added: Support for Windows-based (cmd / powershell) payloads for every injection technique.

## Version 0.2b (2015-12-18)
* Added: Support for recalling previous commands.
* Added: Support (in Linux platforms) for tab completion in shell options.
* Added: Support for alternative (Python) os-shell in dynamic code evaluation technique (i.e. "eval-based").
* Added: Support for PHP/Python meterpreter on "reverse_tcp" shell option.
* Added: The "reverse_tcp" shell option.
* Added: The ability to check for default root directories (Apache/Nginx).
* Added: Support for removal of (txt) shell files in semiblind techniques (i.e. "file-based", "tempfile-based").
* Added: Support for JSON POST data.
* Added: The "enumeration" and "file-read" results to log file.
* Added: The ability to get the user's approval before re-{enumerate/file-read} target.
* Added: The ability to stop current injection technique and proceed on the next one(s).

## Version 0.1b (2015-09-20)
* Added: New eval-based payload for `str_replace()` filter bypass.
* Added: Check for (GET) RESTful URL format.
* Added: New option `--base64`, that encodes the OS command to `Base64` format. 
* Added: Support for regular `preg_replace()` injections via `/e` modifier.
* Added: Support for HTML Charset and HTTP "Server" response-header reconnaissance (on verbose mode).
* Replaced: Payloads for semiblind (i.e. "tempfile-based") technique, have been replaced by new (more solid) ones.
* Added: A "new-line" separator support, for blind (i.e. "time-based") and semiblind (i.e. "tempfile-based") techniques.
* Added: Support for Referer HTTP header command injections.
* Added: Support for User-Agent HTTP header command injections.
* Added: [CVE-2014-6278](https://nvd.nist.gov/vuln/detail/CVE-2014-6278) support for "shellshock" module.
* Added: Support for cookie-based command injections.
* Added: A generic false-positive prevention technique.
* Removed: The `Base64` detection option.
* Added: Support for the Tor network.
* Added: The "shellshock" [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/cve-2014-6271) injection technique (module).
* Added: Termcolor support for Windows (colorama).
* Added: File access options.
* Added: Enumeration options.
* Added: New option `--alter-shell` that supports an alternative option for os-shell (e.g. Python).
* Added: New option `--icmp-exfil` that supports the "ICMP exfiltration" injection technique (module).
* Added: The semiblind (i.e. "tempfile-based") technique.
* Added: The semiblind (i.e. "file-based") technique.
* Removed: The blind (i.e. “boolean-based”) technique.
* Added: More Options.

## Version 0.1a (2014-12-20)
* The initial release {aka the Birth!}.
