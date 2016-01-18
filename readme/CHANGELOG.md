## Version 0.3b [2015]
* Added: Time-relative false-positive identification, which identifies unexpected time delays due to unstable requests.
* Added: New option "-l", that parses target and data from HTTP proxy log file (i.e Burp or WebScarab).
* Added: Check if Powershell is enabled in target host, if the applied option's payload is requiring the use of PowerShell.
* Added: New option "--ps-version", that checks PowerShell's version number.
* Replaced: Some powershell-based payloads, have been replaced by new (more solid) ones, so to avoid "Microsoft-IIS" server's incompatibilities.
* Added: Support (in MacOSX platforms) for a tab completion in shell options.
* Added: Undocumented parameter "-InputFormat none" so to avoid "Microsoft-IIS" server's hang.
* Added: Ability for identification of "Microsoft-IIS" servers.
* Added: Statistical checks for time-related ("time-based"/"tempfile-based") techniques.
* Added: Support for Windows-based (cmd / powershell) payloads for every injection technique.

## Version 0.2b [2015]
* Added: Support for recalling previous commands.
* Added: Support (in Linux platforms) for tab completion in shell options.
* Added: Support for alternative (Python) os-shell in dynamic code evaluation ("eval-based") technique.
* Added: Support for PHP/Python meterpreter on "reverse_tcp" shell option.
* Added: The "reverse_tcp" shell option.
* Added: The ability to check for default root directories (Apache/Nginx).
* Added: Support for removal of (txt) shell files in semiblind ("file-based"/"tempfile-based") techniques.
* Added: Support for JSON POST data.
* Added: The "enumeration" and "file-read" results to log file.
* Added: The ability to get the user's approval before re-{enumerate/file-read} target.
* Added: The ability to stop current injection technique and proceed on the next one(s).

## Version 0.1b [2015]
* Added: New eval-based payload for "str_replace()" filter bypass.
* Added: Check for (GET) RESTful URL format.
* Added: New option "--base64", that encodes the OS command to Base64 format. 
* Added: Support for regular "preg_replace()" injections via "/e" modifier.
* Added: Support for HTML Charset and HTTP "Server" response-header reconnaissance (on verbose mode).
* Replaced: Payloads for "tempfile-based" (semiblind) technique, have been replaced by new (more solid) ones.
* Added: A "new-line" separator support, for "time-based" (blind) & "tempfile-based" (semiblind) techniques.
* Added: Support for referer-based command injections.
* Added: Support for user-agent-based command injections.
* Added: CVE-2014-6278 support for "shellshock" module.
* Added: Support for cookie-based command injections.
* Added: A generic false-positive prevention technique.
* Removed: The "Base64" detection option.
* Added: Support for the Tor network.
* Added: The "shellshock" (CVE-2014-6271) injection technique (module).
* Added: Termcolor support for Windows (colorama).
* Added: File access options.
* Added: Enumeration options.
* Added: An alternative option for os-shell (Python).
* Added: The "ICMP Exfiltration" injection technique (module). 
* Added: The "tempfile-based" (semiblind) technique.
* Added: The "file-based" (semiblind) technique.
* Removed: The "boolean-based" (blind) technique.
* Added: More Options.

## Version 0.1a [2014]
* The initial release {aka the Birth!}.
