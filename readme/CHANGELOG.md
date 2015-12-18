## Version 0.3b [2015]
* Added: Support for Windows-based (cmd / powershell) payloads for every injection technique.

## Version 0.2b [2015]
* Added: Support for recalling previous commands.
* Added: Support for a tab completion in shell options.
* Added: Support for alternative (Python) os-shell in dynamic code evaluation (aka eval-based) technique.
* Added: Support for PHP/Python meterpreter on "reverse_tcp" shell option.
* Added: The "reverse_tcp" shell option.
* Added: The ability to check for default root directories (Apache/Nginx).
* Added: Support for removal of (txt) shell files (File-based/Tempfile-based).
* Added: Support for JSON POST data.
* Added: The "enumeration" and "file-read" results to log file.
* Added: The ability to get the user's approval before re-{enumerate/file-read} target.
* Added: The ability to stop current injection technique and proceed on the next one(s).

## Version 0.1b [2015]
* Added: New eval-based payload (str_replace filter bypass).
* Added: Check for (GET) RESTful URL format.
* Added: New option "--base64", that encodes the OS command to Base64 format. 
* Added: Support for regular preg_replace() injections via "/e" modifier.
* Added: Support for HTML Charset and HTTP "Server" response-header reconnaissance (on verbose mode).
* Replaced: Payloads on "tempfile-based" (semiblind) technique, have been replaced by new (more solid) ones.
* Added: A "new-line" separator support, on "time-based" (blind) & "tempfile-based" (semiblind) techniques.
* Added: Support for referer-based command injections.
* Added: Support for user-agent-based command injections.
* Added: CVE-2014-6278 support on "shellshock" module.
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
* The initial release {aka the Birth!}
