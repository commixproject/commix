## Version 0.1b [2015]
* Added new eval-based payload (str_replace filter bypass).
* Added check for (GET) RESTful URL format.
* Added new option "--base64", that encodes the OS command to Base64 format. 
* Added support for regular preg_replace() injections via "/e" modifier.
* Added support for HTML Charset and HTTP "Server" response-header reconnaissance (on verbose mode).
* Payloads on "tempfile-based" semiblind technique, have been replaced by new (more solid) ones.
* Added a "new-line" separator support, on "time-based" blind & "tempfile-based" semiblind techniques.
* Added support for referer-based command injections.
* Added support for user-agent-based command injections.
* Added CVE-2014-6278 support on 'shellshock' module.
* Added support for cookie-based command injections.
* Added a generic false-positive prevention technique.
* Removed the "Base64" detection option.
* Added Tor network support.
* Added the 'shellshock' (CVE-2014-6271) injection technique (module).
* Added termcolor support for Windows (colorama).
* Added file access options.
* Added enumeration options.
* Added an alternative option for os-shell (Python).
* Added the "ICMP Exfiltration" injection technique (module). 
* Added the "tempfile-based" semiblind technique.
* Added the "file-based" semiblind technique.
* Removed the "boolean-based" blind technique.
* Added More Options.

## Version 0.1a [2014]
* The initial release {aka the Birth!}
