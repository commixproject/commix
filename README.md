	                                       __
	   ___    ___     ___ ___     ___ ___ /\_\   __  _ 
	  /'___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\
	 /\ \__//\ \L\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
	 \ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\
	  \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ { v0.01b }

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


#Usage
    Usage: python commix.py [options]

####Options:

    -h, --help            Show help and exit.
    --verbose             Enable the verbose mode.
    --install             Install 'commix' to your system.
    --version             Show version number and exit.
    --update              Check for updates (apply if any) and exit.

####Target:
    This options has to be provided, to define the target URL.

    --url=URL           Target URL.
    --url-reload        Reload target URL after command execution.

####Request:

    These options can be used, to specify how to connect to the target
    URL.

    --method=METHOD     HTTP method (GET or POST).
    --host=HOST         HTTP Host header.
    --referer=REFERER   HTTP Referer header.
    --user-agent=AGENT  HTTP User-Agent header.
    --cookie=COOKIE     HTTP Cookie header.
    --headers=HEADERS   Extra headers (e.g. 'Header1:Value1\nHeader2:Value2').
    --proxy=PROXY       Use a HTTP proxy (e.g. '127.0.0.1:8080').
    --auth-url=AUTH_..  Login panel URL.
    --auth-data=AUTH..  Login parameters and data.
    --auth-cred=AUTH..  HTTP Basic Authentication credentials (e.g.
                        'admin:admin').

####Injection:

    These options can be used, to specify which parameters to inject and
    to provide custom injection payloads.

    --param=PARAMETER   Parameter(s) to inject (use 'INJECT_HERE' tag).
    --suffix=SUFFIX     Injection payload suffix string.
    --prefix=PREFIX     Injection payload prefix string.
    --technique=TECH    Specify a certain injection technique : 'classic',
                        'eval-based', 'time-based' or 'boolean-based'.
    --maxlen=MAXLEN     The length of the output on time-based technique
                        (Default: 10000 chars).
    --delay=DELAY       Set Time-delay for time-based and boolean-based
                        techniques (Default: 1 sec).
    --base64            Use Base64 (enc)/(de)code trick to prevent false-
                        positive results.

####Usage Examples:
**Exploiting Damn Vulnerable Web App :**

    python commix.py --url="http://192.168.178.58/DVWA-1.0.8/vulnerabilities/exec/#" --method="POST" --param="ip=INJECT_HERE&submit=submit" --cookie="security=medium; PHPSESSID=nq30op434117mo7o2oe5bl7is4"
    
**Exploiting php-Charts 1.0 *(using injection payload suffix & prefix string)* :**

    python commix.py --url="http://192.168.178.55/php-charts_v1.0/wizard/index.php?type=INJECT_HERE" --prefix="//" --suffix="'" 
    
**Exploiting OWASP Mutillidae *(using Extra headers and HTTP proxy)* :**

    python commix.py --url="http://192.168.178.46/mutillidae/index.php?popUpNotificationCode=SL5&page=dns-lookup.php" --param="target_host=INJECT_HERE" --method="POST" --headers="Accept-Language:fr\nETag:123\n" --proxy="127.0.0.1:8081"
