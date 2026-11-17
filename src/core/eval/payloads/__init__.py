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

"""
What every payload in this package prints with, and why it is not what the command payloads print
with.

Those choose between 'printf' and 'echo' through the 'checks.print_*' family, because a POSIX shell
writes an argument as it stands with the one and reads backslashes as escapes - and an output
beginning '-n' as an option - with the other. These do not choose. One payload here serves either
operating system, only what a shell cannot share being written twice ('$((...))' against 'set /a'),
and 'echo' is the one printer 'cmd.exe' also has: asking 'checks.print_*' for it would reach for a
'printf' that is not there the moment the target turns out to be Windows.

Nothing printed here is an output of the target's, either. It is a marker of letters, or a sum of
two numbers commix chose itself, so neither of the things 'echo' does to a string can reach one -
which is the whole of what 'printf' is preferred for on the other side.
"""

# eof
