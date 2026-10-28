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
Behavioural regression suite, run against a local instance of the
Commix Testbed (https://github.com/commixproject/commix-testbed).

  python tests/regression.py [base-url]

Exits non-zero if any check fails.
"""

import os
import re
import sys
import subprocess

DEFAULT_URL = "http://127.0.0.1:8081"
TIMEOUT = 300

_RESULTS = []

"""
Runs commix with the given arguments and returns its combined output.
"""
def run(args, timeout=TIMEOUT):
  cmd = [sys.executable, "commix.py", "--batch", "--flush-session"] + args
  try:
    process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
  except subprocess.TimeoutExpired:
    return "[timeout]"
  return re.sub(r"\x1b\[[0-9;]*m", "", process.stdout + process.stderr)

"""
Counts the techniques reported in the given output.
"""
def techniques(output):
  return len(re.findall(r"^ \* Technique:", output, re.M))

"""
Records the result of a single check.
"""
def check(name, condition, detail=""):
  _RESULTS.append((name, bool(condition), detail))

"""
The checks themselves.
"""
def main():
  base = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL).rstrip("/")
  url = base + "/scenarios"

  # Every module imports and the built-in self test still passes.
  output = run(["--smoke-test"])
  check("smoke test (all modules import)", "Smoke test passed" in output)

  # A tamper script must not be applied to the eval-sink heuristic probes.
  output = run(["--url=" + url + "/ctf/deadsec24_bing2.php?cmd=id", "--technique=r", "--tamper=printfoctal"])
  check("printfoctal does not hijack to code injection", "code injection technique" not in output)

  # Prose already present in the baseline response must not read as an eval sink.
  output = run(["--url=" + url + "/ctf/dvwa_command_injection.php", "--data=ip=127.0.0.1", "--technique=r", "-v", "1"])
  check("no false 'evaluated language' from page prose", "identified evaluated language" not in output)

  # A self-proving technique must not be re-verified away.
  output = run(["--url=" + url + "/ctf/dvwa_command_injection.php", "--data=ip=127.0.0.1"])
  check("dvwa genuine finding survives", techniques(output) >= 1 and "does not seem to be injectable" not in output,
        "techniques=" + str(techniques(output)))

  # An inference-only finding must still be re-verified.
  output = run(["--url=" + url + "/regular/POST/blind.php", "--data=addr=127.0.0.1", "--technique=b"])
  check("boolean-only finding still re-verified", "is a false positive" in output and techniques(output) == 1)

  # An explicit --tamper switches off both the retry prompt and self-adoption.
  output = run(["--url=" + url + "/ctf/deadsec24_bing2.php?cmd=id", "--technique=r", "--tamper=space2ifs"])
  check("explicit --tamper: no prompt, no stacking",
        "Do you want commix to try again" not in output and "too many tamper scripts" not in output)

  # Self-adopted scripts are not counted against the user.
  output = run(["--url=" + url + "/ctf/dvwa_command_injection.php", "--data=ipx=127.0.0.1", "--technique=r"])
  check("self-adopted scripts: no 'too many tampers' warning", "too many tamper scripts" not in output)
  check("prompt makes no unverified filter claim", "which the target may be filtering" not in output)

  # The writable directory is only ever asked for once per run.
  output = run(["--url=" + url + "/ctf/dvwa_command_injection.php", "--data=ipx=127.0.0.1"])
  asked = output.count("What do you want to use for the writable directory")
  check("writable-dir menu asked once", asked == 1, "asked " + str(asked) + "x")

  # A script adopted for one parameter must not survive into the next.
  output = run(["--url=" + url + "/regular/GET/multiple_params.php?addr=127.0.0.1&count=4&label=x", "--technique=r"])
  payload = re.search(r"^ \* Payload: (.*)$", output, re.M)
  check("no cross-parameter tamper leak",
        payload and "${IFS}" not in payload.group(1) and "\t" not in payload.group(1),
        payload.group(1)[:40] if payload else "no payload")

  # A shell sink reached through --eval is reported with a caveat.
  output = run(["--url=" + url + "/regular/GET/classic.php?addr=127.0.0.1", "--eval=php", "--technique=f"])
  check("--eval on a shell sink: caveat shown", "Re-run without '--eval'" in output)

  # A real eval sink is reported without one.
  output = run(["--url=" + url + "/regular/GET/eval.php?user=commix", "--eval=php"])
  check("--eval on a real eval sink: no caveat",
        "Re-run without '--eval'" not in output and techniques(output) >= 1,
        "techniques=" + str(techniques(output)))

  # The same holds for the non-PHP eval sinks.
  false_caveats = []
  for language, target in (("python", "/python/eval.py"), ("perl", "/perl/eval.pl"), ("lua", "/lua/eval.lua")):
    output = run(["--url=" + url + target + "?user=commix", "--eval=" + language])
    if "Re-run without '--eval'" in output:
      false_caveats.append(language)
  check("--eval on non-PHP eval sinks: no caveat", not false_caveats, ",".join(false_caveats))

  print("")
  passed = 0
  for name, ok, detail in _RESULTS:
    print(("  [ OK ]  " if ok else "  [FAIL]  ") + name + (("   (" + detail + ")") if detail else ""))
    passed += int(ok)
  print("\n" + str(passed) + "/" + str(len(_RESULTS)) + " checks passed")
  return 0 if passed == len(_RESULTS) else 1

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
  sys.exit(main())
