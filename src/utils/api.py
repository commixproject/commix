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

import io
import os
import re
import sys
import json
import signal
import shutil
import secrets
import tempfile
import subprocess
import contextlib

from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib import parse as _urlparse
from urllib import request as _urlrequest
from optparse import OptionValueError

from src.utils import settings

"""
The parser is read for what the options are and what they are worth, which is what lets a request
name them the way a command line does.

Read behind an empty command line, and with its output held back: the module settles a run of its
own on the way in, and left as it is would read the server's own arguments as though they had been
meant for a scan, and print the banner one starts with.
"""
_argv = sys.argv
try:
  sys.argv = sys.argv[:1]
  with contextlib.redirect_stdout(io.StringIO()):
    from src.core.parse import cmdline as menu
    from src.core.parse import configfile
    from src.utils import common
finally:
  sys.argv = _argv

"""
What the server answers to, and what it answers with.
"""
API_VERSION = "1.0"
TASK_ID_BYTES = 8
LOG_LINE_REGEX = re.compile(r"^\[(?P<time>\d{2}:\d{2}:\d{2})\]\s+\[(?P<level>[a-z]+)\]\s+(?P<message>.*)$")

"""
Every name an option answers to: where it is kept, and every spelling the command line takes.

Twelve of them are not the same word - '--user-agent' is kept as 'agent', '--technique' as 'tech' -
and a request is free to name either, rather than having to know which of the two this one is.
"""
_OPTION_NAMES = {}

def _option(name):
  if not _OPTION_NAMES:
    for option_list in [menu.parser.option_list] + [group.option_list for group in menu.parser.option_groups]:
      for option in option_list:
        if not option.dest:
          continue
        for spelling in [option.dest] + option._long_opts + option._short_opts:
          _OPTION_NAMES.setdefault(spelling.lstrip("-").replace("-", "_"), option)
  return _OPTION_NAMES.get(name)

"""
One scan, from the options it was given to the process running them and the files it leaves behind.
"""
class Task(object):
  def __init__(self, taskid, directory):
    self.taskid = taskid
    self.directory = directory
    self.options = menu.parser.get_default_values().__dict__.copy()
    self.process = None
    self.config_file = os.path.join(directory, "options.ini")
    self.report_file = os.path.join(directory, "report.json")
    self.console_file = os.path.join(directory, "console.log")
    self.output_dir = os.path.join(directory, "output")

  """
  Settle one option, by the name the command line knows it as.
  """
  def set_option(self, name, value):
    option = _option(name.strip().lstrip("-").replace("-", "_"))
    if option is None:
      return "Unknown option '" + str(name).strip() + "'."
    # Checked here rather than left for the run to refuse: a value the parser would not have taken
    # is a request that did not do what it was told it did.
    if option.action == "store" and not isinstance(value, bool) and value is not None:
      try:
        value = option.convert_value((option._long_opts + option._short_opts)[0], str(value))
      except OptionValueError as err_msg:
        return str(err_msg).replace("option ", "The option ", 1).rstrip(".") + "."
    self.options[option.dest] = value
    return None

  """
  Run commix over what has been set, as a process of its own.

  Of its own, because a run is settled in module-level state that is written once and read
  everywhere - two of them in one process would be one run with two sets of answers.
  """
  def start(self):
    values = menu.parser.get_default_values()
    for name, value in self.options.items():
      setattr(values, name, value)
    # The three the server decides for itself: a task reads its own report, keeps its own output,
    # and is never waited on for an answer nobody is there to type.
    values.report_json = self.report_file
    values.output_dir = self.output_dir
    values.batch = True
    with contextlib.redirect_stdout(io.StringIO()):
      configfile.save(menu.parser, values, self.config_file)
    command = _commix_command() + ["-c", self.config_file]
    # Kept rather than thrown away: what the run says as it goes is what '/scan/<id>/log' hands back,
    # and the run's own log file is a report of what was found, not a record of the going.
    console = open(self.console_file, "wb")
    self.process = subprocess.Popen(command, cwd=_commix_directory(), stdout=console,
                                    stderr=subprocess.STDOUT, close_fds=not settings.IS_WINDOWS)
    console.close()

  """
  Whether the process is still going, and what it ended with where it is not.
  """
  def returncode(self):
    if self.process is None:
      return None
    return self.process.poll()

  """
  Ask the run to stop, so that it writes down what it has before it goes.
  """
  def stop(self):
    if self.process is None or self.process.poll() is not None:
      return False
    self.process.send_signal(signal.SIGTERM)
    return True

  """
  End the process where asking did not.
  """
  def kill(self):
    if self.process is None or self.process.poll() is not None:
      return False
    self.process.kill()
    return True

  """
  The report as it stands - a run still going writes it as it goes, so there is one either way.
  """
  def data(self):
    try:
      with open(self.report_file, encoding=settings.DEFAULT_CODEC) as report:
        return json.load(report)
    except (IOError, OSError, ValueError):
      return None

  """
  The run's own log, as lines with the level each was printed at.
  """
  def log(self, start=None, end=None):
    lines = []
    try:
      with open(self.console_file, encoding=settings.DEFAULT_CODEC, errors="replace") as console:
        for line in console:
          match = LOG_LINE_REGEX.match(settings.strip_ansi_codes(line).rstrip())
          if match:
            lines.append(match.groupdict())
    except (IOError, OSError):
      return []
    return lines[start:end] if (start is not None or end is not None) else lines

"""
Where commix itself is, as seen from wherever the server was started.
"""
def _commix_directory():
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _commix_command():
  beside = os.path.join(_commix_directory(), settings.APPLICATION + ".py")
  if os.path.isfile(beside):
    return [sys.executable or "python", beside]
  # Installed rather than checked out: there is no file to hand the interpreter, and the command
  # that was installed alongside this one is what a run is started as.
  installed = shutil.which(settings.APPLICATION)
  if installed:
    return [installed]
  raise RuntimeError("Unable to find " + settings.APPLICATION + " to run.")

"""
Every task this server has been asked to keep, and the word that has to be shown to reach them.
"""
class Store(object):
  tasks = {}
  token = ""
  directory = ""

"""
Take back the tasks of a server that has been restarted.

Their directories are what a task really is - the options it was given, what the run said and what
it found. Left unread, a client holding a task id is told there is no such task while all of it is
still on disk.
"""
def recover():
  if not os.path.isdir(Store.directory):
    return 0
  for name in sorted(os.listdir(Store.directory)):
    directory = os.path.join(Store.directory, name)
    if name in Store.tasks or not re.match(r"^[0-9a-f]+$", name) or not os.path.isdir(directory):
      continue
    task = Task(name, directory)
    if os.path.isfile(task.config_file):
      values = menu.parser.get_default_values()
      try:
        with contextlib.redirect_stdout(io.StringIO()):
          configfile.load(menu.parser, values, task.config_file)
        task.options = values.__dict__.copy()
      except SystemExit:
        pass
    Store.tasks[name] = task
  return len(Store.tasks)

"""
Take a task out of the store, after making sure nothing of it is still running.
"""
def _forget(taskid):
  task = Store.tasks.pop(taskid, None)
  if task is not None:
    task.kill()

"""
The routes, as (method, pattern, handler-name) - matched in order, first one wins.
"""
ROUTES = (
  ("GET", r"^/version$", "version"),
  ("GET", r"^/task/new$", "task_new"),
  ("GET", r"^/task/(?P<taskid>[0-9a-f]+)/delete$", "task_delete"),
  ("GET", r"^/admin/list$", "admin_list"),
  ("GET", r"^/admin/flush$", "admin_flush"),
  ("GET", r"^/option/(?P<taskid>[0-9a-f]+)/list$", "option_list"),
  ("POST", r"^/option/(?P<taskid>[0-9a-f]+)/get$", "option_get"),
  ("POST", r"^/option/(?P<taskid>[0-9a-f]+)/set$", "option_set"),
  ("POST", r"^/scan/(?P<taskid>[0-9a-f]+)/start$", "scan_start"),
  ("GET", r"^/scan/(?P<taskid>[0-9a-f]+)/stop$", "scan_stop"),
  ("GET", r"^/scan/(?P<taskid>[0-9a-f]+)/kill$", "scan_kill"),
  ("GET", r"^/scan/(?P<taskid>[0-9a-f]+)/status$", "scan_status"),
  ("GET", r"^/scan/(?P<taskid>[0-9a-f]+)/data$", "scan_data"),
  ("GET", r"^/scan/(?P<taskid>[0-9a-f]+)/log$", "scan_log"),
)

"""
What every endpoint answers with, so that a client reads one shape whatever it asked for.
"""
def _ok(**fields):
  answer = {"success": True}
  answer.update(fields)
  return 200, answer

def _no(message, code=200):
  return code, {"success": False, "message": message}

"""
One request, answered.

Held apart from the HTTP of it so that what each endpoint does is readable on its own, and so the
same calls can be made from a test without a socket in the way.
"""
class Api(object):
  def version(self, **_):
    return _ok(version=settings.VERSION, api=API_VERSION)

  def task_new(self, **_):
    taskid = secrets.token_hex(TASK_ID_BYTES)
    directory = os.path.join(Store.directory, taskid)
    os.makedirs(directory)
    Store.tasks[taskid] = Task(taskid, directory)
    return _ok(taskid=taskid)

  def task_delete(self, taskid=None, **_):
    if taskid not in Store.tasks:
      return _no("Unknown task.")
    _forget(taskid)
    return _ok()

  def admin_list(self, **_):
    tasks = {}
    for taskid, task in Store.tasks.items():
      tasks[taskid] = _status_of(task)
    return _ok(tasks=tasks, count=len(tasks))

  def admin_flush(self, **_):
    for taskid in list(Store.tasks):
      _forget(taskid)
    return _ok()

  def option_list(self, taskid=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    return _ok(options=task.options)

  def option_get(self, taskid=None, body=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    wanted = (body or {}).get("option")
    if not wanted:
      return _no("No option named.")
    option = _option(str(wanted).strip().lstrip("-").replace("-", "_"))
    if option is None:
      return _no("Unknown option '" + str(wanted) + "'.")
    return _ok(**{option.dest: task.options[option.dest]})

  def option_set(self, taskid=None, body=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    if not isinstance(body, dict) or not body:
      return _no("No options given.")
    if task.returncode() is None and task.process is not None:
      # Refused rather than kept: the running scan was handed its options when it started, so one
      # set now would read as having changed something it cannot reach.
      return _no("That scan is running, and a scan is given its options once, when it starts.")
    for name, value in body.items():
      refused = task.set_option(name, value)
      if refused:
        return _no(refused)
    return _ok()

  def scan_start(self, taskid=None, body=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    if task.returncode() is None and task.process is not None:
      return _no("That scan is already running.")
    for name, value in (body or {}).items():
      refused = task.set_option(name, value)
      if refused:
        return _no(refused)
    if not any(task.options.get(_) for _ in ("url", "logfile", "bulkfile", "requestfile", "sitemap_url", "openapi")):
      return _no("Nothing to scan: none of 'url', 'logfile', 'bulkfile', 'requestfile', 'sitemap_url' or 'openapi' was set.")
    task.start()
    return _ok(engineid=task.process.pid)

  def scan_stop(self, taskid=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    return _ok(stopped=task.stop())

  def scan_kill(self, taskid=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    return _ok(killed=task.kill())

  def scan_status(self, taskid=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    return _ok(**_status_of(task))

  def scan_data(self, taskid=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    report = task.data()
    if report is None:
      return _ok(data={}, error=[])
    # A run over several targets keeps each one's errors with that target; gathered here, so that
    # 'error' says the same thing whichever shape the report took.
    errors = report.get("errors")
    if errors is None:
      errors = [issue for target in report.get("targets", []) for issue in target.get("errors", [])]
    return _ok(data=report, error=errors)

  def scan_log(self, taskid=None, query=None, **_):
    task = Store.tasks.get(taskid)
    if task is None:
      return _no("Unknown task.")
    start, end = _bounds(query or {})
    return _ok(log=task.log(start, end))

"""
Where a run has got to, said the same way whether it is going, gone, or never started.
"""
def _status_of(task):
  returncode = task.returncode()
  if task.process is None:
    # A task read back off disk has no process of its own, but the run it belongs to left its word
    # for how it ended.
    return {"status": (task.data() or {}).get("status") or "not started", "returncode": None}
  if returncode is None:
    return {"status": settings.REPORT_STATUS_RUNNING, "returncode": None}
  state = (task.data() or {}).get("status")
  if not state or state == settings.REPORT_STATUS_RUNNING:
    # The process is gone while its report still says it is going: it ended without the chance to
    # write one down, which is what a signal it cannot answer does to it.
    if returncode < 0:
      state = "killed"
    else:
      state = settings.REPORT_STATUS_COMPLETED if not returncode else settings.REPORT_STATUS_FAILED
  return {"status": state, "returncode": returncode}

"""
The slice of the log a request asked for, where it asked for one.
"""
def _bounds(query):
  def _number(name):
    try:
      return int(query[name][0])
    except (KeyError, IndexError, ValueError):
      return None
  return _number("start"), _number("end")

"""
The HTTP in front of the endpoints above.
"""
class Handler(BaseHTTPRequestHandler):
  server_version = settings.APPLICATION + "/" + str(settings.VERSION)
  api = Api()

  # Nothing to a terminal: a server that narrates every poll buries what it was asked to say.
  def log_message(self, *args):
    pass

  def do_GET(self):
    self._dispatch("GET")

  def do_POST(self):
    self._dispatch("POST")

  """
  Find the endpoint the request named, check it is allowed to ask, and answer it.
  """
  def _dispatch(self, method):
    parsed = _urlparse.urlparse(self.path)
    for route_method, pattern, name in ROUTES:
      match = re.match(pattern, parsed.path)
      if not match:
        continue
      if route_method != method:
        return self._answer(*_no("That address is not asked this way.", code=405))
      if name != "version" and not self._permitted():
        return self._answer(*_no("Wrong or missing API token.", code=401))
      try:
        code, answer = getattr(self.api, name)(body=self._body(), query=_urlparse.parse_qs(parsed.query),
                                               **match.groupdict())
      except Exception as err_msg:
        code, answer = _no(str(err_msg), code=500)
      return self._answer(code, answer)
    self._answer(*_no("No such address.", code=404))

  """
  The token, as the client was told to send it.
  """
  def _permitted(self):
    return secrets.compare_digest(str(self.headers.get("X-Api-Token", "")), Store.token)

  """
  The JSON a POST carried, or nothing where it carried none.
  """
  def _body(self):
    try:
      length = int(self.headers.get("Content-Length") or 0)
    except ValueError:
      return None
    if length <= 0:
      return None
    try:
      return json.loads(self.rfile.read(length).decode(settings.DEFAULT_CODEC))
    except (ValueError, UnicodeDecodeError):
      return None

  def _answer(self, code, answer):
    body = json.dumps(answer, indent=2, ensure_ascii=False).encode(settings.DEFAULT_CODEC)
    self.send_response(code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

"""
Serve the API until it is stopped.
"""
def server(host, port, token=None, directory=None):
  Store.token = token or secrets.token_hex(16)
  Store.directory = directory or tempfile.mkdtemp(prefix=settings.APPLICATION + "-api-")
  if not os.path.isdir(Store.directory):
    os.makedirs(Store.directory)

  taken_back = recover()

  httpd = ThreadingHTTPServer((host, port), Handler)
  info_msg = "Serving the " + settings.APPLICATION + " API at 'http://" + host + ":" + str(httpd.server_port) + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  info_msg = "Tasks are kept under '" + Store.directory + "'"
  info_msg += ("." if not taken_back else ", where " + str(taken_back) + " of them were already.")
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  info_msg = "Send the token '" + Store.token + "' as the 'X-Api-Token' header."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  finally:
    for taskid in list(Store.tasks):
      _forget(taskid)
    httpd.server_close()

"""
The commands a client understands, and what each one says it does.
"""
CLIENT_COMMANDS = (
  ("new", "Make a task and use it from here on"),
  ("use <taskid>", "Work on a task that already exists"),
  ("set <option> <value>", "Set an option on the task in use"),
  ("options", "Show every option of the task in use that is set"),
  ("start", "Start the task's scan"),
  ("status", "Say where the scan has got to"),
  ("data", "Show what the scan has found"),
  ("log", "Show what the scan has said"),
  ("stop", "Ask the scan to stop, keeping what it found"),
  ("kill", "End the scan's process outright"),
  ("list", "Show every task the server holds"),
  ("flush", "Forget all of them"),
  ("exit", "Leave"),
)

"""
Talk to a server from a terminal.

The same addresses, asked for by hand - which is what makes a server worth having a look at before
anything is written against it.
"""
def client(host, port, token):
  base = "http://" + host + ":" + str(port)

  # One request, and the answer it gave, or what went wrong instead of one.
  def ask(path, body=None):
    request = _urlrequest.Request(base + path, method="POST" if body is not None else "GET")
    request.add_header("X-Api-Token", token or "")
    data = None
    if body is not None:
      data = json.dumps(body).encode(settings.DEFAULT_CODEC)
      request.add_header("Content-Type", "application/json")
    try:
      with _urlrequest.urlopen(request, data, timeout=30) as answer:
        return json.loads(answer.read().decode(settings.DEFAULT_CODEC))
    except Exception as err_msg:
      return {"success": False, "message": str(err_msg)}

  hello = ask("/version")
  if not hello.get("success"):
    err_msg = "Unable to reach a " + settings.APPLICATION + " API server at '" + base + "' (" + str(hello.get("message")) + ")."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  info_msg = "Talking to " + settings.APPLICATION + " " + str(hello.get("version")) + " at '" + base + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  menu.print_module_table("Available Commands", [(name, what) for name, what in CLIENT_COMMANDS])

  taskid = None
  while True:
    try:
      line = common.read_input(settings.APPLICATION + "-api > ", default="", check_batch=False)
    except (KeyboardInterrupt, EOFError):
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      break
    words = str(line or "").split()
    if not words:
      continue
    command, rest = words[0].lower(), words[1:]
    if command in ("exit", "quit"):
      break
    if command == "new":
      answer = ask("/task/new")
      taskid = answer.get("taskid") or taskid
    elif command == "use" and rest:
      taskid = rest[0]
      answer = ask("/option/" + taskid + "/list")
      answer = {"success": answer.get("success"), "taskid": taskid} if answer.get("success") else answer
    elif command == "list":
      answer = ask("/admin/list")
    elif command == "flush":
      answer = ask("/admin/flush")
    elif taskid is None:
      answer = {"success": False, "message": "No task in use - 'new' makes one, 'use <taskid>' takes one."}
    elif command == "set" and len(rest) > 1:
      answer = ask("/option/" + taskid + "/set", {rest[0]: _typed(" ".join(rest[1:]))})
    elif command == "options":
      answer = ask("/option/" + taskid + "/list")
      if answer.get("success"):
        # Only what was settled: every option it does not name is what it was already worth.
        answer = {"success": True, "options": {name: value for name, value in answer["options"].items() if value not in (None, False, "", 0)}}
    elif command == "start":
      answer = ask("/scan/" + taskid + "/start", {})
    elif command in ("status", "data", "log", "stop", "kill"):
      answer = ask("/scan/" + taskid + "/" + command)
    else:
      answer = {"success": False, "message": "No such command - 'exit' leaves."}
    settings.print_data_to_stdout(json.dumps(answer, indent=2, ensure_ascii=False) + "\n")

"""
A value typed at a prompt, as the thing it reads as rather than always as text.
"""
def _typed(value):
  if value.lower() in ("true", "false"):
    return value.lower() == "true"
  try:
    return int(value)
  except ValueError:
    return value

"""
Read what the server was asked for, and serve it.
"""
def entry_point():
  from optparse import OptionParser
  parser = OptionParser(usage="python " + settings.APPLICATION + "api.py [option(s)]")
  parser.add_option("-s", "--server", action="store_true", dest="server", default=False,
                    help="Run as a REST API server (the default).")
  parser.add_option("-c", "--client", action="store_true", dest="client", default=False,
                    help="Run as a REST API client, against a server already serving.")
  parser.add_option("-H", "--host", dest="host", default="127.0.0.1",
                    help="Address to listen on (Default: '127.0.0.1').")
  parser.add_option("-p", "--port", dest="port", type="int", default=8775,
                    help="Port to listen on (Default: 8775).")
  parser.add_option("--token", dest="token", default=None,
                    help="Token a request has to carry (Default: one made up per run).")
  parser.add_option("--tasks-dir", dest="tasks_dir", default=None,
                    help="Directory to keep each task's options, output and report in.")
  (options, _) = parser.parse_args()
  if options.server and options.client:
    err_msg = "The options '-s' and '-c' cannot be used together: a run is one or the other."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  try:
    if options.client:
      client(options.host, options.port, options.token)
    else:
      server(options.host, options.port, options.token, options.tasks_dir)
  except KeyboardInterrupt:
    raise SystemExit()
  except Exception as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(str(err_msg)))
    raise SystemExit(settings.EXIT_FAILURE)

# eof
