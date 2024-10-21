#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import time
import base64
import sqlite3
from src.utils import menu
from src.utils import settings
from src.utils import common
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Session handler via SQLite3 db.
"""
no_such_table = False

"""
"""
def split_url(url):
  return url.split("?")[0]

"""
Generate table name for SQLite3 db.
"""
def table_name(url):
  host = url.split('//', 1)[1].split('/', 1)[0]
  table_name = "session_" + host.replace(".","_").replace(":","_").replace("-","_").replace("[","_").replace("]","_")
  return table_name

"""
Ignore session.
"""
def ignore(url):
  if os.path.isfile(settings.SESSION_FILE):
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Ignoring the stored session from the session file due to '--ignore-session' switch."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  else:
    if settings.VERBOSITY_LEVEL != 0:
      warn_msg = "Skipping ignoring the stored session, as the session file not exist."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Flush session.
"""
def flush(url):
  if os.path.isfile(settings.SESSION_FILE):
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Flushing the stored session from the session file."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    try:
      conn = sqlite3.connect(settings.SESSION_FILE)
      tables = list(conn.execute("SELECT name FROM sqlite_master WHERE type is 'table'"))
      conn.executescript(';'.join(["DROP TABLE IF EXISTS %s" %i for i in tables]))
      conn.commit()
      conn.close()
    except sqlite3.OperationalError as err_msg:
      err_msg = "Unable to flush the session file. " + str(err_msg)
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  else:
    if settings.VERBOSITY_LEVEL != 0:
      warn_msg = "Skipping flushing the stored session, as the session file not exist."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Clear injection point records
except latest for every technique.
"""
def clear(url):
  try:
    if no_such_table:
      conn = sqlite3.connect(settings.SESSION_FILE)
      query = "DELETE FROM " + table_name(url) + "_ip WHERE " + \
              "id NOT IN (SELECT MAX(id) FROM " + \
              table_name(url) + "_ip GROUP BY technique);"
      conn.execute(query)
      conn.commit()
      conn.close()
  except sqlite3.OperationalError as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  except:
    settings.LOAD_SESSION = None
    return False

"""
Import successful injection points to session file.
"""
def import_injection_points(url, technique, injection_type, filename, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS " + table_name(url) + "_ip" + \
                 "(id INTEGER PRIMARY KEY, url VARCHAR, technique VARCHAR, injection_type VARCHAR, separator VARCHAR," \
                 "shell VARCHAR, vuln_parameter VARCHAR, prefix VARCHAR, suffix VARCHAR, "\
                 "TAG VARCHAR, alter_shell VARCHAR, payload VARCHAR, http_header VARCHAR, http_request_method VARCHAR, url_time_response INTEGER, "\
                 "timesec INTEGER, exec_time INTEGER, output_length INTEGER, is_vulnerable VARCHAR, data VARCHAR, cookie VARCHAR);")

    conn.execute("INSERT INTO " + table_name(url) + "_ip(url, technique, injection_type, separator, "\
                 "shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_header, http_request_method, "\
                 "url_time_response, timesec, exec_time, output_length, is_vulnerable, data, cookie) "\
                 "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", \
                 (str(url), str(technique), str(injection_type), \
                 str(separator), str(shell), str(vuln_parameter), str(prefix), str(suffix), \
                 str(TAG), str(alter_shell), str(payload), str(settings.HTTP_HEADER), str(http_request_method), \
                 int(url_time_response), int(timesec), int(exec_time), \
                 int(output_length), str(is_vulnerable), str(menu.options.data), str(menu.options.cookie)))
    conn.commit()
    conn.close()
    if settings.INJECTION_CHECKER == False:
      settings.INJECTION_CHECKER = True

  except sqlite3.OperationalError as err_msg:
    err_msg = str(err_msg)[:1].upper() + str(err_msg)[1:] + "."
    err_msg += " You are advised to rerun with switch '--flush-session'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    checks.quit(filename, url, _ = False)

  except sqlite3.DatabaseError as err_msg:
    checks.error_loading_session_file()

"""
Export successful applied techniques from session file.
"""
def applied_techniques(url, http_request_method): 
  try: 
    techniques = []
    conn = sqlite3.connect(settings.SESSION_FILE)
    query = "SELECT * FROM sqlite_master WHERE name = '" + table_name(url) + "_ip' AND type = 'table';"
    result = conn.execute(query)
    if result:
      query = "SELECT * FROM " + table_name(url) + "_ip WHERE url like '%" + split_url(url) + "%';"
      cursor = conn.execute(query).fetchall()
      if cursor:
        for session in cursor:
          if session[2] == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
            technique = session[2].split()[2][0]
          else:
            technique = session[2][0]
          techniques.append(technique)
      techniques = list(set(techniques))
      techniques = "".join(str(x) for x in techniques)
    return techniques
  except sqlite3.OperationalError as err_msg:
    settings.LOAD_SESSION = None
    return techniques
  except:
    settings.LOAD_SESSION = None
    return techniques

"""
Export successful applied injection level from session file.
"""
def applied_levels(url, http_request_method):
  level = settings.DEFAULT_INJECTION_LEVEL
  try: 
    conn = sqlite3.connect(settings.SESSION_FILE)
    query = "SELECT * FROM sqlite_master WHERE name = '" + table_name(url) + "_ip' AND type = 'table';"
    result = conn.execute(query)
    if result:
      query = "SELECT * FROM " + table_name(url) + "_ip WHERE url like '%" + split_url(url) + "%';"
      cursor = conn.execute(query).fetchall()
      if cursor:
        for session in cursor:
          http_header = session[12]
          level = int(session[18])
    if http_header:
      if http_header == settings.COOKIE.lower(): 
        level = settings.COOKIE_INJECTION_LEVEL
      else:
        level = settings.HTTP_HEADER_INJECTION_LEVEL
    return level
  except sqlite3.OperationalError as err_msg:
    settings.LOAD_SESSION = None
    return level
  except:
    settings.LOAD_SESSION = None
    return level

"""
Export successful injection points from session file.
"""
def check_stored_injection_points(url, check_parameter, http_request_method):
  _ = False 
  try:
    techniques = []
    conn = sqlite3.connect(settings.SESSION_FILE)
    query = "SELECT * FROM sqlite_master WHERE name = '" + table_name(url) + "_ip' AND type = 'table';"
    result = conn.execute(query).fetchall()
    # vuln_parameter = check_parameter
    if result:
      query = "SELECT * FROM " + table_name(url) + "_ip WHERE url like '%" + split_url(url) + "%';"
      cursor = conn.execute(query).fetchall()
      if cursor:
        for session in cursor:
          url = session[1]
          if session[2] == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
            technique = session[2].split()[2][0]
          else:
            technique = session[2][0]
          if technique in menu.options.tech:
            _ = True
          techniques.append(technique)
          cookie = session[20]
          if cookie:
            if settings.INJECT_TAG in cookie:
              settings.COOKIE_INJECTION = True
            menu.options.cookie = cookie
      techniques = list(set(techniques))
      techniques = "".join(str(x) for x in techniques)
      if _:
        vuln_parameter = session[6]
        settings.LOAD_SESSION = True
        settings.INJECTION_CHECKER = True
        if not settings.MULTI_TARGETS:
          settings.TESTABLE_PARAMETERS_LIST.append(vuln_parameter)
        return url, vuln_parameter
      else:
        settings.LOAD_SESSION = False
      return url, vuln_parameter
    else:
      settings.LOAD_SESSION = None
      return url, check_parameter
  except sqlite3.OperationalError as err_msg:
    settings.LOAD_SESSION = None
    return url, check_parameter
  except:
    settings.LOAD_SESSION = None
    return url, check_parameter

"""
Export successful injection points from session file.
"""
def export_injection_points(url, technique, injection_type, http_request_method):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    result = conn.execute("SELECT * FROM sqlite_master WHERE name = '" + table_name(url) + "_ip' AND type = 'table';")
    if result:
      query = "SELECT * FROM " + table_name(url) + "_ip WHERE " + \
              "url like '%" + split_url(url) + "%' AND " + \
              "technique == '" + technique + "' AND " + \
              "injection_type == '" + injection_type + "' AND " + \
              "http_request_method == '" + http_request_method + "';"
      cursor = conn.execute(query).fetchall()
      if cursor:
        for session in cursor:
          url = session[1]
          technique = session[2]
          injection_type = session[3]
          separator = session[4]
          shell = session[5]
          vuln_parameter = session[6]
          prefix = session[7]
          suffix = session[8]
          TAG = session[9]
          alter_shell = session[10]
          payload = session[11]
          http_header = session[12]
          http_request_method = session[13]
          url_time_response = session[14]
          timesec = session[15]
          exec_time = session[16]
          output_length = session[17]
          is_vulnerable = session[18]
          data = session[19]
          cookie = session[20]
          if http_header:
            settings.HTTP_HEADER = http_header
          if cookie:
            menu.options.cookie = cookie
          if data:
            settings.IGNORE_USER_DEFINED_POST_DATA = False
            menu.options.data = data
          if settings.INJECTION_LEVEL != is_vulnerable:
            settings.INJECTION_LEVEL = int(is_vulnerable)
          return url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable
      else:
        settings.LOAD_SESSION = None
        return False
    else:
      no_such_table = True
      pass
  except sqlite3.OperationalError as err_msg:
    settings.LOAD_SESSION = None
    return False
  except:
    settings.LOAD_SESSION = None
    return False

"""
Import successful command execution outputs to session file.
"""
def store_cmd(url, cmd, shell, vuln_parameter):
  if any(type(_) is str for _ in (url, cmd, shell, vuln_parameter)):
    try:
      conn = sqlite3.connect(settings.SESSION_FILE)
      conn.execute("CREATE TABLE IF NOT EXISTS " + table_name(url) + "_ir" + \
                   "(cmd VARCHAR, output VARCHAR, vuln_parameter VARCHAR);")
      conn.execute("INSERT INTO " + table_name(url) + "_ir(cmd, output, vuln_parameter) " \
                   "VALUES(?,?,?)", \
                   (str(base64.b64encode(cmd.encode(settings.DEFAULT_CODEC)).decode()), \
                    str(base64.b64encode(shell.encode(settings.DEFAULT_CODEC)).decode()), \
                    str(vuln_parameter)))
      conn.commit()
      conn.close()
    except sqlite3.OperationalError as err_msg:
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    except (TypeError, AttributeError) as err_msg:
      pass

"""
Export successful command execution outputs from session file.
"""
def export_stored_cmd(url, cmd, vuln_parameter):
  try:
    output = None
    conn = sqlite3.connect(settings.SESSION_FILE)
    query = "SELECT output FROM " + table_name(url) + \
            "_ir WHERE cmd='" + base64.b64encode(cmd.encode(settings.DEFAULT_CODEC)).decode() + "' AND " + \
            "vuln_parameter= '" + vuln_parameter + "';"
    cursor = conn.execute(query).fetchall()
    conn.commit()
    conn.close()
    for session in cursor:
      output = base64.b64decode(session[0])
    try:
      return output.decode(settings.DEFAULT_CODEC)
    except AttributeError:
      return output
  except sqlite3.OperationalError as err_msg:
    pass

"""
Import valid credentials to session file.
"""
def import_valid_credentials(url, authentication_type, admin_panel, username, password):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS " + table_name(url) + "_creds" + \
                 "(id INTEGER PRIMARY KEY, url VARCHAR, authentication_type VARCHAR, admin_panel VARCHAR, "\
                 "username VARCHAR, password VARCHAR);")
    conn.execute("INSERT INTO " + table_name(url) + "_creds(url, authentication_type, " \
                 "admin_panel, username, password) VALUES(?,?,?,?,?)", \
                 (str(url), str(authentication_type), str(admin_panel), \
                 str(username), str(password)))
    conn.commit()
    conn.close()
  except sqlite3.OperationalError as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  except sqlite3.DatabaseError as err_msg:
    checks.error_loading_session_file()

"""
Export valid credentials from session file.
"""
def export_valid_credentials(url, authentication_type):
  try:
    output = None
    conn = sqlite3.connect(settings.SESSION_FILE)
    query = "SELECT username, password FROM " + table_name(url) + \
            "_creds WHERE url like '%" + split_url(url) + "%' AND " + \
            "authentication_type= '" + authentication_type + "';"
    cursor = conn.execute(query).fetchall()
    conn.commit()
    conn.close()
    return ":".join(cursor[0])
  except sqlite3.OperationalError as err_msg:
    pass

# eof