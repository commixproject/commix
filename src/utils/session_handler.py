#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

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
import hashlib
from src.utils import menu
from src.utils import settings
from src.utils import common
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Split the URL and return only the base part without any query parameters.
"""
no_such_table = False

"""
Generate a safe and valid SQLite table name derived from the host part of the given URL.
Replaces special characters with underscores to comply with SQLite naming rules.
"""
def split_url(url):
  return url.split("?")[0]

"""
Return SHA1 hash of the given text (UTF-8 encoded).
Used for obfuscating hostnames in SQLite table names.
"""
def sha1_hash(text):
  return hashlib.sha1(text.encode('utf-8')).hexdigest()

"""
Extract the host from a full URL string.
Example: from 'http://example.com/path' returns 'example.com'
"""
def get_host_from_url(url):
  return url.split('//', 1)[1].split('/', 1)[0]

"""
Generate a SQLite table name based on the SHA1 hash of the URL's host.
This prevents leaking raw hostnames in session files and ensures
safe table names (hex digits only).
"""
def table_name(url):
  host = get_host_from_url(url)
  hashed_host = sha1_hash(host)
  # Prefix 'session_' to identify session-related tables
  return "session_" + hashed_host

"""
Handle the scenario where the user requests to ignore any stored session data.
Logs debug or warning messages depending on session file presence.
"""
def ignore(url):
  if os.path.isfile(settings.SESSION_FILE):
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Ignoring the stored session from the session file due to '--ignore-session' switch."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  else:
    if settings.VERBOSITY_LEVEL != 0:
      warn_msg = "Skipping ignoring the stored session, as the session file does not exist."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Remove all stored session data by dropping every table in the session database file.
Logs progress and errors appropriately.
"""
def flush(url):
  if os.path.isfile(settings.SESSION_FILE):
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Flushing the stored session from the session file."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    try:
      conn = sqlite3.connect(settings.SESSION_FILE)
      tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
      for table in tables:
        conn.execute("DROP TABLE IF EXISTS " + table)
      conn.commit()
      conn.close()
    except sqlite3.OperationalError as err_msg:
      err_msg = "Unable to flush the session file. " + str(err_msg)
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  else:
    if settings.VERBOSITY_LEVEL != 0:
      warn_msg = "Skipping flushing the stored session, as the session file does not exist."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Remove all but the earliest injection point record for each unique URL and injection technique.
This helps keep the session database clean by preserving only the first discovered injection point,
which might be useful for historical or consistency purposes.
"""
def clear(url):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_ip"
    
    # Query to get the smallest (earliest) id for each unique combination of url and technique
    query = "SELECT MIN(id) FROM \"" + table + "\" GROUP BY url, technique;"
    cursor = conn.execute(query)
    
    # Collect the ids to keep as strings
    earliest_ids = [str(row[0]) for row in cursor.fetchall()]
    
    # If no records found, close connection and return
    if not earliest_ids:
      conn.close()
      return
    
    # Create a comma-separated string of ids to keep
    ids_to_keep = ",".join(earliest_ids)
    
    # Delete all records that do NOT have an id in the earliest_ids list
    delete_query = "DELETE FROM \"" + table + "\" WHERE id NOT IN (" + ids_to_keep + ");"
    conn.execute(delete_query)
    conn.commit()
    conn.close()
    
  except sqlite3.OperationalError as err_msg:
    # Log SQLite operational errors critically
    settings.print_data_to_stdout(settings.print_critical_msg("SQLite error: " + str(err_msg)))
  except Exception as e:
    # Log any other unexpected errors critically
    settings.print_data_to_stdout(settings.print_critical_msg("Error in clear(): " + str(e)))

"""
Store details of a successful injection point into the session database.
Includes various metadata such as technique, payload, timing, vulnerability status, HTTP method, headers, and cookies.
"""
def import_injection_points(url, technique, injection_type, filename, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable):
  
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_ip"
    
    # Create the table if it does not exist
    conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" "
                 "(id INTEGER PRIMARY KEY, url VARCHAR, technique VARCHAR, injection_type VARCHAR, separator VARCHAR, "
                 "shell VARCHAR, vuln_parameter VARCHAR, prefix VARCHAR, suffix VARCHAR, "
                 "TAG VARCHAR, alter_shell VARCHAR, payload VARCHAR, http_header VARCHAR, http_request_method VARCHAR, url_time_response INTEGER, "
                 "timesec INTEGER, exec_time INTEGER, output_length INTEGER, is_vulnerable VARCHAR, data VARCHAR, cookie VARCHAR);")

    # Check if an exact matching record already exists to avoid duplicates
    query_check = ("SELECT 1 FROM \"" + table + "\" WHERE url = ? AND technique = ? AND injection_type = ? AND separator = ? AND "
                   "shell = ? AND vuln_parameter = ? AND prefix = ? AND suffix = ? AND TAG = ? AND alter_shell = ? AND payload = ? AND "
                   "http_header = ? AND http_request_method = ? AND url_time_response = ? AND timesec = ? AND exec_time = ? AND "
                   "output_length = ? AND is_vulnerable = ? AND data = ? AND cookie = ? LIMIT 1;")
    
    params = (str(url), str(technique), str(injection_type), str(separator), str(shell), str(vuln_parameter),
              str(prefix), str(suffix), str(TAG), str(alter_shell), str(payload), str(settings.HTTP_HEADER),
              str(http_request_method), int(url_time_response), int(timesec), int(exec_time),
              int(output_length), str(is_vulnerable), str(menu.options.data), str(menu.options.cookie))

    # Apply urlencode_base64_padding to all string elements in params
    # This ensures that any base64 padding is safely URL-encoded before database insertion.
    params = tuple(
      x.replace(settings.BASE64_PADDING, _urllib.parse.quote(settings.BASE64_PADDING)) 
      if isinstance(x, str) and settings.BASE64_PADDING in x else x
      for x in params
    )

    cursor = conn.execute(query_check, params)
    
    # Insert new record only if no identical record exists
    if cursor.fetchone() is None:
      conn.execute("INSERT INTO \"" + table + "\" (url, technique, injection_type, separator, "
                   "shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_header, http_request_method, "
                   "url_time_response, timesec, exec_time, output_length, is_vulnerable, data, cookie) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params)
      conn.commit()
    
    conn.close()

    # Mark injection checker as True to indicate session contains injection data
    if not settings.INJECTION_CHECKER:
      settings.INJECTION_CHECKER = True

  except sqlite3.OperationalError as err_msg:
    err_msg = str(err_msg)[:1].upper() + str(err_msg)[1:] + "."
    err_msg += " You are advised to rerun with switch '--flush-session'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    checks.quit(filename, url, _=False)

  except sqlite3.DatabaseError:
    checks.error_loading_session_file()

"""
Retrieve a summary string of all unique injection techniques that have been successfully applied
and stored in the session for the given URL.
"""
def applied_techniques(url, http_request_method): 
  techniques = []
  try: 
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_ip"
    query = "SELECT name FROM sqlite_master WHERE name = ? AND type = 'table';"
    result = conn.execute(query, (table,))
    if result:
      query = "SELECT technique FROM \"" + table + "\" WHERE url LIKE ?;"
      cursor = conn.execute(query, ("%" + split_url(url) + "%",)).fetchall()
      for session in cursor:
        technique_info = session[0]
        if technique_info == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
          technique = technique_info.split()[2][0]
        else:
          technique = technique_info[0]
        techniques.append(technique)
      conn.close()
      techniques = list(set(techniques))
      techniques = "".join(str(x) for x in techniques)
    return techniques
  except sqlite3.OperationalError:
    settings.LOAD_SESSION = None
    return techniques
  except:
    settings.LOAD_SESSION = None
    return techniques

"""
Retrieve the injection level stored in the session for the given URL, considering HTTP headers or cookies.
Returns the default injection level if no stored data is found.
"""
def applied_levels(url, http_request_method):
  level = settings.DEFAULT_INJECTION_LEVEL
  http_header = None
  try: 
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_ip"
    query = "SELECT name FROM sqlite_master WHERE name = ? AND type = 'table';"
    result = conn.execute(query, (table,))
    if result:
      query = "SELECT http_header, is_vulnerable FROM \"" + table + "\" WHERE url LIKE ?;"
      cursor = conn.execute(query, ("%" + split_url(url) + "%",)).fetchall()
      for session in cursor:
        http_header = session[0]
        level = int(session[1])
      conn.close()
    if http_header:
      if http_header == settings.COOKIE.lower():
        level = settings.COOKIE_INJECTION_LEVEL
      else:
        level = settings.HTTP_HEADER_INJECTION_LEVEL
    return level
  except sqlite3.OperationalError:
    settings.LOAD_SESSION = None
    return level
  except:
    settings.LOAD_SESSION = None
    return level


"""
Check the session database for stored injection points matching the given URL and parameter.
If found, updates the relevant settings and returns stored vulnerable parameter information.
"""
def check_stored_injection_points(url, check_parameter, http_request_method):
  try:
    found = False
    techniques = set()
    vuln_parameter = check_parameter
    table = table_name(url) + "_ip"

    # Ensure table name is safe (only alphanumeric + underscore)
    if not table.isidentifier():
      raise ValueError("Unsafe table name")

    conn = sqlite3.connect(settings.SESSION_FILE)
    cursor = conn.cursor()

    # Check if the table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE name = ? AND type = 'table';", (table,))
    if not cursor.fetchall():
      settings.LOAD_SESSION = None
      return url, check_parameter

    # Fetch stored sessions for matching URL
    like_url = "%" + split_url(url) + "%"
    query = "SELECT * FROM \"" + table + "\" WHERE url LIKE ?;"
    cursor.execute(query, (like_url,))
    sessions = cursor.fetchall()

    for session in sessions:
      session_url = session[1]
      technique_info = session[2]
      vuln_param = session[6]
      http_header = session[12]
      
      # Parse technique
      if technique_info == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
        technique = technique_info.split()[2][0]
      else:
        technique = technique_info[0]

      techniques.add(technique)

      if technique in menu.options.tech:
        found = True
        # Prefer more specific vulnerable parameter (e.g., HTTP header), if available
        vuln_parameter = vuln_param or http_header

      cookie = session[20] if len(session) > 20 else None
      if cookie:
        if settings.INJECT_TAG in cookie:
          settings.COOKIE_INJECTION = True
        menu.options.cookie = cookie

    if found:
      settings.LOAD_SESSION = True
      settings.INJECTION_CHECKER = True
      if not settings.MULTI_TARGETS and vuln_parameter not in settings.TESTABLE_PARAMETERS_LIST:
        settings.TESTABLE_PARAMETERS_LIST.append(vuln_parameter)
      return session_url, vuln_parameter

    settings.LOAD_SESSION = False
    return url, check_parameter

  except sqlite3.OperationalError:
    settings.LOAD_SESSION = None
    return url, check_parameter
  except Exception:
    settings.LOAD_SESSION = None
    return url, check_parameter


"""
Retrieve detailed stored injection point information from the session database matching
URL, technique, injection type, and HTTP method.
Returns False if no matching session is found.
"""
def export_injection_points(url, technique, injection_type, http_request_method):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_ip"

    # Check if table exists safely
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE name = ? AND type = 'table';", (table,))
    if not cursor.fetchall():
      settings.LOAD_SESSION = None
      return False

    # Prepare query with parameters
    like_url = "%" + split_url(url) + "%"
    query = ("SELECT * FROM \"" + table + "\" WHERE url LIKE ? AND technique = ? "
             "AND injection_type = ? AND http_request_method = ?;")
    cursor.execute(query, (like_url, technique, injection_type, http_request_method))
    sessions = cursor.fetchall()

    if sessions:
      for session in sessions:
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

        return (url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix,
                TAG, alter_shell, payload, http_request_method, url_time_response, timesec,
                exec_time, output_length, is_vulnerable)

    settings.LOAD_SESSION = None
    return False

  except sqlite3.OperationalError:
    settings.LOAD_SESSION = None
    return False
  except:
    settings.LOAD_SESSION = None
    return False


"""
Store the output of a successfully executed command for a given URL and vulnerable parameter in the session database.
Command and output are base64-encoded for storage.
"""
def store_cmd(url, cmd, shell, vuln_parameter):
  if any(type(_) is str for _ in (url, cmd, shell, vuln_parameter)):
    try:
      conn = sqlite3.connect(settings.SESSION_FILE)
      table = table_name(url) + "_ir"
      conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" "
                   "(cmd VARCHAR, output VARCHAR, vuln_parameter VARCHAR);")
      conn.execute("INSERT INTO \"" + table + "\" (cmd, output, vuln_parameter) VALUES (?, ?, ?)",
                   (base64.b64encode(cmd.encode(settings.DEFAULT_CODEC)).decode(),
                    base64.b64encode(shell.encode(settings.DEFAULT_CODEC)).decode(),
                    vuln_parameter))
      conn.commit()
      conn.close()
    except sqlite3.OperationalError as err_msg:
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    except (TypeError, AttributeError):
      pass


"""
Retrieve the stored output of a previously executed command from the session database, decoding it back to a string.
Returns None if no stored output is found.
"""
def export_stored_cmd(url, cmd, vuln_parameter):
  try:
    output = None
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_ir"
    encoded_cmd = base64.b64encode(cmd.encode(settings.DEFAULT_CODEC)).decode()
    query = "SELECT output FROM \"" + table + "\" WHERE cmd = ? AND vuln_parameter = ?;"
    cursor = conn.execute(query, (encoded_cmd, vuln_parameter)).fetchall()
    conn.close()
    for session in cursor:
      output = base64.b64decode(session[0])
    try:
      return output.decode(settings.DEFAULT_CODEC)
    except AttributeError:
      return output
  except sqlite3.OperationalError:
    pass


"""
Save valid authentication credentials (e.g., username and password) discovered during testing into the session database.
"""
def import_valid_credentials(url, authentication_type, admin_panel, username, password):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_creds"
    conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" "
                 "(id INTEGER PRIMARY KEY, url VARCHAR, authentication_type VARCHAR, admin_panel VARCHAR, "
                 "username VARCHAR, password VARCHAR);")
    conn.execute("INSERT INTO \"" + table + "\" (url, authentication_type, admin_panel, username, password) VALUES (?, ?, ?, ?, ?)",
                 (url, authentication_type, admin_panel, username, password))
    conn.commit()
    conn.close()
  except sqlite3.OperationalError as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  except sqlite3.DatabaseError:
    checks.error_loading_session_file()

"""
Retrieve valid stored authentication credentials for a given URL and authentication type from the session database.
Returns the credentials as a colon-separated string if found.
"""
def export_valid_credentials(url, authentication_type):
  try:
    conn = sqlite3.connect(settings.SESSION_FILE)
    table = table_name(url) + "_creds"
    like_url = "%" + split_url(url) + "%"
    query = "SELECT username, password FROM \"" + table + "\" WHERE url LIKE ? AND authentication_type = ?;"
    cursor = conn.execute(query, (like_url, authentication_type)).fetchall()
    conn.close()
    if cursor:
      return ":".join(cursor[0])
  except sqlite3.OperationalError:
    pass

# eof
