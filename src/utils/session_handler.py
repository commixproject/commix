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

import os
import re
import time
import base64
import sqlite3
import hashlib
import contextlib
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
Open the session DB and always close it; retry after recreating a deleted directory.
"""
@contextlib.contextmanager
def _session_connection(session_file=None):
  if session_file is None:
    session_file = settings.SESSION_FILE
  conn = None
  last_err = None
  for attempt in range(5):
    try:
      session_dir = os.path.dirname(session_file)
      if session_dir and not os.path.isdir(session_dir):
        os.makedirs(session_dir, exist_ok=True)
      conn = sqlite3.connect(session_file, timeout=10)
      break
    except sqlite3.OperationalError as err:
      last_err = err
      time.sleep(0.3 * (attempt + 1))
  if conn is None:
    raise last_err
  try:
    yield conn
  finally:
    conn.close()

"""
Split the URL and return only the base part without any query parameters.
"""
def split_url(url):
  return url.split("?")[0]

"""
Escape SQL LIKE wildcard characters so they're matched literally.
"""
def escape_like(value):
  return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

"""
Check whether the given table exists in the session database.
"""
def table_exists(conn, table):
  return conn.execute("SELECT name FROM sqlite_master WHERE name = ? AND type = 'table';", (table,)).fetchone() is not None

"""
Return SHA1 hash of the given text (UTF-8 encoded).
Used for obfuscating hostnames in SQLite table names.
"""
def sha1_hash(text):
  return hashlib.sha1(text.encode('utf-8')).hexdigest()

"""
How a stored row is matched to a URL: the address without its query string, either stored as it is
or followed by one - so a row kept for '/abc' is not handed back for '/a'.
"""
def url_match(url):
  base_url = split_url(url)
  return "(url = ? OR url LIKE ? ESCAPE '\\')", (base_url, escape_like(base_url) + "?%")

"""
Restore a value the session stored, unless this run was given one of its own on the command line -
what the user asked for now outranks what a previous run happened to be using.
"""
def restore_option(stored, applied, label):
  if not stored or stored == "None":
    return None
  # What was stored carries the marker saying where the injection point is, and what is given now
  # does not - so the two are compared by what they hold rather than by how they are written.
  if applied and checks.remove_tags(applied) != checks.remove_tags(stored):
    warn_msg = ("The stored session was found using the " + label + " '" + checks.remove_tags(stored) + "', which differs "
                "from the one provided now ('" + applied + "'). Keeping the one provided now.")
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return None
  return stored

"""
Say when a stored finding was made with something other than what this run was given.

These are the values a replay cannot honour: the stored payload was built around them, so the one
given now would only appear to be in use. Announced and then left alone, rather than applied.
"""
def announce_replay_conflict(stored, applied, label, switch):
  if not applied or str(applied) == str(stored):
    return
  warn_msg = ("The stored session was found using the " + label + " '" + str(stored) + "', which "
              "differs from the '" + switch + "' value provided now ('" + str(applied) + "'). "
              "Using the stored value to replay this technique consistently.")
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
How a stored technique is selected today: the technique letter it is reached by, and whether it
reaches the evaluation sink. What was stored as its own technique letter is now a sink reached by
one of the others, so a finding kept under the old spelling still resumes under the new one.
"""
def technique_selection(technique_info, injection_type=None):
  if technique_info == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    return settings.EVAL_CAPABLE_TECHNIQUES[0], True
  # Which sink was found is the stored type's to say: every other technique reaches either one.
  return technique_letter(technique_info), injection_type in settings.EVAL_INJECTION_TYPES

"""
Map stored technique names to their "--technique" menu letters.
"""
def technique_letter(technique_info):
  if technique_info == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    return technique_info.split()[2][0]
  if technique_info == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    return settings.INJECTION_TECHNIQUE.FILE_BASED[0]
  if technique_info in (settings.INJECTION_TECHNIQUE.CLASSIC, settings.INJECTION_TECHNIQUE.TIME_BASED, settings.INJECTION_TECHNIQUE.FILE_BASED, settings.INJECTION_TECHNIQUE.OOB):
    return technique_info[0]
  return None

"""
Extract the host from a full URL string.
Example: from 'http://example.com/path' returns 'example.com'
"""
def get_host_from_url(url):
  if '//' in url:
    url = url.split('//', 1)[1]
  return url.split('/', 1)[0]

"""
Generate a SQLite table name based on the SHA1 hash of the URL's host.
This prevents leaking raw hostnames in session files and ensures
safe table names (hex digits only).
"""
def table_name(url):
  host = get_host_from_url(url)
  # The layout stamp is hashed in with the host, so a table left by an earlier layout is not found.
  hashed_host = sha1_hash(host + "|" + settings.SESSION_MILESTONE_VALUE)
  # Prefix 'session_' to identify session-related tables
  return "session_" + hashed_host

"""
Handle the scenario where the user requests to ignore any stored session data.
Logs debug or warning messages depending on session file presence.
"""
def ignore():
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
def flush():
  if os.path.isfile(settings.SESSION_FILE):
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Flushing the stored session from the session file."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    try:
      with _session_connection() as conn:
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
          conn.execute("DROP TABLE IF EXISTS " + table)
        conn.commit()
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as err_msg:
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
    with _session_connection() as conn:
      table = table_name(url) + "_ip"

      # Nothing to clear if the table hasn't been created yet.
      if conn.execute("SELECT name FROM sqlite_master WHERE name = ? AND type = 'table';", (table,)).fetchone() is None:
        return

      query = "SELECT MIN(id) FROM \"" + table + "\" GROUP BY url, technique, vuln_parameter, http_header;"
      cursor = conn.execute(query)

      # Collect the ids to keep as strings
      earliest_ids = [str(row[0]) for row in cursor.fetchall()]

      # If no records found, nothing more to do
      if not earliest_ids:
        return

      # Create a comma-separated string of ids to keep
      ids_to_keep = ",".join(earliest_ids)

      # Delete all records that do NOT have an id in the earliest_ids list
      delete_query = "DELETE FROM \"" + table + "\" WHERE id NOT IN (" + ids_to_keep + ");"
      conn.execute(delete_query)
      conn.commit()

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
def import_injection_points(url, technique, injection_type, filename, separator, shell, vuln_parameter, prefix, suffix, TAG, interpreter, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable):
  
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_ip"

      # Create the table if it does not exist
      conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" "
                   "(id INTEGER PRIMARY KEY, url VARCHAR, technique VARCHAR, injection_type VARCHAR, separator VARCHAR, "
                   "shell VARCHAR, vuln_parameter VARCHAR, prefix VARCHAR, suffix VARCHAR, "
                   "TAG VARCHAR, interpreter VARCHAR, payload VARCHAR, http_header VARCHAR, http_request_method VARCHAR, url_time_response INTEGER, "
                   "timesec INTEGER, exec_time INTEGER, output_length INTEGER, is_vulnerable VARCHAR, data VARCHAR, cookie VARCHAR, tamper VARCHAR, "
                   "target_os VARCHAR, file_deleted VARCHAR DEFAULT '', web_root VARCHAR DEFAULT '', tmp_path VARCHAR DEFAULT '');")

      # Check if an exact matching record already exists to avoid duplicates
      query_check = ("SELECT 1 FROM \"" + table + "\" WHERE url = ? AND technique = ? AND injection_type = ? AND separator = ? AND "
                     "shell = ? AND vuln_parameter = ? AND prefix = ? AND suffix = ? AND TAG = ? AND interpreter = ? AND payload = ? AND "
                     "http_header = ? AND http_request_method = ? AND url_time_response = ? AND timesec = ? AND exec_time = ? AND "
                     "output_length = ? AND is_vulnerable = ? AND data = ? AND cookie = ? AND tamper = ? AND target_os = ? AND web_root = ? AND tmp_path = ? LIMIT 1;")

      params = (str(url), str(technique), str(injection_type), str(separator), str(shell), str(vuln_parameter or ""),
                str(prefix), str(suffix), str(TAG), str(interpreter), str(payload), str(settings.HTTP_HEADER),
                str(http_request_method), int(url_time_response), int(timesec), int(exec_time),
                int(output_length), str(is_vulnerable), str(menu.options.data), str(menu.options.cookie),
                str(menu.options.tamper or ""), str(settings.TARGET_OS), str(settings.WEB_ROOT or ""), str(menu.options.tmp_path or ""))

      if settings.BASE64_PADDING in params[0]:
        params = (params[0].replace(settings.BASE64_PADDING, _urllib.parse.quote(settings.BASE64_PADDING)),) + params[1:]

      cursor = conn.execute(query_check, params)

      # Insert new record only if no identical record exists
      if cursor.fetchone() is None:
        conn.execute("INSERT INTO \"" + table + "\" (url, technique, injection_type, separator, "
                     "shell, vuln_parameter, prefix, suffix, TAG, interpreter, payload, http_header, http_request_method, "
                     "url_time_response, timesec, exec_time, output_length, is_vulnerable, data, cookie, tamper, target_os, web_root, tmp_path) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params)
        conn.commit()

    # Mark injection checker as True to indicate session contains injection data
    if not settings.INJECTION_CHECKER:
      settings.INJECTION_CHECKER = True

  except sqlite3.OperationalError as err_msg:
    err_msg = str(err_msg)[:1].upper() + str(err_msg)[1:] + "."
    err_msg += " Re-run with switch '--flush-session'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    checks.quit(filename, url, hard_exit=False)

  except sqlite3.DatabaseError:
    checks.error_loading_session_file()

"""
All stored shellshock findings for this URL, one (header, payload) pair per header - resumes everything at once, mirroring the core engine's LOAD_SESSION behavior instead of the technique-letter-keyed model the other 4 techniques use.
"""
def get_all_stored_shellshock(url, http_request_method):
  found = []
  if menu.options.ignore_session or menu.options.flush_session:
    return found
  try:
    table = table_name(url) + "_ip"
    with _session_connection() as conn:
      if not table_exists(conn, table):
        return found
      clause, url_params = url_match(url)
      query = ("SELECT http_header, payload FROM \"" + table + "\" WHERE " + clause + " AND "
               "technique = ? AND http_request_method = ?;")
      cursor = conn.execute(query, url_params + ("shellshock injection technique", http_request_method))
      found = [(row[0], row[1]) for row in cursor.fetchall()]
    return found
  except Exception:
    return found

"""
Whether this URL already has any stored shellshock finding, regardless of header - skips re-asking to test for it.
"""
def has_stored_shellshock(url):
  if menu.options.ignore_session or menu.options.flush_session:
    return False
  try:
    table = table_name(url) + "_ip"
    with _session_connection() as conn:
      if not table_exists(conn, table):
        return False
      clause, url_params = url_match(url)
      query = "SELECT 1 FROM \"" + table + "\" WHERE " + clause + " AND technique = ? LIMIT 1;"
      cursor = conn.execute(query, url_params + ("shellshock injection technique",))
      return cursor.fetchone() is not None
  except Exception:
    return False

"""
Retrieve a summary string of all unique injection techniques that have been successfully applied
and stored in the session for the given URL.
"""
def applied_techniques(url, http_request_method): 
  techniques = []
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_ip"
      if table_exists(conn, table):
        clause, url_params = url_match(url)
        query = "SELECT technique FROM \"" + table + "\" WHERE " + clause + " AND http_request_method = ?;"
        cursor = conn.execute(query, url_params + (http_request_method,)).fetchall()
        for session in cursor:
          technique_info = session[0]
          letter = technique_letter(technique_info)
          if letter:
            techniques.append(letter)
        techniques = list(set(techniques))
        techniques = "".join(str(x) for x in techniques)
    return techniques
  except Exception:
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
    with _session_connection() as conn:
      table = table_name(url) + "_ip"
      if table_exists(conn, table):
        clause, url_params = url_match(url)
        query = "SELECT http_header, is_vulnerable FROM \"" + table + "\" WHERE " + clause + " AND http_request_method = ?;"
        cursor = conn.execute(query, url_params + (http_request_method,)).fetchall()
        for session in cursor:
          http_header = session[0]
          level = int(session[1])
    if http_header:
      if http_header == settings.COOKIE.lower():
        level = settings.COOKIE_INJECTION_LEVEL
      else:
        level = settings.HTTP_HEADER_INJECTION_LEVEL
    return level
  except Exception:
    settings.LOAD_SESSION = None
    return level


"""
Where the session file for this URL would live - settings.SESSION_FILE isn't set this early.
"""
def compute_expected_session_file(url):
  if menu.options.session_file:
    return menu.options.session_file
  output_dir = menu.options.output_dir or settings.OUTPUT_DIR
  host = _urllib.parse.urlparse(url).netloc.replace(":", "_")
  return os.path.join(output_dir, host, "session.db")

"""
Cheap, coarse (no parameter match yet) check for any stored injection point for this (host, method).
"""
def has_any_stored_technique(url, http_request_method):
  if menu.options.ignore_session or menu.options.flush_session:
    return False
  session_file = compute_expected_session_file(url)
  if not os.path.isfile(session_file):
    return False
  try:
    with _session_connection(session_file) as conn:
      table = table_name(url) + "_ip"
      if not table_exists(conn, table):
        return False
      cursor = conn.cursor()
      clause, url_params = url_match(url)
      query = "SELECT technique, injection_type FROM \"" + table + "\" WHERE " + clause + " AND http_request_method = ?;"
      cursor.execute(query, url_params + (http_request_method,))
      return any(technique_selection(*row)[0] and checks.technique_selected(*technique_selection(*row)) for row in cursor.fetchall())
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    return False

"""
Find a stored injection point matching the URL, parameter, and HTTP method, then restore its settings.
"""
def check_stored_injection_points(url, check_parameter, http_request_method):
  try:
    found = False
    vuln_parameter = check_parameter
    session_url = url
    table = table_name(url) + "_ip"

    # Ensure table name is safe (only alphanumeric + underscore)
    if not table.isidentifier():
      raise ValueError("Unsafe table name")

    with _session_connection() as conn:
      # Check if the table exists
      if not table_exists(conn, table):
        settings.LOAD_SESSION = None
        return url, check_parameter

      cursor = conn.cursor()

      # Fetch stored sessions for matching URL
      base_url = split_url(url)
      query = "SELECT * FROM \"" + table + "\" WHERE (url = ? OR url LIKE ? ESCAPE '\\');"
      cursor.execute(query, (base_url, escape_like(base_url) + "?%"))
      sessions = cursor.fetchall()

      for session in sessions:
        technique_info = session[2]
        vuln_param = session[6]
        http_header = session[12]
        stored_method = session[13]

        # A stored point only applies to the exact parameter/method being tested.
        if check_parameter not in (vuln_param, http_header) or stored_method != http_request_method:
          continue

        technique, technique_is_eval = technique_selection(technique_info, session[3])

        if technique and checks.technique_selected(technique, technique_is_eval):
          found = True
          # Prefer more specific vulnerable parameter (e.g. HTTP header), if available
          vuln_parameter = vuln_param or http_header
          session_url = session[1]

          cookie = restore_option(session[20] if len(session) > 20 else None, settings.USER_APPLIED_COOKIE, "cookie")
          if cookie:
            if settings.INJECT_TAG in cookie:
              settings.COOKIE_INJECTION = True
            menu.options.cookie = cookie

    if found:
      settings.LOAD_SESSION = True
      settings.INJECTION_CHECKER = True
      # Said where it happens, as the '--ignore-session' switch says the opposite where it happens.
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Resuming the injection point for '" + str(vuln_parameter) + "' from the stored session."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      if not settings.MULTI_TARGETS and vuln_parameter not in settings.TESTABLE_PARAMETERS_LIST:
        settings.TESTABLE_PARAMETERS_LIST.append(vuln_parameter)
      return session_url, vuln_parameter

    settings.LOAD_SESSION = False
    return url, check_parameter

  except Exception:
    settings.LOAD_SESSION = None
    return url, check_parameter


"""
Fetch all stored injection points in one query, keyed by technique.
"""
def load_stored_techniques(url, check_parameter, http_request_method):
  stored = {}
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_ip"
      if not table_exists(conn, table):
        return stored

      cursor = conn.cursor()
      base_url = split_url(url)
      query = "SELECT * FROM \"" + table + "\" WHERE (url = ? OR url LIKE ? ESCAPE '\\') AND http_request_method = ?;"
      cursor.execute(query, (base_url, escape_like(base_url) + "?%", http_request_method))

      for session in cursor.fetchall():
        row = session[1:]
        technique, vuln_parameter, http_header = row[1], row[5], row[11]
        letter, letter_is_eval = technique_selection(technique, row[2])
        if check_parameter not in (vuln_parameter, http_header) or not letter:
          continue
        # A technique this run was not asked to test is not resumed, nor reported as resumed.
        if not checks.technique_selected(letter, letter_is_eval):
          continue
        stored[technique] = row
    return {_: stored[_] for _ in settings.TECHNIQUE_ORDER if _ in stored}
  except Exception:
    return stored

"""
Restore stored technique state and resume without querying the database again.
"""
def apply_stored_technique(row):
  (url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix,
   TAG, interpreter, payload, http_header, http_request_method, url_time_response,
   timesec, exec_time, output_length, is_vulnerable, data, cookie) = row[:20]
  # Older sessions (pre-tamper-column) won't have this field - default to "".
  tamper = row[20] if len(row) > 20 else ""
  # Older sessions (pre-target_os-column) won't have this field either.
  target_os = row[21] if len(row) > 21 else None
  # Nor will they have the document root the stored payload writes into, or the temporary
  # directory a finding that fell back to one used.
  web_root = row[23] if len(row) > 23 else None
  tmp_path = row[24] if len(row) > 24 else None

  if http_header:
    settings.HTTP_HEADER = http_header
  cookie = restore_option(cookie, settings.USER_APPLIED_COOKIE, "cookie")
  if cookie:
    menu.options.cookie = cookie
  data = restore_option(data, settings.USER_APPLIED_DATA, "POST data")
  if data:
    settings.IGNORE_USER_DEFINED_POST_DATA = False
    menu.options.data = data
  if settings.INJECTION_LEVEL != is_vulnerable:
    settings.INJECTION_LEVEL = int(is_vulnerable)
  if tamper:
    if menu.options.tamper and menu.options.tamper != tamper:
      warn_msg = ("The stored session was found using tamper script(s) '" + tamper + "', "
                  "which differs from the '--tamper' value provided now ('" + menu.options.tamper +
                  "'). Using the stored value to replay this technique consistently.")
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    menu.options.tamper = tamper
  if target_os and target_os != "None":
    if menu.options.os and menu.options.os.lower() != target_os:
      warn_msg = ("The stored session was found against target OS '" + target_os.title() + "', "
                  "which differs from the '--os' value provided now ('" + menu.options.os.title() +
                  "'). Using the stored value to replay this technique consistently.")
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    # Stored as text, restored as one of the two values the rest of the code compares against.
    settings.TARGET_OS = settings.OS.WINDOWS if target_os.lower() == settings.OS.WINDOWS else settings.OS.UNIX
  if web_root and web_root != "None":
    # The stored payload writes to the document root it was found with, spelled out inside it.
    if settings.USER_APPLIED_WEB_ROOT:
      announce_replay_conflict(web_root, menu.options.web_root, "document root", "--web-root")
    settings.WEB_ROOT = web_root
  if tmp_path and tmp_path != "None":
    # Likewise the temporary directory, for a finding that fell back to one.
    if settings.USER_APPLIED_TMP_PATH:
      announce_replay_conflict(tmp_path, menu.options.tmp_path, "temporary directory", "--tmp-path")
    menu.options.tmp_path = tmp_path
  """
  The interpreter and the delay are stored as they were used, and the replay below is handed both.
  Neither is taken from the command line again, so a run asking for something else is told so.
  """
  if settings.USER_APPLIED_INTERPRETER:
    announce_replay_conflict(interpreter or "none", menu.options.interpreter, "interpreter", "--interpreter")
  if settings.USER_APPLIED_TIMESEC and timesec:
    announce_replay_conflict(timesec, int(menu.options.timesec), "delay", "--time-sec")

  return (url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix,
          TAG, interpreter, payload, http_request_method, url_time_response, timesec,
          exec_time, output_length, is_vulnerable)

"""
Check whether the output file for a stored technique has already been deleted from the target.
"""
def check_file_deleted(url, technique, vuln_parameter, http_request_method):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_ip"
      if not table_exists(conn, table):
        return False
      cursor = conn.cursor()
      clause, url_params = url_match(url)
      query = ("SELECT file_deleted FROM \"" + table + "\" WHERE " + clause + " AND technique = ? AND "
               "(vuln_parameter = ? OR http_header = ?) AND http_request_method = ? LIMIT 1;")
      cursor.execute(query, url_params + (technique, vuln_parameter, vuln_parameter, http_request_method))
      row = cursor.fetchone()
      return bool(row and row[0])
  except Exception:
    return False

"""
Persist that the output file for a stored technique has been deleted from the target.
"""
def mark_file_deleted(url, technique, vuln_parameter, http_request_method):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_ip"
      if not table_exists(conn, table):
        return
      clause, url_params = url_match(url)
      conn.execute("UPDATE \"" + table + "\" SET file_deleted = '1' WHERE " + clause + " AND technique = ? AND "
                   "(vuln_parameter = ? OR http_header = ?) AND http_request_method = ?;",
                   url_params + (technique, vuln_parameter, vuln_parameter, http_request_method))
      conn.commit()
  except Exception:
    pass

"""
Store the output of a successfully executed command for a given URL and vulnerable parameter in the session database.
Command and output are base64-encoded for storage.
"""
def store_cmd(url, cmd, shell, vuln_parameter):
  if all(type(_) is str for _ in (url, cmd, shell, vuln_parameter)):
    try:
      with _session_connection() as conn:
        table = table_name(url) + "_ir"
        conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" "
                     "(cmd VARCHAR, output VARCHAR, vuln_parameter VARCHAR);")
        conn.execute("INSERT INTO \"" + table + "\" (cmd, output, vuln_parameter) VALUES (?, ?, ?)",
                     (base64.b64encode(cmd.encode(settings.DEFAULT_CODEC)).decode(),
                      base64.b64encode(shell.encode(settings.DEFAULT_CODEC)).decode(),
                      vuln_parameter))
        conn.commit()
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as err_msg:
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
    with _session_connection() as conn:
      table = table_name(url) + "_ir"
      encoded_cmd = base64.b64encode(cmd.encode(settings.DEFAULT_CODEC)).decode()
      query = "SELECT output FROM \"" + table + "\" WHERE cmd = ? AND vuln_parameter = ?;"
      cursor = conn.execute(query, (encoded_cmd, vuln_parameter)).fetchall()
    for session in cursor:
      output = base64.b64decode(session[0])
    try:
      return output.decode(settings.DEFAULT_CODEC)
    except AttributeError:
      return output
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    pass


"""
Store whether the target was found to be WAF/IPS-protected, so a resumed
session against the same target doesn't need to redo the heuristic probe.
"""
def import_waf_status(url, waf_enabled):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_waf"
      conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" (waf_enabled VARCHAR);")
      conn.execute("DELETE FROM \"" + table + "\";")
      conn.execute("INSERT INTO \"" + table + "\" (waf_enabled) VALUES (?)", (str(waf_enabled),))
      conn.commit()
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    pass

"""
Retrieve a previously stored WAF/IPS detection result for the given target.
Returns None if nothing is stored yet.
"""
def check_stored_waf_status(url):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_waf"
      if not table_exists(conn, table):
        return None
      row = conn.execute("SELECT waf_enabled FROM \"" + table + "\" LIMIT 1;").fetchone()
      return row[0] == "True" if row else None
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    return None

"""
Restore a WAF/IPS finding from a previous session, before testing starts.
"""
def restore_waf_status(url):
  # A run that asked for no heuristics gets none, cached or otherwise: what is restored here was
  # learned by a heuristic probe, and it goes on to decide how the tamper scripts behave.
  if menu.options.skip_waf or menu.options.ignore_session or menu.options.flush_session \
     or menu.options.skip_heuristics:
    return
  if not settings.WAF_ENABLED and check_stored_waf_status(url):
    settings.WAF_ENABLED = True
    info_msg = "Previous session heuristics detected that the target is protected by some kind of WAF/IPS."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Store a confirmed testable-value placeholder, so a resumed session can reuse
it instead of re-probing whether the parameter's real value is required.
"""
def import_testable_value_status(url, vuln_parameter, http_request_method, placeholder):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_tv"
      conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" (vuln_parameter VARCHAR, http_request_method VARCHAR, placeholder VARCHAR);")
      conn.execute("DELETE FROM \"" + table + "\" WHERE vuln_parameter = ? AND http_request_method = ?;", (vuln_parameter, http_request_method))
      conn.execute("INSERT INTO \"" + table + "\" (vuln_parameter, http_request_method, placeholder) VALUES (?, ?, ?)", (vuln_parameter, http_request_method, placeholder))
      conn.commit()
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    pass

"""
Retrieve a previously confirmed testable-value placeholder. Returns None if nothing is stored.
"""
def check_stored_testable_value(url, vuln_parameter, http_request_method):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_tv"
      if not table_exists(conn, table):
        return None
      row = conn.execute("SELECT placeholder FROM \"" + table + "\" WHERE vuln_parameter = ? AND http_request_method = ?;", (vuln_parameter, http_request_method)).fetchone()
      return row[0] if row else None
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    return None

"""
Re-apply the stored placeholder to URL/data/prefix; the stored prefix still has the original value.
"""
def reapply_testable_value(url, vuln_parameter, http_request_method, prefix=None):
  placeholder = check_stored_testable_value(url, vuln_parameter, http_request_method)
  if not placeholder:
    return (url, prefix) if prefix is not None else url
  # Use the reloaded row's value; settings.TESTABLE_VALUE may already be a placeholder.
  tag_pattern = r'([^&=]*)' + re.escape(settings.INJECT_TAG)
  if menu.options.data and settings.INJECT_TAG in menu.options.data:
    match = re.search(tag_pattern, menu.options.data)
    if match and match.group(1) != placeholder:
      menu.options.data = menu.options.data.replace(match.group(1) + settings.INJECT_TAG, placeholder + settings.INJECT_TAG)
      settings.TESTABLE_VALUE = placeholder
      settings.TESTABLE_VALUE_OPTIMIZED = True
  elif settings.INJECT_TAG in url:
    match = re.search(tag_pattern, url)
    if match and match.group(1) != placeholder:
      url = url.replace(match.group(1) + settings.INJECT_TAG, placeholder + settings.INJECT_TAG)
      settings.TESTABLE_VALUE = placeholder
      settings.TESTABLE_VALUE_OPTIMIZED = True
  if prefix is not None and prefix and prefix != placeholder:
    prefix = placeholder
    settings.TESTABLE_VALUE_OPTIMIZED = True
  return (url, prefix) if prefix is not None else url

"""
Save valid authentication credentials (e.g. username and password) discovered during testing into the session database.
"""
def import_valid_credentials(url, authentication_type, admin_panel, username, password):
  try:
    with _session_connection() as conn:
      table = table_name(url) + "_creds"
      conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" "
                   "(id INTEGER PRIMARY KEY, url VARCHAR, authentication_type VARCHAR, admin_panel VARCHAR, "
                   "username VARCHAR, password VARCHAR);")
      cursor = conn.execute("SELECT 1 FROM \"" + table + "\" WHERE url = ? AND authentication_type = ? AND "
                             "admin_panel = ? AND username = ? AND password = ? LIMIT 1;",
                             (url, authentication_type, admin_panel, username, password))
      if cursor.fetchone() is None:
        conn.execute("INSERT INTO \"" + table + "\" (url, authentication_type, admin_panel, username, password) VALUES (?, ?, ?, ?, ?)",
                     (url, authentication_type, admin_panel, username, password))
        conn.commit()
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
    with _session_connection() as conn:
      table = table_name(url) + "_creds"
      clause, url_params = url_match(url)
      query = "SELECT username, password FROM \"" + table + "\" WHERE " + clause + " AND authentication_type = ?;"
      cursor = conn.execute(query, url_params + (authentication_type,)).fetchall()
    if cursor:
      return ":".join(cursor[0])
  except (sqlite3.OperationalError, sqlite3.DatabaseError):
    pass

# eof
