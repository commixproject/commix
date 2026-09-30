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
import json

from src.utils import settings
from src.core.parse import cmdline as menu
from src.thirdparty import six
from src.thirdparty.six.moves import urllib as _urllib

try:
  import yaml
except ImportError:
  yaml = None

"""
Targets described by an OpenAPI (Swagger) document.

A target that ships a description of itself has already said what a crawl would have to discover:
every endpoint it serves, the method each answers to, and the shape of what it expects. The document
is read here as a generator of requests rather than as a contract to check - one concrete request is
built per operation, and an operation that cannot be built is skipped with a word about it, so a
loose or partial description still yields what it can.
"""

MAX_REF_DEPTH = 25
EXAMPLE_MAX_DEPTH = 8
METHODS = ("get", "post", "put", "delete", "patch", "options", "head")
HEADER_NAME_REGEX = re.compile(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")

"""
The document, whichever of the two ways it is written in.
"""
def _load_spec(content):
  try:
    return json.loads(content)
  except ValueError:
    if yaml is None:
      err_msg = "The provided OpenAPI (Swagger) specification is not JSON, and the optional 'pyyaml' "
      err_msg += "module needed for the YAML form is not available."
      raise ValueError(err_msg)
    try:
      return yaml.safe_load(content)
    except Exception as err:
      raise ValueError("it is neither valid JSON nor valid YAML (" + str(err) + ")")

"""
What a '$ref' points at, followed until it names something real.
"""
def _resolve(spec, node, seen=None, depth=0):
  seen = seen or set()
  if isinstance(node, dict) and "$ref" in node:
    ref = node["$ref"]
    # Only a string names anything; anything else is a malformed reference and stands for nothing.
    if not isinstance(ref, six.string_types):
      return {}
    if ref in seen or depth > MAX_REF_DEPTH:
      return {}
    if not ref.startswith("#/"):
      warn_msg = "Skipping the external reference '" + ref + "', which is not part of this document."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return {}
    seen = seen | set([ref])
    current = spec
    for part in ref[2:].split("/"):
      part = part.replace("~1", "/").replace("~0", "~")
      if not isinstance(current, dict) or part not in current:
        warn_msg = "Skipping the reference '" + ref + "', which points at nothing in this document."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        return {}
      current = current[part]
    return _resolve(spec, current, seen, depth + 1)
  return node

"""
A value of the shape the document says to send.

What is wanted here is something to inject into, not something to validate: a value the target will
accept far enough to run what it was given. What the document itself offers is taken first, and only
where it offers nothing is one made up from the type.

Worked out once per reference and kept, because a large description reuses the same shapes across
thousands of operations, and made afresh each time the work would grow with the square of them.
"""
def _example(spec, schema, seen=None, depth=0, cache=None):
  seen = seen or set()
  if cache is None:
    cache = {}
  if depth > EXAMPLE_MAX_DEPTH:
    return "1"
  ref = schema.get("$ref") if isinstance(schema, dict) else None
  if not isinstance(ref, six.string_types):
    ref = None
  if ref is not None and ref in cache:
    return cache[ref]

  schema = _resolve(spec, schema or {}, seen, depth)
  if not isinstance(schema, dict):
    return "1"

  value = None
  if "example" in schema:
    value = schema["example"]
  elif "const" in schema:
    value = schema["const"]
  elif "default" in schema:
    value = schema["default"]
  elif isinstance(schema.get("examples"), list) and schema["examples"]:
    value = schema["examples"][0]
  elif isinstance(schema.get("enum"), list) and schema["enum"]:
    value = schema["enum"][0]
  else:
    combinator = next((_ for _ in ("allOf", "oneOf", "anyOf") if schema.get(_)), None)
    if combinator:
      if combinator == "allOf":
        merged = {}
        for sub in schema[combinator]:
          part = _example(spec, sub, seen, depth + 1, cache)
          if isinstance(part, dict):
            merged.update(part)
        value = merged if merged else _example(spec, schema[combinator][0], seen, depth + 1, cache)
      else:
        value = _example(spec, schema[combinator][0], seen, depth + 1, cache)
    else:
      declared = schema.get("type")
      # A type may be given as a list, where what is wanted is the one that is not the absence of one.
      if isinstance(declared, list):
        declared = next((_ for _ in declared if _ != "null"), None)
      if declared == "object" or ("properties" in schema and not declared):
        properties = schema.get("properties")
        value = dict((name, _example(spec, sub, seen, depth + 1, cache))
                     for name, sub in (properties if isinstance(properties, dict) else {}).items())
      elif declared == "array":
        value = [_example(spec, schema.get("items") or {}, seen, depth + 1, cache)]
      elif declared in ("integer", "number"):
        value = 1
      elif declared == "boolean":
        value = True
      elif declared == "string":
        formats = {"uuid": "11111111-1111-1111-1111-111111111111", "date": "2020-01-01",
                   "date-time": "2020-01-01T00:00:00Z", "email": "a@b.co", "byte": "MQ=="}
        value = formats.get(schema.get("format"), "1")
      else:
        value = "1"

  if ref is not None:
    cache[ref] = value
  return value

"""
A value as it goes into a URL or a header, rather than as the document holds it.
"""
def _scalar(value):
  if isinstance(value, bool):
    return "true" if value else "false"
  if isinstance(value, (int, float)):
    return str(value)
  if isinstance(value, six.string_types):
    return value
  try:
    return json.dumps(value)
  except TypeError:
    return str(value)

NO_EXAMPLE = object()

"""
A value the document states outright, which is worth more than one worked out from the shape.
"""
def _explicit_example(spec, container):
  if not isinstance(container, dict):
    return NO_EXAMPLE
  # Given as nothing is given as nothing, and the shape is asked instead.
  if container.get("example") is not None:
    return container["example"]
  examples = container.get("examples")
  if isinstance(examples, dict) and examples:
    first = _resolve(spec, next(iter(examples.values())))
    if isinstance(first, dict) and first.get("value") is not None:
      return first["value"]
  return NO_EXAMPLE

# A marker the document supplied is not a marker this run put there, so it is taken back out.
def _no_mark(text):
  return text.replace(settings.CUSTOM_INJECTION_MARKER_CHAR, "")

# What cannot legally appear in a header, so that a document cannot write headers of its own.
def _header_clean(text):
  return re.sub(r"[\x00-\x1f\x7f]", "", text)

# Encoded so that a value cannot end the parameter it is part of and start another.
def _url_safe(value, safe=""):
  try:
    if isinstance(value, six.text_type):
      value = value.encode(settings.DEFAULT_CODEC)
    elif not isinstance(value, bytes):
      value = str(value)
    return _urllib.parse.quote(value, safe=safe)
  except Exception:
    return value

"""
Where the described endpoints actually live.

A document may say so itself, or say it only in part, or not at all - in which case the address it
was fetched from is what its paths hang off.
"""
def _base_url(spec, origin=None, servers=None):
  base_path = spec.get("basePath") if isinstance(spec.get("basePath"), six.string_types) else ""
  if base_path and not base_path.startswith("/"):
    base_path = "/" + base_path
  servers = servers if servers is not None else spec.get("servers")
  if isinstance(servers, list) and servers and isinstance(servers[0], dict):
    url = servers[0].get("url")
    url = url if isinstance(url, six.string_types) else ""
    variables = servers[0].get("variables")
    if isinstance(variables, dict):
      for name, meta in variables.items():
        meta = meta if isinstance(meta, dict) else {}
        default = meta.get("default")
        # Where no default is given, a value the document does allow beats one invented here.
        if default is None:
          enum = meta.get("enum")
          default = enum[0] if isinstance(enum, list) and enum else "1"
        url = url.replace("{" + name + "}", str(default))
    # An address given in full is used as it stands, host and all.
    if re.match(r"(?i)[a-z][a-z0-9+.-]*://", url):
      return url.rstrip("/")
    return ((origin.rstrip("/") if origin else "") + "/" + url.lstrip("/")).rstrip("/")
  if spec.get("host"):
    schemes = spec.get("schemes")
    scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
    return scheme + "://" + spec["host"] + base_path.rstrip("/")
  return (origin.rstrip("/") if origin else "") + base_path.rstrip("/")

"""
Every request the document describes, as this run would send it.

Handed back as (url, method, data, headers, cookie), where a path, header or cookie value carries the
marker that makes it a place to test - those are where a described API puts the values it acts on,
and nothing else would find them.
"""
def openapi_targets(content, origin=None, tags=None):
  tag_set = set(tags) if tags else None

  spec = _load_spec(content)
  if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict) or not spec.get("paths"):
    raise ValueError("it describes no paths")

  try:
    root_base = _base_url(spec, origin)
  except Exception:
    root_base = origin.rstrip("/") if isinstance(origin, six.string_types) else ""
  is_v2 = "swagger" in spec and "openapi" not in spec
  targets = []
  cache = {}

  for path, item in (spec.get("paths") or {}).items():
    item = _resolve(spec, item)
    if not isinstance(item, dict):
      continue
    shared = item.get("parameters") or []
    for method, operation in item.items():
      if str(method).lower() not in METHODS or not isinstance(operation, dict):
        continue
      if tag_set is not None and not (tag_set & set(_ for _ in (operation.get("tags") or []) if isinstance(_, six.string_types))):
        continue
      try:
        # An operation may say where it lives, and what it says outranks what the path or the document says.
        own_servers = operation.get("servers") or item.get("servers")
        base = root_base
        if own_servers:
          try:
            base = _base_url(spec, origin, own_servers)
          except Exception:
            base = root_base

        # The same parameter named twice is the operation's version of it.
        params, seen = [], {}
        for raw in ((shared if isinstance(shared, list) else []) + (operation.get("parameters") or [])):
          resolved = _resolve(spec, raw)
          if isinstance(resolved, dict) and resolved.get("name"):
            key = (resolved.get("in"), resolved.get("name"))
            if key in seen:
              params[seen[key]] = resolved
              continue
            seen[key] = len(params)
          params.append(resolved)

        url_path = path if isinstance(path, six.string_types) else str(path)
        query, headers, form, cookies = [], [], [], []

        for param in params:
          if not isinstance(param, dict):
            continue
          location, name = param.get("in"), param.get("name")
          if not name:
            continue
          if not isinstance(name, six.string_types):
            name = str(name)
          explicit = _explicit_example(spec, param)
          if explicit is not NO_EXAMPLE:
            value = _scalar(explicit)
          else:
            schema = param.get("schema") or {"type": param.get("type", "string")}
            value = _scalar(_example(spec, schema, cache=cache))
          if location == "path":
            # A value in the path is where a described API carries what it acts on, so it is marked.
            url_path = url_path.replace("{" + name + "}", _url_safe(value) + settings.CUSTOM_INJECTION_MARKER_CHAR)
          elif location == "query":
            query.append(_url_safe(name, "[]") + "=" + _url_safe(value))
          elif location == "header":
            header_name = _header_clean(name)
            if header_name and HEADER_NAME_REGEX.match(header_name):
              headers.append((header_name, _header_clean(_no_mark(value)) + settings.CUSTOM_INJECTION_MARKER_CHAR))
          elif location == "cookie":
            cookie_name = _header_clean(name)
            if cookie_name and HEADER_NAME_REGEX.match(cookie_name):
              # Nothing that separates one cookie from the next, so the document cannot add any.
              cookie_value = re.sub(r"[;,\s]", "", _header_clean(_no_mark(value)))
              cookies.append(cookie_name + "=" + cookie_value + settings.CUSTOM_INJECTION_MARKER_CHAR)
          elif location == "formData":
            form.append(_url_safe(name, "[]") + "=" + _url_safe(value))

        # What the path itself is written with, so a literal cannot end the URL early.
        url_path = url_path.replace(" ", "%20").replace("?", "%3F").replace("#", "%23")
        if url_path and not url_path.startswith("/"):
          url_path = "/" + url_path

        url = base + url_path
        if query:
          url += "?" + "&".join(query)

        # Anything still written as a placeholder was never defined, and stands for a value.
        url = re.sub(r"\{[^}]+\}", "1", url)

        if not re.match(r"(?i)[a-z][a-z0-9+.-]*://", url):
          warn_msg = "Skipping the '" + str(method).upper() + " " + str(path) + "' operation, which resolves to no "
          warn_msg += "address - fetch the specification by URL, or give a base with '--openapi-base'."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          continue

        data = None
        body = _resolve(spec, operation.get("requestBody") or {})
        described = body.get("content") if isinstance(body, dict) else None
        if isinstance(described, dict) and described:
          media_types = [_ for _ in described if isinstance(_, six.string_types)]
          picked = next((_ for _ in media_types if _ == "application/json" or _.endswith("+json") or "json" in _), None) \
                   or ("application/x-www-form-urlencoded" if "application/x-www-form-urlencoded" in media_types else None) \
                   or (media_types[0] if media_types else None)
          if picked:
            media_type = described[picked] if isinstance(described[picked], dict) else {}
            example = _explicit_example(spec, media_type)
            if example is NO_EXAMPLE:
              example = _example(spec, media_type.get("schema") or {}, cache=cache)
            if "json" in picked:
              data = _no_mark(json.dumps(example, default=str))
              headers.append((settings.CONTENT_TYPE, "application/json"))
            elif picked == "application/x-www-form-urlencoded" and isinstance(example, dict):
              data = "&".join(_url_safe(name, "[]") + "=" + _url_safe(_scalar(value)) for name, value in example.items())
              headers.append((settings.CONTENT_TYPE, "application/x-www-form-urlencoded"))
            elif isinstance(example, six.string_types):
              # A body with no parameters of its own is tested whole.
              data = _no_mark(example) + settings.CUSTOM_INJECTION_MARKER_CHAR
              headers.append((settings.CONTENT_TYPE, picked))
            else:
              if settings.VERBOSITY_LEVEL != 0:
                debug_msg = "Not building a '" + picked + "' body for the '" + str(method).upper() + " " + str(path) + "' operation."
                settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        elif isinstance(operation.get("parameters"), list) or is_v2:
          for param in params:
            if isinstance(param, dict) and param.get("in") == "body":
              example = _example(spec, param.get("schema") or {}, cache=cache)
              data = _no_mark(json.dumps(example, default=str))
              headers.append((settings.CONTENT_TYPE, "application/json"))

        if data is None and form:
          data = "&".join(form)
          headers.append((settings.CONTENT_TYPE, "application/x-www-form-urlencoded"))

        targets.append((url, str(method).upper(), data, headers or None, "; ".join(cookies) if cookies else None))
      except Exception as err:
        warn_msg = "Skipping the '" + str(method).upper() + " " + str(path) + "' operation (" + str(err) + ")."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  return targets

"""
The document itself, from wherever it was pointed at.
"""
def _read_specification():
  location = menu.options.openapi
  if re.match(r"(?i)\Ahttps?://", location):
    info_msg = "Fetching the OpenAPI (Swagger) specification from '" + location + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    try:
      response = _urllib.request.urlopen(location, timeout=settings.TIMEOUT)
      content = response.read()
    except Exception as err:
      err_msg = "Unable to fetch the specification from '" + location + "' (" + str(err) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    if isinstance(content, bytes):
      content = content.decode(settings.DEFAULT_CODEC, errors="replace")
    # Fetched from somewhere, so that somewhere is what its own relative addresses hang off.
    origin = None
    matched = re.match(r"(?i)(https?://[^/]+)", location)
    if matched:
      origin = matched.group(1)
    return content, origin

  location = os.path.expanduser(location)
  if not os.path.isfile(location):
    err_msg = "It seems the '" + location + "' file does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  if os.stat(location).st_size == 0:
    err_msg = "It seems the '" + location + "' file is empty."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  info_msg = "Parsing the OpenAPI (Swagger) specification from '" + os.path.split(location)[1] + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  with open(location, encoding="utf-8-sig") as spec_file:
    return spec_file.read(), None

"""
Every operation the specification describes, made into the targets the rest of the run tests.
"""
def openapi_parser():
  from src.core.parse import request

  if menu.options.method:
    warn_msg = "The '--method' option overrides the method every operation says it answers to."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  content, origin = _read_specification()
  # What was given by hand says where the endpoints are, over anything the document works out itself.
  if menu.options.openapi_base:
    origin = menu.options.openapi_base.rstrip("/")

  tags = None
  if menu.options.openapi_tags:
    tags = [_.strip() for _ in re.split(r"[,;]", menu.options.openapi_tags) if _.strip()]
    if tags:
      info_msg = "Restricting extraction to the operations tagged: " + ", ".join(tags) + "."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  try:
    described = openapi_targets(content, origin, tags)
  except ValueError as err:
    err_msg = "Unable to parse the OpenAPI (Swagger) specification (" + str(err) + ")."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # An API that says it expects to be authenticated, tested without anything to authenticate with,
  # answers every request the same way and is reported as testing nothing.
  if re.search(r"(?i)securitySchemes|securityDefinitions", content) and \
     not any((menu.options.auth_type, menu.options.auth_cred)) and \
     not (menu.options.headers and "authorization" in menu.options.headers.lower()) and \
     not (menu.options.cookie):
    warn_msg = "The specification declares authentication, and none was provided. Requests are likely "
    warn_msg += "to be refused - see '--auth-type'/'--auth-cred', '--cookie' or '--headers'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  targets, mutating = [], 0
  for url, method, data, headers, cookie in described:
    if menu.options.scope and not re.search(menu.options.scope, url, re.I):
      settings.SKIPPED_OUT_OF_SCOPE.append(url)
      continue
    if method not in ("GET", "HEAD", "OPTIONS"):
      mutating += 1
    raw_headers = settings.END_LINE.LF.join(name + ": " + value for name, value in (headers or []))
    targets.append({
      "url" : url,
      "method" : method,
      "data" : data or "",
      "host" : None,
      "agent" : None,
      "cookie" : cookie,
      "referer" : None,
      "auth_type" : None,
      "auth_cred" : None,
      "headers" : raw_headers,
      "raw_headers" : raw_headers
    })

  if not targets:
    warn_msg = "No usable target was derived from the specification."
    if not menu.options.openapi_base:
      warn_msg += " Where it names no host of its own, fetch it by URL or give a base with '--openapi-base'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  info_msg = "Derived " + str(len(targets)) + " target" + "s"[len(targets) == 1:] + " from the specification."
  if settings.SKIPPED_OUT_OF_SCOPE:
    info_msg += " Skipped " + str(len(settings.SKIPPED_OUT_OF_SCOPE)) + " out of scope."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  # Said plainly, because what is about to be sent is not all reading: these change what is there.
  if mutating:
    warn_msg = str(mutating) + " of them answer to a method that changes state (POST, PUT, PATCH, DELETE). "
    warn_msg += "Testing those may create, alter or remove data on the target."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  settings.MULTI_REQUEST_TARGETS = targets
  request.apply_target(targets[0])
  return targets

# eof
