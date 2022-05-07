#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2022 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""
import re
import sys
import socket
import tempfile
from src.utils import menu
from src.utils import settings
from src.utils.common import extract_regex_result
from src.core.injections.controller import checks
from src.core.requests import headers
from socket import error as SocketError
from src.core.requests import redirection
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup

sitemap_loc = []
visited_hrefs = []
crawled_hrefs = []
new_crawled_hrefs = []

def store_crawling():
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to store crawling results to a temporary file "
      question_msg += "(for eventual further processing with other tools)? [y/N] > "
      message = _input(settings.print_question_msg(question_msg))
    else:
      message = ""
    if len(message) == 0:
       message = "n"
    if message in settings.CHOICE_YES:
      filename = tempfile.mkstemp(suffix=".txt")[1]
      info_msg = "Writing crawling results to a temporary file '" + str(filename) + "'."
      print(settings.print_info_msg(info_msg))
      return str(filename)
    elif message in settings.CHOICE_NO:
      return None
    elif message in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + message + "' is not a valid answer."  
      sys.stdout.write(settings.print_error_msg(err_msg))
      sys.stdout.flush()
      pass  

"""
Check for URLs in sitemap.xml.
"""
def sitemap(url):
  try:
    if not url.endswith(".xml"):
      if not url.endswith("/"):
        url = url + "/"
      url = _urllib.parse.urljoin(url, "sitemap.xml")
    response = request(url)
    content = checks.page_encoding(response, action="decode")
    for match in re.finditer(r"<loc>\s*([^<]+)", content or ""):
      url = match.group(1).strip()
      if url not in sitemap_loc:
        sitemap_loc.append(url)
      if url.endswith(".xml") and "sitemap" in url.lower():
        while True:
          warn_msg = "A sitemap recursion detected (" + url + ")."
          print(settings.print_warning_msg(warn_msg))
          if not menu.options.batch:
            question_msg = "Do you want to follow? [Y/n] > "
            message = _input(settings.print_question_msg(question_msg))
          else:
            message = ""
          if len(message) == 0:
             message = "Y"
          if message in settings.CHOICE_YES:
            sitemap(url)
            break
          elif message in settings.CHOICE_NO:
            break
          elif message in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            err_msg = "'" + message + "' is not a valid answer."  
            print(settings.print_error_msg(err_msg))
            pass
    return sitemap_loc
  except:
    if not menu.options.crawldepth:
      raise SystemExit()
    pass

"""
Store the identified (valid) hrefs.
"""
def store_hrefs(href, identified_hrefs, redirection):
  if href not in crawled_hrefs:
    if (settings.CRAWLING_DEPTH != 1 and href not in new_crawled_hrefs) or redirection:
      new_crawled_hrefs.append(href)
    identified_hrefs = True
    crawled_hrefs.append(href)
  return identified_hrefs
"""
Do a request to target URL.
"""
def request(url):
  try:
    # Check if defined POST data
    if menu.options.data:
      request = _urllib.request.Request(url, menu.options.data.encode(settings.DEFAULT_CODEC))
    else:
      request = _urllib.request.Request(url)
    headers.do_check(request)
    headers.check_http_traffic(request)
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    if not menu.options.ignore_redirects:
      href = redirection.do_check(request, url)
      if href != url:
        store_hrefs(href, identified_hrefs=True, redirection=True)
    return response
  except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.InvalidURL, Exception) as err_msg:
    if url not in settings.HREF_SKIPPED:
      settings.HREF_SKIPPED.append(url)
      settings.CRAWLED_SKIPPED_URLS += 1
      # if settings.CRAWLING_DEPTH == 1:
      if settings.TOTAL_OF_REQUESTS != 1:
        print(settings.SINGLE_WHITESPACE)
      checks.connection_exceptions(err_msg, url)
      if settings.VERBOSITY_LEVEL >= 2:
        print(settings.SINGLE_WHITESPACE)

"""
The crawing process.
"""
def do_process(url):
  identified_hrefs = False
  if settings.VERBOSITY_LEVEL >= 2:
    print(settings.SINGLE_WHITESPACE)
  else:
    if settings.CRAWLED_SKIPPED_URLS == 0:
      sys.stdout.write("\r")

  # Grab the crawled hrefs.
  try:
    response = request(url)
    content = checks.page_encoding(response, action="decode")
    match = re.search(r"(?si)<html[^>]*>(.+)</html>", content)
    if match:
      content = "<html>%s</html>" % match.group(1)
    soup = BeautifulSoup(content)
    tags = soup('a')
    if not tags:
      tags = []
      tags += re.finditer(r'(?i)\s(href|src)=["\'](?P<href>[^>"\']+)', content)
      tags += re.finditer(r'(?i)window\.open\(["\'](?P<href>[^)"\']+)["\']', content)

    for tag in tags:
      href = tag.get("href") if hasattr(tag, settings.HTTPMETHOD.GET) else tag.group("href")
      if href:
        href = _urllib.parse.urljoin(url, _urllib.parse.unquote(href))
        if  _urllib.parse.urlparse(url).netloc in href:
          if (extract_regex_result(r"\A[^?]+\.(?P<result>\w+)(\?|\Z)", href) or "") not in settings.CRAWL_EXCLUDE_EXTENSIONS:
            if not re.search(r"\?(v=)?\d+\Z", href) and \
            not re.search(r"(?i)\.(js|css)(\?|\Z)", href):
              identified_hrefs = store_hrefs(href, identified_hrefs, redirection=False)

    if len(crawled_hrefs) != 0:
      if identified_hrefs:
        if len(new_crawled_hrefs) != 0 and settings.CRAWLING_DEPTH != 1:
          return list(set(new_crawled_hrefs))
        return list(set(crawled_hrefs))
      return list("")
    else:
      warn_msg = "No usable links found."
      print(settings.print_warning_msg(warn_msg))
      raise SystemExit()
  except Exception as e:  # for non-HTML files and non-valid links
    pass
  
"""
The main crawler.
"""
def crawler(url):
  info_msg = "Starting crawler for target URL '" + url + "'"
  print(settings.print_info_msg(info_msg))
  response = request(url)
  if menu.options.sitemap_url:
    message = ""
    if not menu.options.crawldepth:
      while True:
        if not menu.options.batch:
          question_msg = "Do you want to enable crawler? [y/N] > "
          message = _input(settings.print_question_msg(question_msg))
        else:
          message = ""
        if len(message) == 0:
           message = "N"
        if message in settings.CHOICE_YES:
          menu.options.crawldepth = 1
          break  
        if message in settings.CHOICE_NO:
          break  
        elif message in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          err_msg = "'" + message + "' is not a valid answer."  
          print(settings.print_error_msg(err_msg))
          pass

    if menu.options.crawldepth:
      while True:
        if not menu.options.batch:
          question_msg = "Do you want to change the crawling depth level (" + str(menu.options.crawldepth) + ")? [y/N] > "
          message = _input(settings.print_question_msg(question_msg))
        else:
          message = ""
        if len(message) == 0:
           message = "N"
        if message in settings.CHOICE_YES or message in settings.CHOICE_NO:
          break  
        elif message in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          err_msg = "'" + message + "' is not a valid answer."  
          print(settings.print_error_msg(err_msg))
          pass
      # Change the crawling depth level.
      if message in settings.CHOICE_YES:
        while True:
          question_msg = "Please enter the crawling depth level: > "
          message = _input(settings.print_question_msg(question_msg))
          if len(message) == 0:
            message = 1
            break
          else: 
            menu.options.crawldepth = message
            break

  while True:
    sitemap_check = None
    if not menu.options.sitemap_url:
      if not menu.options.batch:
        question_msg = "Do you want to check target for "
        question_msg += "the existence of site's sitemap(.xml)? [y/N] > "
        message = _input(settings.print_question_msg(question_msg))
      else:
        message = ""
      if len(message) == 0:
         message = "n"
      if message in settings.CHOICE_YES:
        sitemap_check = True
        break
      elif message in settings.CHOICE_NO:
        sitemap_check = False
        break
      elif message in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        err_msg = "'" + message + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass
    else:
      message = "n"
      sitemap_check = True
      break
  if sitemap_check:
    output_href = sitemap(url)
    if output_href is None :
      sitemap_check = False

  if not sitemap_check:
    output_href = do_process(url)
    while settings.CRAWLING_DEPTH <= int(menu.options.crawldepth):
      info_msg = "Searching for usable "
      info_msg += "links with depth " + str(settings.CRAWLING_DEPTH) + "." 
      print(settings.print_info_msg(info_msg))
      if settings.CRAWLING_DEPTH != 1:
        output_href = new_crawled_hrefs
      link = 0
      if output_href is not None:
        for url in output_href: 
          link += 1
          if url not in visited_hrefs:
            visited_hrefs.append(url)
            do_process(url)
            info_msg = str(link)
            info_msg += "/" + str(len(output_href)) + " links visited." 
            sys.stdout.write("\r" + settings.print_info_msg(info_msg))
            sys.stdout.flush()
          if settings.VERBOSITY_LEVEL != 0:
            print(settings.SINGLE_WHITESPACE)
      if link != 0:
        print(settings.SINGLE_WHITESPACE)
      settings.CRAWLING_DEPTH += 1

  output_href = crawled_hrefs
  results = []
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to normalize crawling results? [Y/n] > "
      message = _input(settings.print_question_msg(question_msg))
    else:
      message = ""
    if len(message) == 0:
       message = "Y"
    if message in settings.CHOICE_YES:
      seen = set()
      for target in output_href:
        value = "%s%s%s" % (target, '&' if '?' in target else '?', target or "")
        match = re.search(r"/[^/?]*\?.+\Z", value)
        if match:
          key = re.sub(r"=[^=&]*", "=", match.group(0)).strip("&?")
          if '=' in key and key not in seen:
            results.append(target)
            seen.add(key)
      if len(results) != 0:
        output_href = results
      break
    elif message in settings.CHOICE_NO:
      break
    elif message in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + message + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
      pass
      
  return output_href

# eof