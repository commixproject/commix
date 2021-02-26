#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""
import re
import sys
import tempfile
from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.core.requests import headers
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup

SITEMAP_LOC = []
HREF_LIST = []
SKIPPED_URLS = 0

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
Do a request to target URL.
"""
def request(url):
  global SKIPPED_URLS
  try:
    # Check if defined POST data
    if menu.options.data:
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
      request = _urllib.request.Request(url)
    headers.do_check(request)
    headers.check_http_traffic(request)
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    return response
  except _urllib.error.URLError as err_msg:
    err_msg = str(err_msg) + " - Skipping " + str(url) 
    print(settings.print_critical_msg(err_msg))
    SKIPPED_URLS += 1


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
      SITEMAP_LOC.append(url)
      if url.endswith(".xml") and "sitemap" in url.lower():
        while True:
          warn_msg = "A sitemap recursion detected."
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
    return SITEMAP_LOC
  except:
    pass

"""
Grab the crawled hrefs.
"""
def crawling(url):
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
      href = tag.get("href") if hasattr(tag, "get") else tag.group("href")
      if href:
        href = _urllib.parse.urljoin(url, href)
        if _urllib.parse.urlparse(url).netloc in href:
          if not re.search(r"\?(v=)?\d+\Z", href) and not \
          re.search(r"(?i)\.(js|css)(\?|\Z)", href) and \
          href.split('.')[-1].lower() not in settings.CRAWL_EXCLUDE_EXTENSIONS:
            if request(href): 
              HREF_LIST.append(href)
    if len(HREF_LIST) != 0:
      return list(set(HREF_LIST))
    else:
      if not settings.VERBOSITY_LEVEL >= 2:
        print("")
      warn_msg = "No usable links found."
      print(settings.print_warning_msg(warn_msg))
      raise SystemExit()
  except (UnicodeEncodeError, ValueError) as e:  # for non-HTML files and non-valid links
    pass

"""
The crawing process.
"""
def do_process(url):
  try:
    crawled_href = []
    for url in crawling(url):
      crawled_href.append(url)
    return crawled_href
  except TypeError:
    pass

"""
The main crawler.
"""
def crawler(url):
  if menu.options.crawldepth > 0:
    menu.options.DEFAULT_CRAWLDEPTH_LEVEL = menu.options.crawldepth
  if not menu.options.sitemap_url:
    if menu.options.DEFAULT_CRAWLDEPTH_LEVEL > 2:
      err_msg = "Depth level '" + str(menu.options.DEFAULT_CRAWLDEPTH_LEVEL) + "' is not a valid."  
      print(settings.print_error_msg(err_msg))
      raise SystemExit()
    info_msg = "Starting crawler and searching for "
    info_msg += "links with depth " + str(menu.options.DEFAULT_CRAWLDEPTH_LEVEL) + "." 
    print(settings.print_info_msg(info_msg))
  else:
    while True:
      if not menu.options.batch:
        question_msg = "Do you want to change the crawling depth level? [Y/n] > "
        message = _input(settings.print_question_msg(question_msg))
      else:
        message = ""
      if len(message) == 0:
         message = "Y"
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
        question_msg = "Please enter the crawling depth level (1-2) > "
        message = _input(settings.print_question_msg(question_msg))
        if len(message) == 0:
          message = 1
          break
        elif str(message) != "1" and str(message) != "2":
          err_msg = "Depth level '" + message + "' is not a valid answer."  
          print(settings.print_error_msg(err_msg))
          pass
        else: 
          menu.options.DEFAULT_CRAWLDEPTH_LEVEL = message
          break

  while True:
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
      sitemap_check = True
      break
  
  if sitemap_check:
    output_href = sitemap(url)
    if output_href is None :
      sitemap_check = False

  info_msg = "Checking "
  if sitemap_check:
    info_msg += "identified 'sitemap.xml' "
  info_msg += "for usable links (with GET parameters). "
  sys.stdout.write("\r" + settings.print_info_msg(info_msg))
  sys.stdout.flush()

  if not sitemap_check:
    output_href = do_process(url)
    if menu.options.DEFAULT_CRAWLDEPTH_LEVEL > 1:
      for url in output_href:
        output_href = do_process(url)
  if SKIPPED_URLS == 0:
    print("")

  info_msg = "Visited " + str(len(output_href)) + " link"+ "s"[len(output_href) == 1:] + "."
  print(settings.print_info_msg(info_msg))
  filename = store_crawling()
  valid_url_found = False
  try:
    url_num = 0
    valid_urls = []
    for check_url in output_href:
      if re.search(r"(.*?)\?(.+)", check_url):
        valid_url_found = True
        url_num += 1
        print(settings.print_info_msg("URL #" + str(url_num) + " - " + check_url) + "")
        if filename is not None:
          with open(filename, "a") as crawling_results:
            crawling_results.write(check_url + "\n")
        if not menu.options.batch:
          question_msg = "Do you want to use URL #" + str(url_num) + " to perform tests? [Y/n] > "
          message = _input(settings.print_question_msg(question_msg))
        else:
          message = ""
        if len(message) == 0:
           message = "Y"
        if message in settings.CHOICE_YES:
          return check_url
        elif message in settings.CHOICE_NO:
          if settings.VERBOSITY_LEVEL != 0:
            debug_msg = "Skipping '" + check_url + "'.\n"
            sys.stdout.write(settings.print_debug_msg(debug_msg))
          pass 
        elif message in settings.CHOICE_QUIT:
          raise SystemExit()
    raise SystemExit()
  except TypeError:
    pass
  if not valid_url_found:
    print(settings.FAIL_STATUS)
  raise SystemExit()

# eof