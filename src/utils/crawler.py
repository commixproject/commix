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
import re
import sys
import socket
import tempfile
from src.utils import menu
from src.utils import settings
from src.utils import common
from src.core.injections.controller import checks
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import proxy
from src.core.requests import redirection
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup


def init_global_vars():
  global crawled_hrefs
  crawled_hrefs = []
  global sitemap_loc
  sitemap_loc = []
  global visited_hrefs
  visited_hrefs = []
  global new_crawled_hrefs
  new_crawled_hrefs = []

"""
Change the crawling depth level.
"""
def set_crawling_depth():
  while True:
    message = "Do you want to change the crawling depth level (" + str(menu.options.crawldepth) + ")? [y/N] > "
    message = common.read_input(message, default="N", check_batch=True)
    if message in settings.CHOICE_YES or message in settings.CHOICE_NO:
      break
    elif message in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(message)
      pass

  # Change the crawling depth level.
  if message in settings.CHOICE_YES:
    while True:
      message = "Please enter the crawling depth level: > "
      message = common.read_input(message, default="1", check_batch=True)
      menu.options.crawldepth = message
      return


"""
Normalize crawling results.
"""
def normalize_results(output_href):
  results = []
  while True:
    message = "Do you want to normalize crawling results? [Y/n] > "
    message = common.read_input(message, default="Y", check_batch=True)
    if message in settings.CHOICE_YES:
      seen = set()
      for target in output_href:
        try:
          value = "%s%s%s" % (target, '&' if '?' in target else '?', target or "")
          match = re.search(r"/[^/?]*\?.+\Z", value)
          if match:
            key = re.sub(r"=[^=&]*", "=", match.group(0)).strip("&?")
            if '=' in key and key not in seen:
              results.append(target)
              seen.add(key)
        except TypeError:
          pass
      no_usable_links(results)
      return results
    elif message in settings.CHOICE_NO:
      no_usable_links(output_href)
      return output_href
    elif message in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(message)
      pass


"""
Store crawling results to a temporary file.
"""
def store_crawling(output_href):
  try:
    while True:
      message = "Do you want to store crawling results to a temporary file "
      message += "(for eventual further processing with other tools)? [y/N] > "
      message = common.read_input(message, default="N", check_batch=True)
      if message in settings.CHOICE_YES:
        filename = tempfile.mkstemp(suffix=settings.OUTPUT_FILE_EXT)[1]
        info_msg = "Writing crawling results to a temporary file '" + str(filename) + "'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as crawling_results:
          for url in output_href:
            crawling_results.write(str(url.encode(settings.DEFAULT_CODEC).decode()) + "\n")
        return
      elif message in settings.CHOICE_NO:
        return
      elif message in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(message)
        pass
  except:
    pass
    
"""
Check for URLs in sitemap.xml.
"""
def sitemap(url, http_request_method):
  try:
    if not url.endswith(".xml"):
      if not url.endswith("/"):
        url = url + "/"
      url = _urllib.parse.urljoin(url, settings.SITEMAP_XML_FILE)
    response = request(url, http_request_method)
    content = checks.page_encoding(response, action="decode")
    for match in re.finditer(r"<loc>\s*([^<]+)", content or ""):
      url = match.group(1).strip()
      if url not in sitemap_loc:
        sitemap_loc.append(url)
      if url.endswith(".xml") and "sitemap" in url.lower():
        while True:
          warn_msg = "A sitemap recursion detected (" + url + ")."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          message = "Do you want to follow? [Y/n] > "
          message = common.read_input(message, default="Y", check_batch=True)
          if message in settings.CHOICE_YES:
            sitemap(url, http_request_method)
            break
          elif message in settings.CHOICE_NO:
            break
          elif message in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(message)
            pass
    no_usable_links(sitemap_loc)
    return sitemap_loc
  except:
    if not menu.options.crawldepth:
      raise SystemExit()
    pass


"""
Store the identified (valid) hrefs.
"""
def store_hrefs(href, identified_hrefs, redirection):
  set(crawled_hrefs)
  set(new_crawled_hrefs)
  if href not in crawled_hrefs:
    if (settings.DEFAULT_CRAWLING_DEPTH != 1 and href not in new_crawled_hrefs) or redirection:
      new_crawled_hrefs.append(href)
    identified_hrefs = True
    crawled_hrefs.append(href)
  return identified_hrefs


"""
Do a request to target URL.
"""
def request(url, http_request_method):
  return requests.crawler_request(url, http_request_method)

"""
Enable crawler.
"""
def enable_crawler():
  message = ""
  if not settings.CRAWLING:
    while True:
      message = "Do you want to enable crawler? [y/N] > "
      message = common.read_input(message, default="N", check_batch=True)
      if message in settings.CHOICE_YES:
        menu.options.crawldepth = 1
        break
      if message in settings.CHOICE_NO:
        break
      elif message in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(message)
        pass
    set_crawling_depth()

"""
Check for the existence of site's sitemap
"""
def check_sitemap():
  while True:
    message = "Do you want to check target"+ ('', 's')[settings.MULTI_TARGETS] + " for "
    message += "the existence of site's sitemap(.xml)? [y/N] > "
    message = common.read_input(message, default="N", check_batch=True)
    if message in settings.CHOICE_YES:
      settings.SITEMAP_CHECK = True
      return
    elif message in settings.CHOICE_NO:
      settings.SITEMAP_CHECK = False
      return
    elif message in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(message)
      pass

"""
Check if no usable links found.
"""
def no_usable_links(crawled_hrefs):
  if len(crawled_hrefs) == 0:
    warn_msg = "No usable links found (with GET parameters)."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    if not settings.MULTI_TARGETS:
      raise SystemExit()

"""
The crawing process.
"""
def do_process(url, http_request_method):
  identified_hrefs = False
  if settings.CRAWLED_SKIPPED_URLS_NUM == 0 or settings.CRAWLED_URLS_NUM != 0:
    settings.print_data_to_stdout(settings.END_LINE.CR)
  # Grab the crawled hrefs.
  try:
    response = request(url, http_request_method)
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
        if _urllib.parse.urlparse(url).netloc in href:
          if (common.extract_regex_result(r"\A[^?]+\.(?P<result>\w+)(\?|\Z)", href) or "") not in settings.CRAWL_EXCLUDE_EXTENSIONS:
            if not re.search(r"\?(v=)?\d+\Z", href) and not re.search(r"(?i)\.(js|css)(\?|\Z)", href):
              if menu.options.crawl_exclude and re.search(menu.options.crawl_exclude, href or ""):
                if href not in visited_hrefs:
                  visited_hrefs.append(href)
                  if settings.VERBOSITY_LEVEL != 0:
                    debug_msg = "Skipping URL " + href + "."
                    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
              else:
                identified_hrefs = store_hrefs(href, identified_hrefs, redirection=False)
    no_usable_links(crawled_hrefs)
    if identified_hrefs:
      if len(new_crawled_hrefs) != 0 and settings.DEFAULT_CRAWLING_DEPTH != 1:
        return list(set(new_crawled_hrefs))
      return list(set(crawled_hrefs))
    return list("")

  except Exception as e:  # for non-HTML files and non-valid links
    pass


"""
The main crawler.
"""
def crawler(url, url_num, crawling_list, http_request_method):
  init_global_vars()
  if crawling_list > 1:
    _ = " (" + str(url_num) + "/" + str(crawling_list) + ")"
  else:
    _ = ""
  response = request(url, http_request_method)
  if type(response) is not bool and response is not None:
    if settings.SITEMAP_CHECK:
      enable_crawler()
    if settings.SITEMAP_CHECK is None:
      check_sitemap()
    if settings.SITEMAP_CHECK:
      output_href = sitemap(url, http_request_method)
    if not settings.SITEMAP_CHECK or (settings.SITEMAP_CHECK and output_href is None):
      info_msg = "Starting crawler for target URL '" + url + "'" + _ + "."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      output_href = do_process(url, http_request_method)
      if settings.MULTI_TARGETS and settings.DEFAULT_CRAWLING_DEPTH != 1:
        settings.DEFAULT_CRAWLING_DEPTH = 1
      while settings.DEFAULT_CRAWLING_DEPTH <= int(menu.options.crawldepth):
        info_msg = "Searching for usable "
        info_msg += "links with depth " + str(settings.DEFAULT_CRAWLING_DEPTH) + "."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        if settings.DEFAULT_CRAWLING_DEPTH == 2:
          output_href = new_crawled_hrefs
        elif settings.DEFAULT_CRAWLING_DEPTH > 2:
          output_href = new_crawled_hrefs + crawled_hrefs
        try:
          [output_href.remove(x) for x in visited_hrefs if x in output_href]
        except TypeError:
          pass
        link = 0
        if output_href is not None:
          for url in output_href:
            if url not in visited_hrefs and url is not None:
              link += 1
              settings.CRAWLED_URLS_NUM = link
              if settings.SINGLE_WHITESPACE in url:
                url = url.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE))
              visited_hrefs.append(url)
              do_process(url, http_request_method)
              info_msg = str(link)
              info_msg += "/" + str(len(output_href)) + " links visited."
              settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
              
        if link != 0:
          settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        settings.DEFAULT_CRAWLING_DEPTH += 1

  output_href = crawled_hrefs
  no_usable_links(output_href)
  return output_href

# eof