#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix project (http://commixproject.com).
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import sys
import urllib
import urllib2
import urlparse

from src.utils import menu
from src.utils import settings
from src.core.requests import headers
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup

def crawling(url):

  # Check if defined POST data
  if menu.options.data:
    request = urllib2.Request(url, menu.options.data)
  else:
    request = urllib2.Request(url)
  headers.do_check(request) 
  response = urllib2.urlopen(request)
  html_data = response.read()
  soup = BeautifulSoup(html_data)

  href_list = []
  for tag in soup.findAll('a', href=True):
    tag['href'] = urlparse.urljoin(url, tag['href'])
    o = urlparse.urlparse(url)
    if o.netloc in tag['href'] :
      href_list.append(tag['href']) 
  return href_list    
 
def do_process(url):
  crawled_href = crawling(url)
  if menu.options.DEFAULT_CRAWLDEPTH_LEVEL == 1:
    return crawled_href
  else:
    for url in crawled_href:
      crawled_href = crawling(url)
      return crawled_href

def crawler(url):

  info_msg = "Starting crawler and searching for "
  info_msg += "links with depth " + str(menu.options.DEFAULT_CRAWLDEPTH_LEVEL) + "." 
  print settings.print_info_msg(info_msg)

  output_href = do_process(url)
  info_msg = "Checking for usable links with GET parameters... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()

  succeed_banner = True
  valid_url_found = False
  for check_url in output_href:
    # Check for usable URL with GET parameters
    if re.search(r"(.*?)\?(.+)", check_url):
      valid_url_found = True
      if succeed_banner:
        print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
      print settings.print_success_msg(check_url)
      question_msg = "Do you want to use this URL to perform tests? [Y/n/q] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      use_url = sys.stdin.readline().replace("\n","").lower()
      if use_url in settings.CHOICE_YES:
        return check_url
      elif use_url in settings.CHOICE_NO:
        succeed_banner = False
        pass 
      elif gotshell in settings.CHOICE_QUIT:
        sys.exit(0)

  if not valid_url_found:
    print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
  return url

# eof