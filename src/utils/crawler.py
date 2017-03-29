#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

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

"""
Do a request to target URL.
"""
def request(url):
  # Check if defined POST data
  if menu.options.data:
    request = urllib2.Request(url, menu.options.data)
  else:
    request = urllib2.Request(url)
  headers.do_check(request) 
  response = urllib2.urlopen(request)
  soup = BeautifulSoup(response)
  return soup

"""
Check for URLs in sitemap.xml.
"""
def sitemap(url):
  if not url.endswith(".xml"):
    url = urlparse.urljoin(url, "/sitemap.xml")
  try:
    soup = request(url)
    href_list = []
    for match in soup.findAll("loc"):
        href_list.append(match.text)
    return href_list  
  except:
    warn_msg = "The 'sitemap.xml' not found."
    print settings.print_warning_msg(warn_msg) 
    return ""

"""
Grab the crawled hrefs.
"""
def crawling(url):
  soup = request(url)
  href_list = []
  for tag in soup.findAll('a', href=True):
    tag['href'] = urlparse.urljoin(url, tag['href'])
    o = urlparse.urlparse(url)
    if o.netloc in tag['href'] :
      href_list.append(tag['href']) 
  return href_list    
 
"""
The crawing process.
"""
def do_process(url):
  crawled_href = crawling(url)
  if menu.options.DEFAULT_CRAWLDEPTH_LEVEL == 1:
    return crawled_href
  else:
    for url in crawled_href:
      crawled_href = crawling(url)
      return crawled_href

"""
The main crawler.
"""
def crawler(url):
  if not menu.options.sitemap_url:
    info_msg = "Starting crawler and searching for "
    info_msg += "links with depth " + str(menu.options.DEFAULT_CRAWLDEPTH_LEVEL) + "." 
    print settings.print_info_msg(info_msg)

  while True:
    if not menu.options.sitemap_url:
      if not menu.options.batch:
        question_msg = "Do you want to check target for "
        question_msg += "the existence of 'sitemap.xml'? [Y/n] > "
        sys.stdout.write(settings.print_question_msg(question_msg))
        sitemap_check = sys.stdin.readline().replace("\n","").lower()
      else:
        sitemap_check = ""
      if len(sitemap_check) == 0:
         sitemap_check = "y"
      if sitemap_check in settings.CHOICE_YES:
        sitemap_check = True
        break
      elif sitemap_check in settings.CHOICE_NO:
        sitemap_check = False
        break
      elif sitemap_check in settings.CHOICE_QUIT:
        sys.exit(0)
      else:
        err_msg = "'" + sitemap_check + "' is not a valid answer."  
        print settings.print_error_msg(err_msg)
        pass
    else:
      sitemap_check = True
      break
      
  if sitemap_check:
    output_href = sitemap(url)
    sitemap_check = output_href
    for recursion in output_href:
      if recursion.endswith(".xml") and "sitemap" in recursion.lower():
        while True:
          warn_msg = "A sitemap recursion was detected " + "'" + recursion + "'."
          print settings.print_warning_msg(warn_msg)
          if not menu.options.batch:
            question_msg = "Do you want to follow the detected recursion? [Y/n] > "
            sys.stdout.write(settings.print_question_msg(question_msg))
            sitemap_check = sys.stdin.readline().replace("\n","").lower()
          else:
            sitemap_check = ""
          if len(sitemap_check) == 0:
             sitemap_check = "y"
          if sitemap_check in settings.CHOICE_YES:
            output_href = sitemap(recursion)
            sitemap_check = output_href
            break
          elif sitemap_check in settings.CHOICE_NO:
            break
          elif sitemap_check in settings.CHOICE_QUIT:
            sys.exit(0)
          else:
            err_msg = "'" + sitemap_check + "' is not a valid answer."  
            print settings.print_error_msg(err_msg)
            pass

  if not sitemap_check:
    output_href = do_process(url)

  info_msg = "Checking "
  if sitemap_check:
    info_msg += "targets's sitemap.xml "
  info_msg += "for usable links with GET parameters... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()

  succeed_banner = True
  valid_url_found = False
  for check_url in output_href:
    # Check for usable URL with GET parameters
    if re.search(settings.GET_PARAMETERS_REGEX, check_url):
      valid_url_found = True
      if succeed_banner:
        print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
      print settings.print_success_msg(check_url)
      if not menu.options.batch:
        question_msg = "Do you want to use this URL to perform tests? [Y/n] > "
        sys.stdout.write(settings.print_question_msg(question_msg))
        use_url = sys.stdin.readline().replace("\n","").lower()
      else:
        use_url = ""
      if len(use_url) == 0:
         use_url = "y"
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