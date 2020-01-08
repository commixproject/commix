#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2020 Anastasios Stasinopoulos (@ancst).

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
from src.core.requests import headers
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup

def store_crawling():
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to store crawling results to a temporary file "
      question_msg += "(for eventual further processing with other tools)? [y/N] > "
      store_crawling = _input(settings.print_question_msg(question_msg))
    else:
      store_crawling = ""
    if len(store_crawling) == 0:
       store_crawling = "n"
    if store_crawling in settings.CHOICE_YES:
      filename = tempfile.mkstemp(suffix=".txt")[1]
      info_msg = "Writing crawling results to a temporary file '" + str(filename) + "'."
      print(settings.print_info_msg(info_msg))
      return str(filename)
    elif store_crawling in settings.CHOICE_NO:
      return None
    elif store_crawling in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + store_crawling + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
      pass  

"""
Do a request to target URL.
"""
def request(url):
  # Check if defined POST data
  if menu.options.data:
    request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
  else:
    request = _urllib.request.Request(url)
  try:
    headers.do_check(request) 
    response = _urllib.request.urlopen(request)
    soup = BeautifulSoup(response)
    return soup
  except _urllib.error.URLError as e:
    pass

"""
Check for URLs in sitemap.xml.
"""
def sitemap(url):
  try:
    href_list = []
    if not url.endswith(".xml"):
      url = _urllib.parse.urljoin(url, "/sitemap.xml")
    soup = request(url)
    for match in soup.findAll("loc"):
      href_list.append(match.text)
  except:
    warn_msg = "The 'sitemap.xml' not found."
    print(settings.print_warning_msg(warn_msg)) 
  return href_list

"""
Grab the crawled hrefs.
"""
def crawling(url):
  try:
    href_list = []
    soup = request(url)
    for tag in soup.findAll('a', href=True):
      tag['href'] = _urllib.parse.urljoin(url, tag['href'])
      o = _urllib.parse.urlparse(url)
      if o.netloc in tag['href']:
        if tag['href'].split('.')[-1].lower() not in settings.CRAWL_EXCLUDE_EXTENSIONS:
          href_list.append(tag['href']) 
    return href_list
  except:
    pass

"""
The crawing process.
"""
def do_process(url):
  if settings.DEFAULT_CRAWLDEPTH_LEVEL == 1:
    crawled_href = crawling(url)
  else:
    try:
      crawled_href = []
      for url in crawling(url):
        crawled_href.append(crawling(url)) 
        crawled_href = list(set([item for sublist in crawled_href for item in sublist]))
    except TypeError:
      pass
  return crawled_href

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
        change_depth_level = _input(settings.print_question_msg(question_msg))
      else:
        change_depth_level = ""
      if len(change_depth_level) == 0:
         change_depth_level = "y"
      if change_depth_level in settings.CHOICE_YES or change_depth_level in settings.CHOICE_NO:
        break  
      elif change_depth_level in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        err_msg = "'" + change_depth_level + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass
    # Change the crawling depth level.
    if change_depth_level in settings.CHOICE_YES:
      while True:
        question_msg = "Please enter the crawling depth level (1-2) > "
        depth_level = _input(settings.print_question_msg(question_msg))
        if len(depth_level) == 0:
          depth_level = 1
          break
        elif str(depth_level) != "1" and str(depth_level) != "2":
          err_msg = "Depth level '" + depth_level + "' is not a valid answer."  
          print(settings.print_error_msg(err_msg))
          pass
        else: 
          menu.options.DEFAULT_CRAWLDEPTH_LEVEL = depth_level
          break

  while True:
    if not menu.options.sitemap_url:
      if not menu.options.batch:
        question_msg = "Do you want to check target for "
        question_msg += "the existence of site's sitemap(.xml)? [y/N] > "
        sitemap_check = _input(settings.print_question_msg(question_msg))
      else:
        sitemap_check = ""
      if len(sitemap_check) == 0:
         sitemap_check = "n"
      if sitemap_check in settings.CHOICE_YES:
        sitemap_check = True
        break
      elif sitemap_check in settings.CHOICE_NO:
        sitemap_check = False
        break
      elif sitemap_check in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        err_msg = "'" + sitemap_check + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
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
          print(settings.print_warning_msg(warn_msg))
          if not menu.options.batch:
            question_msg = "Do you want to follow the detected recursion? [Y/n] > "
            sitemap_check = _input(settings.print_question_msg(question_msg))
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
            raise SystemExit()
          else:
            err_msg = "'" + sitemap_check + "' is not a valid answer."  
            print(settings.print_error_msg(err_msg))
            pass
  else:
    output_href = do_process(url)
  filename = store_crawling()
  info_msg = "Checking "
  if sitemap_check:
    info_msg += "targets's sitemap.xml "
  info_msg += "for usable links with GET parameters... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  succeed_banner = True
  valid_url_found = False

  try:
    url_num = 0
    valid_urls = []
    for check_url in output_href:
      # Check for usable URL with GET parameters
      if re.search(settings.GET_PARAMETERS_REGEX, check_url):
        valid_url_found = True
        url_num += 1
        if succeed_banner:
          print("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
        print(settings.print_success_msg("URL " + str(url_num) + " - " + check_url))
        if filename is not None:
          with open(filename, "a") as crawling_results:
            crawling_results.write(check_url + "\n")
        if not menu.options.batch:
          question_msg = "Do you want to use this URL to perform tests? [Y/n] > "
          use_url = _input(settings.print_question_msg(question_msg))
        else:
          use_url = ""
        if len(use_url) == 0:
           use_url = "y"
        if use_url in settings.CHOICE_YES:
          return check_url
        elif use_url in settings.CHOICE_NO:
          info_msg = "Skipping '" + check_url + "'.\n"
          sys.stdout.write(settings.print_info_msg(info_msg))
          succeed_banner = False
          pass 
        elif use_url in settings.CHOICE_QUIT:
          raise SystemExit()
    raise SystemExit()
  except TypeError:
    pass
  if not valid_url_found:
    print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
  raise SystemExit()

# eof