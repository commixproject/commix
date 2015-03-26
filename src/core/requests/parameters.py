#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""
import re
from src.utils import settings

"""
  If its not specified the 'INJECT_HERE' tag on any parameter, 
  do automated scan on... every parameter.
"""

def do_GET_check(url):
  
  #Find the host part
  url_part = url.split("?")[0]
  
  #Find the parameter part
  parameters = url.split("?")[1]
  
  # Split parameters
  multi_parameters = parameters.split("&")
  
  # Check if single paramerter
  if len(multi_parameters) == 1:
    
    #Grab the value of parameter.
    value = re.findall(r'=(.*)', parameters)
    value = ''.join(value)
    
    # Replace the value of parameter with INJECT tag
    inject_value = value.replace(value, settings.INJECT_TAG)
    parameters = parameters.replace(value, inject_value)
    
    # Reconstruct the url
    url = url_part +"?"+ parameters
    return url
  
  # Check if multiple paramerters
  else:
    for i in range(0,len(multi_parameters)-1):
      # Check it is on first parameter
      if i == 0 :
	old = re.findall(r'=(.*)', multi_parameters[i])
	old = ''.join(old)
      else :
	old = value
	
      # Grab the value of parameter.
      value = re.findall(r'=(.*)', multi_parameters[i])
      value = ''.join(value)
      
      #Replace the value of parameter with INJECT tag
      inject_value = value.replace(value, settings.INJECT_TAG)
      multi_parameters[i] = multi_parameters[i].replace(value, inject_value)
      multi_parameters[i-1] = multi_parameters[i-1].replace(inject_value, old)
      parameter = '&'.join(multi_parameters)
      
    # Reconstruct the url
    url = url_part +"?"+ parameter
    return url
  
  
def do_POST_check(parameter):
  # Split parameters 
  multi_parameters = parameter.split("&")
  
  # Check if single paramerter
  if len(multi_parameters) == 1:
    value = re.findall(r'=(.*)', parameter)
    value = ''.join(value)
    
    # Replace the value of parameter with INJECT tag
    inject_value = value.replace(value, settings.INJECT_TAG)
    parameter = parameter.replace(value, inject_value)
    return parameter
  
  # Check if multiple paramerters
  else:
    for i in range(0,len(multi_parameters)-1):
      # Check it is on first parameter
      if i == 0 :
	old = re.findall(r'=(.*)', multi_parameters[i])
	old = ''.join(old)
      else :
	old = value
	
      # Grab the value of parameter.
      value = re.findall(r'=(.*)', multi_parameters[i])
      value = ''.join(value)
      
      # Replace the value of parameter with INJECT tag
      inject_value = value.replace(value, settings.INJECT_TAG)
      multi_parameters[i] = multi_parameters[i].replace(value, inject_value)
      multi_parameters[i-1] = multi_parameters[i-1].replace(inject_value, old)
      parameter = '&'.join(multi_parameters)
    return parameter
  
#eof