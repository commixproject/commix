#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""
import re
import os
from src.utils import colors
from src.utils import settings

"""
  If its not specified the 'INJECT_HERE' tag on any parameter, 
  do automated scan on... every parameter.
"""

# Check if its not specified the 'INJECT_HERE' tag on GET Requests
def do_GET_check(url):
  
  #Find the host part
  url_part = url.split("?")[0]
  
  #Find the parameter part
  parameters = url.split("?")[1]
  
  # Split parameters
  multi_parameters = parameters.split("&")
  
  # Check if single paramerter
  if len(multi_parameters) == 1:
    
    # Check if defined the INJECT_TAG
    if settings.INJECT_TAG not in parameters:
      
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
    all_params = '&'.join(multi_parameters)
    
    # Check if defined the "INJECT_HERE" tag
    if settings.INJECT_TAG in all_params:
      for i in range(0,len(multi_parameters)):
        # Grab the value of parameter.
        value = re.findall(r'=(.*)', multi_parameters[i])
        value = ''.join(value)
        parameter = '&'.join(multi_parameters)

      url = url_part +"?"+ parameter  
      return url
    
    else:
      print "\n" + colors.BGRED + "(x) Error: You must set the \"INJECT_HERE\" tag to specify the testable parameter." + colors.RESET + "\n"
      os._exit(0)
      
      ## Multiple paramerters without the "INJECT_HERE" tag.
      #urls_list = []
      #for i in range(0,len(multi_parameters)):
        #if i == 0 :
          #old = re.findall(r'=(.*)', multi_parameters[i])
          #old = ''.join(old)
        #else :
          #old = value
          
        ## Grab the value of parameter.
        #value = re.findall(r'=(.*)', multi_parameters[i])
        #value = ''.join(value)
        
        ##Replace the value of parameter with INJECT tag
        #inject_value = value.replace(value, settings.INJECT_TAG)
        #multi_parameters[i] = multi_parameters[i].replace(value, inject_value)
        #multi_parameters[i-1] = multi_parameters[i-1].replace(inject_value, old)
        #parameter = '&'.join(multi_parameters)
        
        ## Reconstruct the url
        #url = url_part +"?"+ parameter
        
        ## Add all urls to url list.
        #urls_list.append(url)
      #return urls_list


# Define the vulnerable parameter
def vuln_GET_param(url):
  
  # Define the vulnerable parameter
  if re.findall(r"&(.*)=" + settings.INJECT_TAG + "", url):
    vuln_parameter = re.findall(r"&(.*)=" + settings.INJECT_TAG + "", url)
    vuln_parameter = ''.join(vuln_parameter)
    vuln_parameter = re.sub(r"(.*)=(.*)&", "", vuln_parameter)
    
  elif re.findall(r"\?(.*)=" + settings.INJECT_TAG + "", url):
    vuln_parameter = re.findall(r"\?(.*)=" + settings.INJECT_TAG + "", url)
    vuln_parameter = ''.join(vuln_parameter)
    
  elif re.findall(r"(.*)=" + settings.INJECT_TAG + "", url):
    vuln_parameter = re.findall(r"(.*)=" + settings.INJECT_TAG + "", url)
    vuln_parameter = ''.join(vuln_parameter)
    
  # Check if one parameter but 
  # not defined the INJECT_TAG.
  elif settings.INJECT_TAG not in url:
      #Grab the value of parameter.
      value = re.findall(r'\?(.*)=', url)
      value = ''.join(value)
      vuln_parameter = value
      
  else:
    vuln_parameter = url
    
  return vuln_parameter 


# Check if its not specified the 'INJECT_HERE' tag on GET Requests
def do_POST_check(parameter):

  # Split parameters 
  multi_parameters = parameter.split("&")
  
  # Check if single paramerter
  if len(multi_parameters) == 1:

      # Check if defined the INJECT_TAG
      if settings.INJECT_TAG not in parameter:
        #Grab the value of parameter.
        value = re.findall(r'=(.*)', parameter)
        value = ''.join(value)
        # Replace the value of parameter with INJECT tag
        inject_value = value.replace(value, settings.INJECT_TAG)
        parameter = parameter.replace(value, inject_value)
        
      return parameter
  
  # Check if multiple paramerters
  else:
    all_params = '&'.join(multi_parameters)
    
    # Check if defined the "INJECT_HERE" tag
    if settings.INJECT_TAG in all_params:
      for i in range(0,len(multi_parameters)):
        if settings.INJECT_TAG not in multi_parameters[i]:
          # Grab the value of parameter.
          value = re.findall(r'=(.*)', multi_parameters[i])
          value = ''.join(value)
          parameter = '&'.join(multi_parameters)
          
      return parameter
    
    else:
      print "\n" + colors.BGRED + "(x) Error: You must set the \"INJECT_HERE\" tag to specify the testable parameter." + colors.RESET + "\n"
      os._exit(0)
      
      ## Multiple paramerters without the "INJECT_HERE" tag.
      #paramerters_list = []
      #for i in range(0,len(multi_parameters)):
        #if i == 0 :
          #old = re.findall(r'=(.*)', multi_parameters[i])
          #old = ''.join(old)
        #else :
          #old = value
          
        ## Grab the value of parameter.
        #value = re.findall(r'=(.*)', multi_parameters[i])
        #value = ''.join(value)
        
        ##Replace the value of parameter with INJECT tag
        #inject_value = value.replace(value, settings.INJECT_TAG)
        #multi_parameters[i] = multi_parameters[i].replace(value, inject_value)
        #multi_parameters[i-1] = multi_parameters[i-1].replace(inject_value, old)
        #parameter = '&'.join(multi_parameters)
        
        ## Reconstruct the paramerters
        ## Add all parameters to paramerters list.
        #paramerters_list.append(parameter)

      #return paramerters_list


# Define the vulnerable parameter
def vuln_POST_param(parameter,url):
  
    # Define the vulnerable parameter
    if re.findall(r"&(.*)=" + settings.INJECT_TAG + "", parameter):
      vuln_parameter = re.findall(r"&(.*)=" + settings.INJECT_TAG + "", parameter)
      vuln_parameter = ''.join(vuln_parameter)
      vuln_parameter = re.sub(r"(.*)=(.*)&", "", vuln_parameter)

    elif re.findall(r"(.*)=" + settings.INJECT_TAG + "", parameter):
      vuln_parameter = re.findall(r"(.*)=" + settings.INJECT_TAG + "", parameter)
      vuln_parameter = ''.join(vuln_parameter)

    else:
      vuln_parameter = parameter
    
    return vuln_parameter
    
#eof
