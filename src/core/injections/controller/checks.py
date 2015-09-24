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

import os
import sys

from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

#-------------------------------------
# Procced to the next attack vector.
#-------------------------------------
def check_next_attack_vector(technique, go_back):
  while True:
    next_attack_vector= raw_input("(?) Continue with testing the "+ technique +"? [Y/n/q] > ").lower()
    if next_attack_vector in settings.CHOISE_YES:
      go_back = True
      return go_back

    elif next_attack_vector in settings.CHOISE_NO:
      go_back = False
      return go_back

    elif next_attack_vector in settings.CHOISE_QUIT:
      sys.exit(0)

    else:
      if next_attack_vector == "":
        next_attack_vector = "enter"
      print Back.RED + "(x) Error: '" + next_attack_vector + "' is not a valid answer." + Style.RESET_ALL + "\n"
      pass
      
#eof
