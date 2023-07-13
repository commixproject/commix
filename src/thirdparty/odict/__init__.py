#!/usr/bin/env python

import sys

if sys.version_info[:2] >= (2, 7):
  from collections import OrderedDict
else:
  from src.thirdparty.six.moves import collections_abc as _collections
  from _collections import OrderedDict
