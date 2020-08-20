#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2019 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from setuptools import setup, find_packages

setup(
      name='commix',
      version='3.2-dev',
      description='Automated All-in-One OS command injection and exploitation tool.',
      long_description=open('README.md').read(),
      long_description_content_type='text/markdown',
      author='Anastasios Stasinopoulos',
      url='https://commixproject.com',
      project_urls={
          'Documentation': 'https://github.com/commixproject/commix/wiki',
          'Source': 'https://github.com/commixproject/commix',
          'Tracker': 'https://github.com/commixproject/commix/issues',
      },
      license='GNU General Public License v3 (GPLv3)',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
    classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Environment :: Console',
          'Topic :: Security',
      ],
      entry_points={
          'console_scripts': [
              'commix = src.core.main:entry_point'
          ]
      },
)

# eof