#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from setuptools import setup, find_packages

setup(
      name='commix',
      version='4.2.dev',
      description='Automated All-in-One OS Command Injection Exploitation Tool',
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
      python_requires='>=3.7',
      # The data files live beside the code rather than inside it, so they are named here to be
      # installed along with it.
      packages=find_packages() + ["data", "data.txt"],
      include_package_data=True,
      package_data={"": ["*.txt"], "data.txt": ["*.txt", "*.tx_"]},
      zip_safe=False,
    classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
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