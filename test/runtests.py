#!/usr/bin/env python
"""
<Program Name>
  runtests.py

<Author>
  Santiago Torres <santiago@nyu.edu>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  May 23, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Script to search, load and run in-toto tests using the Python `unittest`
  framework.
"""

import unittest.defaultTestLoader
import unittest.TextTestRunner
import sys

suite = unittest.defaultTestLoader.discover(start_dir=".")
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
