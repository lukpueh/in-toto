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
from __future__ import print_function
import sys
import logging
from unittest import defaultTestLoader, TextTestRunner



import in_toto.log

print(in_toto.log.__file__)

# Override in-toto logger default StreamHandler to prevent test log inundation
# in_toto.log.logger.handlers = [logging.NullHandler()]

# suite = defaultTestLoader.discover(start_dir=".", pattern="test_log.py")
# result = TextTestRunner(verbosity=1, buffer=True).run(suite)
# sys.exit(0 if result.wasSuccessful() else 1)
