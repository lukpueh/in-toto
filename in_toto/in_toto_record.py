#!/usr/bin/env python

"""
<Program Name>
  in_toto_record.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Nov 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a command line interface to start and stop in-toto link metadata
  recording.

  start
    Takes a step name, a functionary's signing key and optional
    material paths.
    Creates a temporary link file containing the file hashes of the passed
    materials and signs it with the functionary's key under
    .<step name>.link-unfinished

  stop
    Takes a step name, a functionary's signing key and optional
    product paths.
    Expects a .<step name>.link-unfinished in the current directory signed by
    the functionary's signing key, adds the file hashes of the passed products,
    updates the signature and renames the file  .<step name>.link-unfinished
    to <step name>.link


  The implementation of the tasks can be found in runlib.

  Example Usage
  ```
  in-toto-record --step-name edit-files start --materials . --key bob
  # Edit files manually ...
  in-toto-record --step-name edit-files stop --products . --key bob
  ```

"""
import os
import sys
import argparse
import in_toto.util
import in_toto.user_settings
import in_toto.runlib
import in_toto.log

def main():
  """ Parse arguments, load key from disk and call either in_toto_record_start
  or in_toto_record_stop. """
  parser = argparse.ArgumentParser(
      description="Starts or stops link metadata recording")

  subparsers = parser.add_subparsers(dest="command")

  subparser_start = subparsers.add_parser('start')
  subparser_stop = subparsers.add_parser('stop')

  # Whitespace padding to align with program name
  lpad = (len(parser.prog) + 1) * " "
  parser.usage = ("\n"
      "%(prog)s  --step-name <unique step name>\n{0}"
               " --key <functionary private key path>\n"
               "[--verbose]\n"
      "Commands:\n{0}"
               "start [--materials <filepath>[ <filepath> ...]]\n{0}"
               "stop  [--products <filepath>[ <filepath> ...]]\n"
               .format(lpad))

  in_toto_args = parser.add_argument_group("in-toto options")
  # FIXME: Do we limit the allowed characters for the name?
  in_toto_args.add_argument("-n", "--step-name", type=str, required=True,
      help="Unique name for link metadata")

  in_toto_args.add_argument("-k", "--key", type=str, required=True,
      help="Path to private key to sign link metadata (PEM)")

  in_toto_args.add_argument("-v", "--verbose", dest='verbose',
      help="Verbose execution.", default=False, action='store_true')

  subparser_start.add_argument("-m", "--materials", type=str, required=False,
      nargs='+', help="Files to record before link command execution")

  subparser_stop.add_argument("-p", "--products", type=str, required=False,
      nargs='+', help="Files to record after link command execution")

  args = parser.parse_args()

  # Turn on all the `log.info()` in the library
  if args.verbose:
    in_toto.log.logging.getLogger().setLevel(in_toto.log.logging.INFO)

  # Override defaults in settings.py with environment variables and RCfiles
  in_toto.user_settings.set_settings()

  # We load the key here because it might prompt the user for a password in
  # case the key is encrypted. Something that should not happen in the library.
  try:
    key = in_toto.util.prompt_import_rsa_key_from_file(args.key)
  except Exception as e:
    in_toto.log.error("in load key - {}".format(args.key))
    sys.exit(1)

  try:
    if args.command == "start":
      in_toto.runlib.in_toto_record_start(args.step_name, args.materials, key)

    elif args.command == "stop": # pragma: no branch
      in_toto.runlib.in_toto_record_stop(args.step_name, args.products, key)

    # Else is caught by argparser

  except Exception as e:
    in_toto.log.error("in {} record - {}".format(args.command, e))
    sys.exit(1)

if __name__ == '__main__':
  main()
