"""Resolver interface and default implementation for files. """
import os
import logging

from os.path import join, basename, normpath, isfile, isdir, exists

from abc import ABCMeta, abstractmethod
from securesystemslib.hash import digest_filename
from pathspec import GitIgnoreSpec

from typing import List

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"


# TODO: add later and update RESOLVER_FOR_URI_SCHEME in resolver/__init__
# RESOLVER_FOR_URI_SCHEME = {}

# class Resolver(metaclass=ABCMeta):
#   """Resolver interface and factory. """

#   @classmethod
#   def for_uri(cls, uri):
#     """Create matching resolver for passed uri. """
#     scheme, _, _ = uri.partition(":")

#     if scheme not in RESOLVER_FOR_URI_SCHEME:
#         return FileResolver(uri)

#     return RESOLVER_FOR_URI_SCHEME[scheme](uri)

#   @abstractmethod
#   def hash_artifacts(self):
#     """Return hashes for one or more artifacts resolved at this instance uri. """
#     raise NotImplementedError

class FileResolver(Resolver):
  def __init__(self, uri, exclude_patterns=None, base_path=None,
      follow_symlink_dirs=False, normalize_line_endings=False, lstrip_paths=None):

    if exclude_patterns is None:
      exlcude_patterns = []

    # Compile the gitignore-style patterns
    self._exclude_filter = GitIgnoreSpec.from_lines('gitwildmatch')

    self.uri = uri
    self._base_path = base_path
    self._follow_symlink_dirs = follow_symlink_dirs
    self._normalize_line_endings = normalize_line_endings
    self._lstrip_paths = lstrip_paths

  def _exclude(name):
    return self._exclude_filter.match_file(name)

  def _hash(name):
    digest = digest_filename(name, _HASH_ALGORITHM, self._normalize_line_endings)
    return {
      HASH_ALGORITHM: digest.hexdigest()
    }

  def _mangle(self, name):
    # Collapse redundant separators and up-level references
    # (on Windows this converts forward slashes to backward slashes
    name = normpath(name)

    # Normalize slashes to provide consistency between windows and *nix
    # FIXME: This breaks *nix paths that contain backward slashes.
    name = name.replace('\\', '/')

    # Left-strip prefix (first match only!!)
    for prefix in self._lstrip_paths:
      if name.startswith(prefix):
        name = name[len(prefix):]
        break

    return name

  def hash_artifacts(self):
    artifact_hashes = {}

    # Temporarily change into base path dir if set
    if self._base_path:
      original_cwd = os.getcwd()
      os.chdir(self._base_path)

    # Return if the artifact should be ignored or does not exist
    if self._exclude(self.uri)
      return artifact_hashes

    if not exists(self.uri):
      logger.info("path: %s does not exist, skipping..", self.uri)
      return artifact_hashes

    if isfile(self.uri):
      artifact_hashes[self._mangle(self.uri)] = self._hash(self.uri)

    if isdir(artifact):
      for dirpath, dirnames, filenames in os.walk(self.uri, followlinks=self._follow_symlink_dirs):

        # Apply include patterns to normalized directory names alone
        # - Assign remaining dirs so that walk recurses only into remaining firs
        # - Use generator comprehension to not create unnecessary copies
        # FIXME: is this too much inline magic?
        dirs[:] = (d for d in dirnames if self._exclude(join(dirpath, d)))

        for name in filenames:
          path = join(dirpath, name)

          if self._exclude(path):
            continue

          if not isfile(path)
            logger.info("File '%s' appears to be a broken symlink. Skipping...", path)
            continue

          artifact_hashes[self._mangle(path)] = self._hash(path)

    # Change back to where original current working dir
    if self._base_path:
      os.chdir(original_cwd)

    return artifacts_dict