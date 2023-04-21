"""Resolver interface and default implementation for files. """
import os
import logging

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

  @staticmethod
  def _hash(name, normalize_line_endings):
    digest = digest_filename(name, _HASH_ALGORITHM, normalize_line_endings)
    return {
      HASH_ALGORITHM: digest.hexdigest()
    }

  @staticmethod
  def _mangle(name, lstrip_paths):
    # Collapse redundant separators and up-level references
    # (on Windows this converts forward slashes to backward slashes
    name = os.path.normpath(name)

    # Normalize slashes to provide consistency between windows and *nix
    # FIXME: This breaks *nix filepaths that contain backward slashes.
    name = name.replace('\\', '/')

    # Left-strip prefix (first match only!!)
    for prefix in lstrip_paths:
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
    if self._exclude_filter.match_file(self.uri)
      return artifact_hashes

    if not os.path.exists(self.uri):
      logger.info("path: %s does not exist, skipping..", self.uri)
      return artifact_hashes


    if os.path.isfile(self.uri):
      artifact_hashes[self._mangle(self.uri)] = self._hash(self.uri)

    if os.path.isdir(artifact):
      for root, dirs, files in os.walk(self.uri, followlinks=self._follow_symlink_dirs):
        # Create a list of normalized dirpaths
        dirpaths = []
        for dirname in dirs:
          norm_dirpath = os.path.normpath(os.path.join(root, dirname))
          dirpaths.append(norm_dirpath)

        # Applying exclude patterns on the directory paths returned by walk
        # allows to exclude a subdirectory 'sub' with a pattern 'sub'.
        # If we only applied the patterns below on the subdirectory's
        # containing file paths, we'd have to use a wildcard, e.g.: 'sub*'
        if exclude_patterns:
          dirpaths = _apply_exclude_patterns(dirpaths, exclude_filter)

        # Reset and refill dirs with remaining names after exclusion
        # Modify (not reassign) dirnames to only recurse into remaining dirs
        dirs[:] = []
        for dirpath in dirpaths:
          # Dirs only contain the basename and not the full path
          name = os.path.basename(dirpath)
          dirs.append(name)

        # Create a list of normalized filepaths
        filepaths = []
        for filename in files:
          norm_filepath = os.path.normpath(os.path.join(root, filename))

          # `os.walk` could also list dead symlinks, which would
          # result in an error later when trying to read the file
          if os.path.isfile(norm_filepath):
            filepaths.append(norm_filepath)

          else:
            LOG.info("File '{}' appears to be a broken symlink. Skipping..."
                .format(norm_filepath))

        # Apply exlcude patterns on the normalized file paths returned by walk
        if exclude_patterns:
          filepaths = _apply_exclude_patterns(filepaths, exclude_filter)

        for filepath in filepaths:
          # FIXME: this is necessary to provide consisency between windows
          # filepaths and *nix filepaths. A better solution may be in order
          # though...
          normalized_filepath = filepath.replace("\\", "/")
          key = _apply_left_strip(
              normalized_filepath, artifacts_dict, lstrip_paths)
          artifacts_dict[key] = _hash_artifact(filepath,
              normalize_line_endings=normalize_line_endings)


    # Change back to where original current working dir
    if self._base_path:
      os.chdir(original_cwd)

    return artifacts_dict