"""Resolver interface and default implementation for files. """
import logging
import os
from itertools import combinations
from os.path import exists, isdir, isfile, join, normpath

from pathspec import GitIgnoreSpec
from securesystemslib.exceptions import FormatError
from securesystemslib.hash import digest_filename

from in_toto.exceptions import PrefixError

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "sha256"


class FileResolver:
    def __init__(
        self,
        exclude_patterns=None,
        base_path=None,
        follow_symlink_dirs=False,
        normalize_line_endings=False,
        lstrip_paths=None,
    ):
        if exclude_patterns is None:
            exclude_patterns = []

        if not lstrip_paths:
            lstrip_paths = []

        for name, val in [
            ("exclude_patterns", exclude_patterns),
            ("lstrip_paths", lstrip_paths),
        ]:
            if not isinstance(val, list) or not all(
                isinstance(i, str) for i in val
            ):
                # FIXME: FormatError for backwards-compat; should be ValueError
                raise FormatError(f"'{name}' must be list of strings")

        for _a, _b in combinations(lstrip_paths, 2):
            if _a.startswith(_b) or _b.startswith(_a):
                raise PrefixError(
                    f"'{_a}' and '{_b}' triggered a left substring error"
                )

        # Compile gitignore-style patterns
        self._exclude_filter = GitIgnoreSpec.from_lines(
            "gitwildmatch", exclude_patterns
        )
        self._base_path = base_path
        self._follow_symlink_dirs = follow_symlink_dirs
        self._normalize_line_endings = normalize_line_endings
        self._lstrip_paths = lstrip_paths

    def _exclude(self, name):
        return self._exclude_filter.match_file(name)

    def _hash(self, name):
        digest = digest_filename(
            name,
            algorithm=_HASH_ALGORITHM,
            normalize_line_endings=self._normalize_line_endings,
        )
        return {_HASH_ALGORITHM: digest.hexdigest()}

    def _mangle(self, name, existing_names):
        # Normalize slashes for cross-platform metadata consistency
        # FIXME: This breaks Unix paths that contain backward slashes
        name = name.replace("\\", "/")

        # Left-strip names using configured prefixes
        for prefix in self._lstrip_paths:
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break

        # Fail if left-stripping results in duplicates
        if self._lstrip_paths and name in existing_names:
            raise PrefixError(
                "Prefix selection has resulted in non unique dictionary key "
                f"'{name}'"
            )

        return name

    def hash_artifacts(self, uris):
        hashes = {}

        if self._base_path:
            original_cwd = os.getcwd()
            # FIXME: Re-raise for backwards-compat; should remove try/except
            try:
                os.chdir(self._base_path)
            except Exception as e:
                raise ValueError(
                    f"Could not use '{self._base_path}' as base path: '{e}'"
                ) from e

        for uri in uris:
            uri = normpath(uri)

            if self._exclude(uri):
                continue

            if not exists(uri):
                logger.info("path: %s does not exist, skipping..", uri)
                continue

            if isfile(uri):
                hashes[self._mangle(uri, hashes)] = self._hash(uri)

            if isdir(uri):
                for dirpath, dirnames, filenames in os.walk(
                    uri, followlinks=self._follow_symlink_dirs
                ):
                    # Filter directories to avoid unnecessary recursion below
                    dirnames[:] = [
                        d
                        for d in dirnames
                        if not self._exclude(join(dirpath, d))
                    ]

                    for name in filenames:
                        path = normpath(join(dirpath, name))

                        if self._exclude(path):
                            continue

                        if not isfile(path):
                            logger.info(
                                "File '%s' appears to be a broken symlink. "
                                "Skipping...",
                                path,
                            )
                            continue

                        hashes[self._mangle(path, hashes)] = self._hash(path)

        # Change back to where original current working dir
        if self._base_path:
            os.chdir(original_cwd)

        return hashes
