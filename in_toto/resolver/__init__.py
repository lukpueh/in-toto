"""Artifact resolver API.

Extensible interface to hash artifacts based on URIs.

# TODO: uncomment when Resolver is added
# Example usage::

#     from in_toto.resolver import Resolver

#     resolver = Resolver.for_uri(artifact_uri)
#     artifact_hashes = resolver.hash_artifacts()

"""

from in_toto.resolver._resolver import FileResolver
