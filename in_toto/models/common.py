"""
<Program Name>
  common.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres <santiago@nyu.edu>

<Started>
  Sep 23, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides base classes for various classes in the model.

<Classes>
  Metablock:
      pretty printed canonical JSON representation and dump

  Signable:
      sign self, store signature to self and verify signatures

"""

import attr
import canonicaljson
import inspect
import securesystemslib.keys
import securesystemslib.formats

class ValidationMixin(object):
  """ The validation mixin provides a self-inspecting method, validate, to
  allow in-toto's objects to check that they are proper. """

  def validate(self):
    """
      <Purpose>
        Inspects the class (or subclass) for validate methods to ensure the
        all its members are properly formed. This method can be used to ensure
        the metadata contained in this class is proper before calling dump.

      <Arguments>
        None

      <Exceptions>
        FormatError: If any of the members of this class are not properly
                     populated.

      <Side Effects>
        None

      <Returns>
        None
    """
    for method in inspect.getmembers(self, predicate=inspect.ismethod):
      if method[0].startswith("_validate_"):
        method[1]()


@attr.s(repr=False, init=False)
class Signable(ValidationMixin):
  """Objects with base class Signable are to be included in a Metablock class
  to be signed (hence the name). They provide a pretty-printed json
  representation of its fields"""

  def __repr__(self):
    return canonicaljson.encode_pretty_printed_json(attr.asdict(self))
