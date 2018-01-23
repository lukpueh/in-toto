import six
import shlex

from datetime import datetime
from dateutil.relativedelta import relativedelta

import in_toto.artifact_rules
import in_toto.gpg.functions
import in_toto.models.layout
import in_toto.models.metadata

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.interface



"""Utils
"""




"""Layout functions
"""
def create():
  """Create an empty layout metadata block and return it. """
  return in_toto.models.metadata.Metablock(
      signed=in_toto.models.layout.Layout())


def load(path):
  """Load an existing layout from path. """
  layout = in_toto.models.metadata.Metablock.load(path)
  if not layout.type_ == "layout":
    raise securesystemslib.exceptions.FormatError("'{}' is not a valid layout"
      .format(path))

  return layout


def sign(layout, key):
  """Create securesystemslib signature signature and append to layout.  Return
  signature. """
  return layout.sign(key)


def sign_gpg(layout, gpg_keyid=None, gpg_home=None):
  """Create gpg signature and append to layout.  Return signature."""
  return layout.sign_gpg(gpg_keyid, gpg_home)


def remove_signature(layout, keyid):
  for signature in layout.signatures:
    if signature["keyid"] == keyid:
      layout.signatures.remove(signature)


def save(layout, path):
  """Save layout at path. """
  layout.dump(path)


def add_step(layout, step):
  """Add a step to layout. """
  layout.signed.steps.append(step)


def add_new_step(layout, step_name):
  """Create new step with name and add step to layout. """
  new_step = in_toto.models.layout.Step(name=step_name)
  add_step_to_layout(layout, new_step)
  return new_step


def remove_step(layout, step_name):
  for step in layout.signed.steps:
    if step.name == step_name:
      layout.signed.steps.remove(step)


def add_inspection(layout, inspection):
  """Add inspection to layout. """
  layout.signed.inspect.append(inspection)


def add_new_inspection(layout, inspection_name):
  """Add inspection to layout. """
  new_inspection = in_toto.models.layout.Inspection(name=inspection_name)
  add_inspection_to_layout(layout, new_inspection)
  return new_inspection


def remove_inspection(layout, inspection_name):
  for inspection in layout.signed.inspect:
    if inspection.name == inspection_name:
      layout.signed.inspect.remove(inspection)


def set_expiration(layout, date_string=None, days=0, months=0, years=0):
  """Set expiration date passing either a date_string or one or more of
  "days", "months", "years" from now to expire in. """

  if date_string != (days or months or years):
    raise Exception("Must set either 'date_string' or one or more of"
        "'days', 'months' or 'years'")

  if date_string:
    backup = layout.signed.expire
    layout.signed.expire = date_string
    try:
      layout.signed._validate_expires()

    except securesystemslib.exceptions.FormatError as e:
      layout.signed.expire = backup
      raise e

  else:
    layout.signed.expire = (datetime.today() + relativedelta(
        days=days, months=months, years=years)).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_readme(layout, readme_string):
  layout.signed.readme = readme_string


def add_functionary_key(layout, key):
  keyid = key["keyid"]
  layout.signed.keys[keyid] = key


def add_functionary_key_from_path(layout, key_path):
  key = securesystemslib.interface.import_rsa_publickey_from_file(
      key_path)
  add_functionary_key_to_layout(layout, key)


def add_functionary_gpg_key(layout, gpg_keyid=None, gpg_home=None):
  key = in_toto.gpg.functions.gpg_export_pubkey(gpg_keyid,
      homedir=gpg_home)
  add_functionary_key_to_layout(layout, key)


def remove_functionary_key(layout, keyid):
  del layout.signed.keys[keyid]


def get_step_name_list(layout):
  return [step.name for step in layout.signed.steps]


def get_inspection_name_list(layout):
  return [inspection.name for inspection in layout.signed.inspect]


def get_functionary_keyid_list(layout):
  return [keyid for keyid in list(layout.signed.keys.keys())]


def get_step(layout, step_name):
  for step in layout.signed.steps:
    if step.name == step_name:
      return step


def get_inspection(layout, inspection_name):
  for inspection in layout.signed.inspect:
    if inspection.name == inspection_name:
      return inspection


def get_functionary_key(layout, functionary_keyid):
  for keyid in list(layout.signed.keys.keys()):
    if keyid == functionary_keyid:
      return layout.signed.keys[keyid]







"""
THESE COULD  GO TO rulelib.py, I GUESS
"""

def _read_from_editor(text):
  # FIXME: Do we want our own implementation for this?
  try:
    import click

  except ImportError:
    print("Warning: Can't open editor. You have to install the Python"
        " package 'click'.")
    return text

  else:
    return click.edit(text)


RULE_EDITOR_HELPTEXT = """
# You can add artifact rules in any of the following formats. The order is
# important for evaluation.
# TODO: more explanation text or link to more explanation


# MATCH <pattern> [IN <source-prefix>] WITH MATERIALS [IN <dest-path-prefix>] FROM <step>
# MATCH <pattern> [IN <source-prefix>] WITH PRODUCTS [IN <dest-path-prefix>] FROM <step>
# CREATE <pattern>
# DELETE <pattern>
# MODIFY <pattern>
# ALLOW <pattern>
# DISALLOW <pattern>

# Empty lines and lines that start with a '#' will be ignored

"""


def _edit_rules(rule_list):
  # Concatenate help text and existing rules for editor
  rules_string = ""
  for rule in rule_list:
    rules_string += " ".join(rule) + "\n"
  editor_text = RULE_EDITOR_HELPTEXT + rules_string

  # Let user edit rules
  editor_result = _read_from_editor(editor_text)

  rule_list_result = []
  # Parse and validate edited rules
  for rule_line in editor_result.split("\n"):
    if rule_line and not rule_line.startswith("#"):
      rule = shlex.split(rule_line)
      # Raise exception if rule is invalid
      in_toto.artifact_rules.unpack_rule(rule)
      # otherwise append to rule_list
      rule_list_result.append(rule)

  return rule_list_result


def get_material_rules(item):
  return item.expected_materials


def get_product_rules(item):
  return item.expected_products


def set_material_rules(item, material_rule_list):
  item.expected_materials = material_rule_list


def set_product_rules(item, product_rule_list):
  item.expected_prodcuts = product_rule_list


def edit_material_rules(item):
  rule_list = _edit_rules(item.expected_materials)
  item.expected_materials = rule_list


def edit_product_rules(item):
  rule_list = _edit_rules(item.expected_materials)
  item.expected_products = rule_list
