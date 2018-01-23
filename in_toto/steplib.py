import in_toto.models.layout

def set_name(step, step_name):
  step.validate()
  if not (step_name and in_toto.formats.step_
  in_toto.models.layout.step.name = step_name


def set_expected_command(step, command_list):
  step.validate()
  in_toto.models.layout.step.expected_command = command_list


def set_expected_command_from_string(step, command_string):
  step.validate()
  in_toto.models.layout.step.expected_command = shlex.split(command_string)


def set_threshold(step, threshold):
  step.validate()
  in_toto.models.layout.step.threshold = threshold


def add_functionary_keyid(step, keyid):
  in_toto.models.layout.step.pubkeys.append(keyid)


def remove_functionary_keyid(step, keyid):
 in_toto.models.layout.step.pubkeys.remove(keyid)
