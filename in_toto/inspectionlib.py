in_toto.models.layout

def set_name(inspection, inspection_name):
  in_toto.models.layout.inspection.name = inspection_name


def set_run(inspection, command_list):
  in_toto.models.layout.inspection.run = command_list


def set_run_from_string(inspection, command_string):
  in_toto.models.layout.inspection.run = shlex.split(command_string)