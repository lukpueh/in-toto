
import six
import sys
from prompt_toolkit import prompt as prompttk
from prompt_toolkit.shortcuts.dialogs import yes_no_dialog

from in_toto.models.metadata import Metablock
from in_toto.models.layout import Layout, Step, Inspection



"""Generic commands
"""
def exit_():
  if yes_no_dialog(
      title="Exit", text="Are you sure you want to exit?"):
    sys.exit()

def help_(commands):
  ordered_commands = sorted(list(commands.keys()))
  for name in ordered_commands:
    message = name
    message_help = commands[name].get("help")

    if message_help:
      message += ": " + message_help

    print(message)


def break_(**kwargs):
  return True


"""Prompt constants and commands
"""
def load(**kwargs):
  if len(kwargs["args"]) < 1:
    print("You have to specify a path.")
    return

  try:
    layout = Metablock.load(kwargs["args"][0])

  except:
    print("Could not load layout from '{}'.".format(kwargs["args"][0]))

  else:
    prompt_layout(layout)


def create(**kwargs):
  prompt_layout(Metablock(signed=Layout()))

PROMPT = "in-toto> "
COMMANDS = {
  "load": {
    "func": load,
    "help": "Load existing layout from file 'load <path/to/layout>'."
    },
  "create": {
    "func": create,
    "help": "Create new layout."
    }
  }




"""Layout constants and commands
"""
def layout_show(**kwargs):
  print(kwargs["layout"])

def layout_show_signatures(**kwargs):
  print(kwargs["layout"].signatures)

def layout_show_readme(**kwargs):
  print(kwargs["layout"].signed.readme)

def layout_show_expires(**kwargs):
  print(kwargs["layout"].signed.expires)

def layout_show_keys(**kwargs):
  for keyid, key in six.iteritems(kwargs["layout"].signed.keys):
    print(keyid)

def layout_show_steps(**kwargs):
  for step in kwargs["layout"].signed.steps:
    print(step.name)

def layout_show_inspections(**kwargs):
  for inspection in kwargs["layout"].signed.inspect:
    print(inspection.name)



def layout_add_step(**kwargs):
  if len(kwargs["args"]) < 1:
    print("You have to specify a step name.")
    return

  name = kwargs["args"][0]
  for step in kwargs["layout"].signed.steps:
    if step.name == name:
      print("Step with name '{}' already exists. Step names have to"
        " be unique. Please choose a different name".format(name))
      return

  step = Step(name=name)
  kwargs["layout"].signed.steps.append(step)
  prompt_step(layout=kwargs["layout"], step=step)


def layout_add_inspection(**kwargs):
  if len(kwargs["args"]) < 1:
    print("You have to specify an inspection name.")
    return

  name = kwargs["args"][0]
  for step in kwargs["layout"].signed.inspect:
    if step.name == name:
      print("Inspection with name '{}' already exists. Inspection names have"
        " to be unique. Please choose a different name".format(name))
      return

  inspection = Inspection(name=name)
  kwargs["layout"].signed.inspect.append(inspection)
  prompt_inspection(layout=kwargs["layout"], inspection=inspection)


def layout_edit_step(**kwargs):
  if len(kwargs["args"]) < 1:
    print("You have to specify a step name.")
    return

  name = kwargs["args"][0]
  step_to_edit = None
  for step in kwargs["layout"].signed.steps:
    if step.name == name:
      step_to_edit = step

  if not step_to_edit:
    print("Step with name '{}' not found in layout.".format(name))
    return

  prompt_step(layout=kwargs["layout"], step=step_to_edit)


def layout_edit_inspection(**kwargs):
  if len(kwargs["args"]) < 1:
    print("You have to specify an inspection name.")
    return

  name = kwargs["args"][0]
  inspection_to_edit = None
  for inspection in kwargs["layout"].signed.inspect:
    if inspection.name == name:
      inspection_to_edit = step

  if not inspection_to_edit:
    print("Inspection with name '{}' not found in layout.".format(name))
    return

  prompt_step(layout=kwargs["layout"], step=inspection_to_edit)


def layout_remove_step(**kwargs):
  pass


def layout_remove_inspection(**kwargs):
  pass


LAYOUT_PROMPT = "in-toto#layout> "
LAYOUT_COMMANDS = {
  "show": {
    "func": layout_show,
    "help": "Print layout (properties) 'show [property]'",
    "subcommands": {
      "signatures": {
        "func": layout_show_signatures,
        "help": "Print layout signatures"
      },
      "readme": {
        "func": layout_show_readme,
        "help": "Print layout readme"
      },
      "expires": {
        "func": layout_show_expires,
        "help": "Print layout expiration date"
      },
      "keys": {
        "func": layout_show_keys,
        "help": "Print layout public keys"
        },
      "steps": {
        "func": layout_show_steps,
        "help": "Print layout steps"
        },
      "inspections": {
        "func": layout_show_inspections,
        "help": "Print layout inspections"
        }
      }
    },
  "add": {
    "help": "Add step or inspection and drop to prompt to edit them",
    "subcommands": {
      "step": {
        "help": "Add step to layout 'add step <name>'",
        "func": layout_add_step
      },
      "inspection": {
        "help": "Add inspection to layout 'add inspection <name>'",
        "func": layout_add_inspection
      }
    }
  },
  "edit": {
    "help": "Drop to step or inspection prompt to edit the item",
    "subcommands": {
      "step": {
        "help": "Edit existing step by name 'edit step <name>'",
        "func": layout_edit_step
      },
      "inspection": {
        "help": "Edit existing inspection by name 'edit inspection <name>'",
        "func": layout_edit_inspection
      }
    }
  },
  "remove": {
    "help": "Remove step or inspection",
    "subcommands": {
      "step": {
        "help": "Remove step by name 'remove step <name>'",
        "func": layout_remove_step
      },
      "inspection": {
        "help": "Remove inspection by name 'remove inspection <name>'",
        "func": layout_remove_inspection
      }
    }
  }
}






"""Step commands and constants
"""
def step_show(**kwargs):
  pass

PROMPT_STEP = "in-toto#layout#step> "
COMMANDS_STEP = {
  "show": {
    "func": step_show,
    },
  "back": {
    "func": break_
    }
  }





"""Inspection commands and constants
"""
def inspection_show(**kwargs):
  pass

PROMPT_INSEPCTION = "in-toto#layout#inspection> "
COMMANDS_INSEPCTION = {
  "show": {
    "func": inspection_show,
    },
  "back": {
    "func": break_
    }
  }




"""Prompts
"""
def _generic_prompt(prompt_text, commands, layout=None, item=None):
  while True:
    text = prompttk(prompt_text)

    if not text:
      continue

    not_a_valid_command = False
    text_list = text.split()
    if text_list[0] == "exit":
      exit_()

    elif text_list[0] == "help":
      help_(commands)

    elif text_list[0] in commands:
      command_data = commands[text_list[0]]
      command_args = text_list[1:]
      subcommands = command_data.get("subcommands")
      func = None

      # TODO: Maybe some recursive command/subcommand function would be nicer?
      if subcommands and command_args:
        if command_args[0] in subcommands:
          subcommand_data = subcommands[command_args[0]]
          command_args = command_args[1:]
          func = subcommand_data["func"]

      else:
        func = command_data.get("func")

      if func:
        #TODO: enable back (break) check return command
        ret = func(args=command_args, layout=layout, item=item)

        if ret == True:
          break

      else:
        not_a_valid_command = True



    else:
      not_a_valid_command = True

    if not_a_valid_command:
      print("You have to input a valid command. Try 'help'.")



def prompt():
  _generic_prompt(PROMPT, COMMANDS)

def prompt_layout(layout):
  _generic_prompt(LAYOUT_PROMPT, LAYOUT_COMMANDS, layout=layout)

def prompt_step(layout, step):
  _generic_prompt(PROMPT_STEP, COMMANDS_STEP, layout=layout, item=step)

def prompt_inspection(layout, inspection):
  _generic_prompt(PROMPT_INSEPCTION, COMMANDS_INSEPCTION, layout=layout,
      item=inspection)


if __name__ == "__main__":
  prompt()