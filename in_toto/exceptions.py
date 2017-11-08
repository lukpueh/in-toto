import securesystemslib.exceptions as exceptions

class SignatureVerificationError(exceptions.Error):
  """Indicates a signature verification Error. """
  pass

class LayoutExpiredError(exceptions.Error):
  """Indicates that the layout expired. """
  pass

class RuleVerficationError(exceptions.Error):
  """Indicates that artifact rule verification failed. """
  pass

class ThresholdVerificationError(exceptions.Error):
  """Indicates that signature threshold verification failed. """
  pass

class BadReturnValueError(exceptions.Error):
  """Indicates that a ran command exited with non-int or non-zero return
  value. """
  pass

class LinkNotFoundError(exceptions.Error):
  """Indicates that a link file was not found. """
  pass

class AuthorizationError(exceptions.Error):
  """Indicates that the link was signed by a non-authorized functionary. """
  pass

class SettingsError(exceptions.Error):
  """Indicates an invalid setting. """
  pass
