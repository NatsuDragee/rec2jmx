"""Exception types whose messages are safe to show to users.

Messages must never contain recorded header values, bodies, or full URLs,
because those may carry credentials.
"""


class Rec2JmxError(Exception):
    """Base class for errors with a user-facing message."""


class InputError(Rec2JmxError):
    """The input is unsupported, malformed, too large, or ambiguous."""


class PlanError(Rec2JmxError):
    """A review plan or generation option is invalid."""


class GenerationError(Rec2JmxError):
    """A JMeter plan could not be generated safely."""


class ValidationError(Rec2JmxError):
    """A generated plan failed validation, or validation could not run safely."""
