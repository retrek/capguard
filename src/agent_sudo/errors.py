class BrokerError(Exception):
    """Base error for broker failures."""


class PolicyError(BrokerError):
    """Raised when policy parsing or validation fails."""


class ArgumentError(BrokerError):
    """Raised when capability arguments are invalid."""


class ApprovalDenied(BrokerError):
    """Raised when the user rejects a confirmation prompt."""


class ExecutionError(BrokerError):
    """Raised when command execution fails."""


class TimeoutError(ExecutionError):
    """Raised when command execution exceeds its timeout."""
