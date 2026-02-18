class HsmClientError(RuntimeError):
    """Base client error."""


class HsmConfigurationError(HsmClientError):
    """Configuration is invalid or incomplete."""


class HsmOperationError(HsmClientError):
    """An HSM operation failed."""
