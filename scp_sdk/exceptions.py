"""
Exception classes for the SCP SDK.
"""


class SCPError(Exception):
    """Base exception for all SCP SDK errors."""
    
    def __init__(self, message: str, error_code: str = None, status_code: int = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


class SCPConnectionError(SCPError):
    """Raised when connection to SCP server fails."""
    pass


class SCPAuthenticationError(SCPError):
    """Raised when authentication with SCP server fails."""
    pass


class SCPSessionError(SCPError):
    """Raised when session-related operations fail."""
    pass


class SCPTimeoutError(SCPError):
    """Raised when requests to SCP server timeout."""
    pass


class SCPValidationError(SCPError):
    """Raised when input validation fails."""
    pass