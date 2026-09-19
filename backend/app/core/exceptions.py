class AnalyzerError(Exception):
    """Base exception for expected analyzer/application failures."""


class InvalidInputError(AnalyzerError):
    """Raised when an analysis input cannot be safely processed."""
