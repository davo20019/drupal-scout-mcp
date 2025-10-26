"""Data models for security scanning."""

from dataclasses import dataclass


@dataclass
class SecurityFinding:
    """Represents a security finding with location and details."""

    severity: str  # "high", "medium", "low"
    category: str  # "xss", "sql_injection", "access_control", etc.
    file: str
    line: int
    code: str
    description: str
    recommendation: str
