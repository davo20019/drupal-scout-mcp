"""
Security analysis tools for Drupal Scout MCP.

This package provides comprehensive security scanning for Drupal modules:
- Pattern-based vulnerability detection
- AST-enhanced analysis with tree-sitter-php
- Drupal-aware false positive filtering
- Educational verification guidance

Structure:
- tools/ - Individual MCP tools (scan_xss, scan_sql_injection, etc.)
- models.py - Data models (SecurityFinding)
- patterns.py - Vulnerability detection patterns (TODO: extract from security.py)
- filters.py - False positive filtering logic (TODO: extract from security.py)
- ast_analysis.py - tree-sitter AST validation (TODO: extract from security.py)
- scanners.py - Core scanning infrastructure (TODO: extract from security.py)

TODO: Refactor security.py (2500+ lines) into this modular structure.
See: https://github.com/davo20019/drupal-scout-mcp/issues/TBD
"""

# Import tools from subdirectory
from .tools.verify_vulnerability import verify_vulnerability

# Export for MCP auto-discovery
__all__ = [
    "verify_vulnerability",
]
