"""
Security analysis tools for Drupal Scout MCP.

This package provides comprehensive security scanning for Drupal modules:
- Pattern-based vulnerability detection
- AST-enhanced analysis with tree-sitter-php
- Drupal-aware false positive filtering
- Educational verification guidance

Package Structure:
- models.py - Data models (SecurityFinding)
- patterns.py - Vulnerability detection patterns (8 categories, 40+ patterns)
- filters.py - False positive filtering logic (Drupal-aware)
- ast_analysis.py - tree-sitter AST validation + scanning infrastructure
- tools/ - Individual MCP tools:
  * scan_xss.py - XSS vulnerability detection
  * scan_sql_injection.py - SQL injection detection
  * scan_access_control.py - Access control analysis
  * scan_deprecated_api.py - Deprecated API detection
  * scan_csrf.py - CSRF protection review
  * scan_command_injection.py - Command injection detection
  * scan_path_traversal.py - Path traversal detection
  * scan_hardcoded_secrets.py - Hardcoded credentials detection
  * scan_anonymous_exploits.py - Anonymous exploit detection (HIGH PRIORITY)
  * security_audit.py - Comprehensive security audit
  * verify_vulnerability.py - Educational verification guide

All tools are registered with MCP and auto-discovered by the server.
"""

# Import all tools for MCP auto-discovery
from .tools.scan_xss import scan_xss
from .tools.scan_sql_injection import scan_sql_injection
from .tools.scan_access_control import scan_access_control
from .tools.scan_deprecated_api import scan_deprecated_api
from .tools.scan_csrf import scan_csrf
from .tools.scan_command_injection import scan_command_injection
from .tools.scan_path_traversal import scan_path_traversal
from .tools.scan_hardcoded_secrets import scan_hardcoded_secrets
from .tools.scan_anonymous_exploits import scan_anonymous_exploits
from .tools.security_audit import security_audit
from .tools.verify_vulnerability import verify_vulnerability

# Export for MCP auto-discovery
__all__ = [
    "scan_xss",
    "scan_sql_injection",
    "scan_access_control",
    "scan_deprecated_api",
    "scan_csrf",
    "scan_command_injection",
    "scan_path_traversal",
    "scan_hardcoded_secrets",
    "scan_anonymous_exploits",
    "security_audit",
    "verify_vulnerability",
]
