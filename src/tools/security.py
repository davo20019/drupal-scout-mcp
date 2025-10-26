"""
Security analysis tools for Drupal Scout MCP server.

This module serves as a compatibility layer, re-exporting all security tools
from the modular security/ package structure.

For implementation details, see:
- src/tools/security/patterns.py - Vulnerability detection patterns
- src/tools/security/filters.py - False positive filtering
- src/tools/security/ast_analysis.py - AST-based analysis
- src/tools/security/tools/ - Individual scan tool implementations

Tools provided:
- scan_xss: Detect Cross-Site Scripting (XSS) vulnerabilities
- scan_sql_injection: Detect SQL injection vulnerabilities
- scan_access_control: Find missing permission checks
- scan_csrf: Review CSRF protection in custom handlers
- scan_command_injection: Detect command injection vulnerabilities
- scan_path_traversal: Detect path traversal vulnerabilities
- scan_hardcoded_secrets: Find hardcoded credentials and API keys
- scan_deprecated_api: Identify unsafe/deprecated API usage
- scan_anonymous_exploits: Identify remotely exploitable vulnerabilities (HIGH PRIORITY)
- verify_vulnerability: Explain how to manually verify vulnerabilities (EDUCATIONAL)
- security_audit: Run all security scans with prioritized report

These tools use deterministic pattern matching - no AI guessing.
All findings are concrete code patterns, not speculation.
"""

# Import all tools from the security package
from src.tools.security.tools.scan_xss import scan_xss
from src.tools.security.tools.scan_sql_injection import scan_sql_injection
from src.tools.security.tools.scan_access_control import scan_access_control
from src.tools.security.tools.scan_deprecated_api import scan_deprecated_api
from src.tools.security.tools.scan_csrf import scan_csrf
from src.tools.security.tools.scan_command_injection import scan_command_injection
from src.tools.security.tools.scan_path_traversal import scan_path_traversal
from src.tools.security.tools.scan_hardcoded_secrets import scan_hardcoded_secrets
from src.tools.security.tools.scan_anonymous_exploits import scan_anonymous_exploits
from src.tools.security.tools.security_audit import security_audit
from src.tools.security import verify_vulnerability

# Re-export all tools for MCP discovery
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
    "verify_vulnerability",
    "security_audit",
]
