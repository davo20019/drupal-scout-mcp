"""
Individual security scanning tools for Drupal Scout MCP.

Each tool is in its own file for maintainability and clear separation of concerns.

Available Tools:
- scan_xss.py - XSS (Cross-Site Scripting) vulnerability scanner
- scan_sql_injection.py - SQL injection vulnerability scanner
- scan_access_control.py - Access control and permission scanner
- scan_deprecated_api.py - Deprecated and unsafe API usage scanner
- scan_csrf.py - CSRF (Cross-Site Request Forgery) protection scanner
- scan_command_injection.py - Command injection vulnerability scanner
- scan_path_traversal.py - Path traversal vulnerability scanner
- scan_hardcoded_secrets.py - Hardcoded credentials and secrets scanner
- scan_anonymous_exploits.py - Anonymous exploit detection scanner (HIGH PRIORITY)
- security_audit.py - Comprehensive security audit runner (calls all scans)
- verify_vulnerability.py - Educational vulnerability verification guide

All tools use:
- Pattern-based detection (src/tools/security/patterns.py)
- False positive filtering (src/tools/security/filters.py)
- Optional AST enhancement (src/tools/security/ast_analysis.py)

Tools are registered with @mcp.tool() decorator for auto-discovery.
"""
