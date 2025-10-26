"""
SQL Injection vulnerability scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components  # noqa: E402
from src.tools.security.patterns import SQL_INJECTION_PATTERNS  # noqa: E402
from src.tools.security.ast_analysis import (  # noqa: E402
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path  # noqa: E402


@mcp.tool()
def scan_sql_injection(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Scan a Drupal module for SQL injection vulnerabilities.

    Uses pattern-based detection to find:
    - db_query with concatenation
    - SQL queries with string concatenation
    - mysqli/PDO without prepared statements
    - EntityQuery with unsanitized user input

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and remediation steps

    Example:
        scan_sql_injection("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 SQL INJECTION SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for SQL injection patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, SQL_INJECTION_PATTERNS, "sql_injection")
        all_findings.extend(findings)

    # Format results
    output.append(_format_findings(all_findings, "SQL Injection Vulnerabilities", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")
        output.append("  • https://www.drupal.org/docs/drupal-apis/database-api")
        output.append("")
        output.append("⚠️  LIMITATIONS: May miss multi-line concatenation and complex data flow.")
        output.append("   For production audits, use manual review + static analysis tools.")
    else:
        output.append("✅ No SQL injection vulnerabilities detected using common patterns.")
        output.append(
            "   Note: This is pattern-based detection. Manual review is still recommended."
        )

    return "\n".join(output)
