"""
Path traversal vulnerability scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from pathlib import Path
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components
from src.tools.security.patterns import PATH_TRAVERSAL_PATTERNS
from src.tools.security.filters import _is_false_positive
from src.tools.security.ast_analysis import (
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path


@mcp.tool()
def scan_path_traversal(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Scan a Drupal module for path traversal vulnerabilities.

    Uses pattern-based detection to find:
    - File includes with user input (include, require)
    - File read operations with user input (file_get_contents, fopen)
    - Directory traversal patterns (../)
    - Drupal file operations without validation
    - File deletion with user input

    Analysis method: Pattern matching + Drupal-aware filtering
    Understands Drupal stream wrappers (public://, private://)

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and remediation steps

    Example:
        scan_path_traversal("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 PATH TRAVERSAL SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for path traversal patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, PATH_TRAVERSAL_PATTERNS, "path_traversal")
        all_findings.extend(findings)

    # Format results
    output.append(_format_findings(all_findings, "Path Traversal Vulnerabilities", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")
        output.append(
            "  • https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"
        )
        output.append("")
        output.append("⚠️  LIMITATIONS: May miss complex path manipulation and validation.")
        output.append("   For production audits, use manual review + penetration testing.")
    else:
        output.append("✅ No path traversal vulnerabilities detected using common patterns.")
        output.append(
            "   Note: This is pattern-based detection. Manual review is still recommended."
        )

    return "\n".join(output)
