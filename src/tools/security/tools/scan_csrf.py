"""
CSRF (Cross-Site Request Forgery) protection scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from pathlib import Path
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components
from src.tools.security.patterns import CSRF_PATTERNS
from src.tools.security.filters import _is_false_positive
from src.tools.security.ast_analysis import (
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path


@mcp.tool()
def scan_csrf(module_name: str, module_path: Optional[str] = None, max_findings: int = 50) -> str:
    """
    Scan a Drupal module for CSRF (Cross-Site Request Forgery) protection issues.

    Drupal provides automatic CSRF protection through:
    - Form API (automatic token generation and validation)
    - Route requirements (_csrf_token: 'TRUE')
    - \\Drupal::csrfToken()->validate() for custom handlers

    This scan helps identify custom routes/handlers that may lack protection.

    Detects:
    - Custom POST handlers outside Form API
    - State-changing operations (save/delete/update)
    - Potential GET routes with state changes (CSRF risk)

    Note: This is an advisory scan. Many findings are informational
    - AI should investigate routing files to confirm CSRF handling.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and verification steps

    Example:
        scan_csrf("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 CSRF PROTECTION SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for CSRF patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, CSRF_PATTERNS, "csrf")
        all_findings.extend(findings)

    # Format results with limit
    output.append(_format_findings(all_findings, "CSRF Protection Review", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 HOW TO VERIFY:")
        output.append("")
        output.append("1. Check routing files (*.routing.yml) for:")
        output.append("   - Route method (GET vs POST/DELETE)")
        output.append("   - _csrf_token: 'TRUE' requirement")
        output.append("")
        output.append("2. For Form API usage:")
        output.append("   - Extends FormBase/ConfigFormBase = Auto CSRF ✅")
        output.append("   - Uses #ajax = Auto CSRF ✅")
        output.append("")
        output.append("3. For custom handlers:")
        output.append("   - Look for \\Drupal::csrfToken()->validate()")
        output.append("   - Verify POST/DELETE methods used for state changes")
        output.append("")
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/csrf-protection")
        output.append("  • https://www.drupal.org/docs/drupal-apis/form-api")
        output.append("")
        output.append("⚠️  NOTE: CSRF scan shows potential areas to review.")
        output.append("   Use list_module_files() to check routing files (*.routing.yml)")
        output.append("   Use read_module_file() to inspect route definitions")
    else:
        output.append("✅ No obvious CSRF protection gaps detected.")
        output.append("")
        output.append("⚠️  Note: This scan checks for patterns in PHP code.")
        output.append(
            "   AI should verify routing files (*.routing.yml) for complete CSRF analysis."
        )
        output.append("")
        output.append("Recommendations:")
        output.append(f"  1. list_module_files('{module_name}', '*.routing.yml')")
        output.append(f"  2. read_module_file('{module_name}', '<module>.routing.yml')")
        output.append("  3. Check route methods and _csrf_token requirements")

    return "\n".join(output)
