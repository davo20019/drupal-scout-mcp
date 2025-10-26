"""
Access control and permission scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from pathlib import Path
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components
from src.tools.security.patterns import ACCESS_CONTROL_PATTERNS
from src.tools.security.filters import _is_false_positive
from src.tools.security.ast_analysis import (
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path


@mcp.tool()
def scan_access_control(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Scan a Drupal module for missing access control checks.

    Uses pattern-based detection to find:
    - Routes without _permission or _access requirements
    - Forms without access checks
    - Entity modifications without access verification
    - User data access without permission checks

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and remediation steps

    Example:
        scan_access_control("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 ACCESS CONTROL SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for access control patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, ACCESS_CONTROL_PATTERNS, "access_control")
        all_findings.extend(findings)

    # Format results
    output.append(_format_findings(all_findings, "Access Control Issues", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/drupal-apis/access-api")
        output.append("  • https://www.drupal.org/docs/drupal-apis/routing-system")
        output.append("")
        output.append("⚠️  LIMITATIONS: Cannot detect access checks across multiple functions.")
        output.append("   Manual review recommended for complex permission logic.")
    else:
        output.append("✅ No access control issues detected using common patterns.")
        output.append(
            "   Note: This is pattern-based detection. Manual review is still recommended."
        )

    return "\n".join(output)
