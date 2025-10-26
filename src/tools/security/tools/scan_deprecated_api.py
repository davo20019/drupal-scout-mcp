"""
Deprecated and unsafe API usage scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from pathlib import Path
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components
from src.tools.security.patterns import DEPRECATED_API_PATTERNS
from src.tools.security.filters import _is_false_positive
from src.tools.security.ast_analysis import (
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path


@mcp.tool()
def scan_deprecated_api(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Scan a Drupal module for deprecated or unsafe API usage.

    Uses pattern-based detection to find:
    - Drupal 7 functions in D8+ code
    - eval() usage
    - unserialize() with user input
    - Deprecated PHP functions (create_function, extract, assert)
    - Other unsafe patterns

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and remediation steps

    Example:
        scan_deprecated_api("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 DEPRECATED/UNSAFE API SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for deprecated API patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, DEPRECATED_API_PATTERNS, "deprecated_api")
        all_findings.extend(findings)

    # Format results
    output.append(_format_findings(all_findings, "Deprecated/Unsafe API Usage", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/drupal-apis/api-change-records")
        output.append("  • https://www.php.net/manual/en/migration80.deprecated.php")
        output.append("")
        output.append("⚠️  LIMITATIONS: Detects known patterns only.")
        output.append("   May miss custom wrappers or indirect usage.")
    else:
        output.append("✅ No deprecated or unsafe API usage detected using common patterns.")
        output.append(
            "   Note: This is pattern-based detection. Manual review is still recommended."
        )

    return "\n".join(output)
