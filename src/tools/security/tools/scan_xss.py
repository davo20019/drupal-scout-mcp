"""
XSS (Cross-Site Scripting) vulnerability scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from pathlib import Path
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components
from src.tools.security.patterns import XSS_PATTERNS
from src.tools.security.filters import _is_false_positive
from src.tools.security.ast_analysis import (
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path


@mcp.tool()
def scan_xss(module_name: str, module_path: Optional[str] = None, max_findings: int = 50) -> str:
    """
    Scan a Drupal module for Cross-Site Scripting (XSS) vulnerabilities.

    Uses pattern-based detection (optionally enhanced with AST analysis):
    - Unescaped print/echo statements
    - Unsafe render arrays
    - Direct superglobal output
    - JavaScript innerHTML usage
    - drupal_set_message with variables

    Analysis method: AST-based validation (tree-sitter) + Pattern matching + Drupal-aware filtering
    Provides enhanced accuracy with understanding of PHP syntax and Drupal APIs

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50, prevents token overflow)

    Returns:
        Formatted report with findings and remediation steps

    Examples:
        scan_xss("my_custom_module")
        scan_xss("large_module", max_findings=20)  # Limit for large modules
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 XSS SECURITY SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for XSS patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, XSS_PATTERNS, "xss")
        all_findings.extend(findings)

    # Format results with limit
    output.append(_format_findings(all_findings, "XSS Vulnerabilities", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")
        output.append("  • https://www.drupal.org/node/101495 (XSS prevention)")
        if len(all_findings) > max_findings:
            output.append("")
            output.append(
                f"💡 Use scan_xss('{module_name}', max_findings=100) to see more findings"
            )
        output.append("")
        output.append("⚠️  LIMITATIONS: Pattern-based analysis may miss:")
        output.append("   - Multi-line code patterns and complex data flow")
        output.append("   - Variables passed through functions")
        output.append("   - For production audits, also use manual review + PHPStan/Psalm")
    else:
        output.append("✅ No XSS vulnerabilities detected using common patterns.")
        output.append("")
        output.append("⚠️  Note: Pattern-based detection has limitations.")
        output.append("   Always perform manual security review for critical code.")

    return "\n".join(output)
