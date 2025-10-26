"""
Command injection vulnerability scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components  # noqa: E402
from src.tools.security.patterns import COMMAND_INJECTION_PATTERNS  # noqa: E402
from src.tools.security.ast_analysis import (  # noqa: E402
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path  # noqa: E402


@mcp.tool()
def scan_command_injection(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Scan a Drupal module for command injection vulnerabilities.

    Uses pattern-based detection to find:
    - exec(), shell_exec(), system(), passthru() with variables
    - Backtick shell execution operator
    - Drush shell commands with variables
    - PHP mail() with user input (header injection)

    Analysis method: Pattern matching + Drupal-aware filtering
    Detects dangerous shell command execution patterns

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and remediation steps

    Example:
        scan_command_injection("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 COMMAND INJECTION SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for command injection patterns
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(
            php_file, COMMAND_INJECTION_PATTERNS, "command_injection"
        )
        all_findings.extend(findings)

    # Format results
    output.append(_format_findings(all_findings, "Command Injection Vulnerabilities", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")
        output.append("  • https://owasp.org/www-community/attacks/Command_Injection")
        output.append("")
        output.append("⚠️  LIMITATIONS: May miss indirect command execution and complex flow.")
        output.append("   For production audits, use manual review + static analysis tools.")
    else:
        output.append("✅ No command injection vulnerabilities detected using common patterns.")
        output.append(
            "   Note: This is pattern-based detection. Manual review is still recommended."
        )

    return "\n".join(output)
