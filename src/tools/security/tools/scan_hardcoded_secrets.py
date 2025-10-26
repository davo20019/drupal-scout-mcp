"""
Hardcoded credentials and secrets scanner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from typing import Optional

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components  # noqa: E402
from src.tools.security.patterns import HARDCODED_SECRETS_PATTERNS  # noqa: E402
from src.tools.security.ast_analysis import (  # noqa: E402
    _get_php_files,
    _scan_file_for_patterns,
    _format_findings,
)
from src.tools.code_analysis import _find_module_path  # noqa: E402


@mcp.tool()
def scan_hardcoded_secrets(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Scan a Drupal module for hardcoded secrets and credentials.

    Uses pattern-based detection to find:
    - API keys hardcoded in code
    - Passwords in variables
    - Database credentials
    - Private/secret keys
    - OAuth tokens
    - AWS credentials

    Analysis method: Pattern matching + False positive filtering
    Excludes test files, examples, placeholders, and comments

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with findings and remediation steps

    Example:
        scan_hardcoded_secrets("my_custom_module")
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🔍 HARDCODED SECRETS SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files...")
    output.append("")

    # Scan for hardcoded secrets
    all_findings = []
    for php_file in php_files:
        findings = _scan_file_for_patterns(
            php_file, HARDCODED_SECRETS_PATTERNS, "hardcoded_secrets"
        )
        all_findings.extend(findings)

    # Format results
    output.append(_format_findings(all_findings, "Hardcoded Secrets", max_findings))
    output.append("")
    output.append("─" * 80)
    output.append("")

    if all_findings:
        output.append("📚 BEST PRACTICES:")
        output.append("  • Use Drupal Key module: https://www.drupal.org/project/key")
        output.append("  • Store secrets in settings.php (excluded from version control)")
        output.append("  • Use environment variables")
        output.append("  • Never commit secrets to git")
        output.append("")
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/managing-sensitive-data")
        output.append(
            "  • https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
        )
        output.append("")
        output.append("⚠️  LIMITATIONS: Pattern-based detection may have false positives.")
        output.append("   May flag example values in documentation. Review each finding.")
    else:
        output.append("✅ No hardcoded secrets detected using common patterns.")
        output.append(
            "   Note: This is pattern-based detection. Manual review is still recommended."
        )

    return "\n".join(output)
