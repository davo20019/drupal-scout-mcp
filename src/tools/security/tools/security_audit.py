"""
Comprehensive security audit runner.

Part of Drupal Scout MCP security scanning suite.
"""

import logging
from pathlib import Path
from typing import Optional, Dict, List

from src.core.config import ensure_indexed
from server import mcp

logger = logging.getLogger(__name__)


# Import shared components  # noqa: E402
from src.tools.security.patterns import (  # noqa: E402
    XSS_PATTERNS,
    SQL_INJECTION_PATTERNS,
    ACCESS_CONTROL_PATTERNS,
    CSRF_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    HARDCODED_SECRETS_PATTERNS,
    DEPRECATED_API_PATTERNS,
)
from src.tools.security.ast_analysis import (  # noqa: E402
    _get_php_files,
    _scan_file_for_patterns,
)
from src.tools.security.models import SecurityFinding  # noqa: E402
from src.tools.code_analysis import _find_module_path  # noqa: E402


@mcp.tool()
def security_audit(
    module_name: str,
    module_path: Optional[str] = None,
    mode: str = "summary",
    severity_filter: Optional[str] = None,
    max_findings: int = 50,
) -> str:
    """
    Run a comprehensive security audit on a Drupal module.

    Executes all security scans:
    - XSS vulnerabilities
    - SQL injection vulnerabilities
    - Access control issues
    - CSRF protection review
    - Command injection vulnerabilities
    - Path traversal vulnerabilities
    - Hardcoded secrets
    - Deprecated/unsafe API usage

    Provides a prioritized report with severity-based recommendations.

    This tool does NOT use AI - all findings are concrete code patterns.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        mode: "summary" (counts only), "findings" (detailed), or "high_only" (HIGH severity details)
        severity_filter: Filter by severity: "high", "medium", "low", or None for all
        max_findings: Maximum findings to show in detail (default: 50, prevents token overflow)

    Returns:
        Security audit report (format depends on mode)

    Examples:
        security_audit("my_module")  # Summary with counts
        security_audit("my_module", mode="high_only")  # Only HIGH severity details
        security_audit("my_module", mode="findings", max_findings=20)  # First 20 findings
        security_audit("my_module", severity_filter="high")  # Summary of HIGH only
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🛡️  SECURITY AUDIT: {module_name}")
    output.append("=" * 80)
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    output.append(f"Scanning {len(php_files)} PHP files for security issues...")
    output.append(f"Mode: {mode.upper()}")
    if severity_filter:
        output.append(f"Filter: {severity_filter.upper()} severity only")
    output.append("")
    output.append("─" * 80)
    output.append("")

    # Run all scans
    all_findings = []

    # XSS scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, XSS_PATTERNS, "xss")
        all_findings.extend(findings)

    # SQL injection scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, SQL_INJECTION_PATTERNS, "sql_injection")
        all_findings.extend(findings)

    # Access control scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, ACCESS_CONTROL_PATTERNS, "access_control")
        all_findings.extend(findings)

    # Deprecated API scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, DEPRECATED_API_PATTERNS, "deprecated_api")
        all_findings.extend(findings)

    # CSRF protection scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, CSRF_PATTERNS, "csrf")
        all_findings.extend(findings)

    # Command injection scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(
            php_file, COMMAND_INJECTION_PATTERNS, "command_injection"
        )
        all_findings.extend(findings)

    # Path traversal scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, PATH_TRAVERSAL_PATTERNS, "path_traversal")
        all_findings.extend(findings)

    # Hardcoded secrets scan
    for php_file in php_files:
        findings = _scan_file_for_patterns(
            php_file, HARDCODED_SECRETS_PATTERNS, "hardcoded_secrets"
        )
        all_findings.extend(findings)

    # Apply severity filter if specified
    if severity_filter:
        all_findings = [f for f in all_findings if f.severity == severity_filter.lower()]

    # Summary by category
    xss_findings = [f for f in all_findings if f.category == "xss"]
    sql_findings = [f for f in all_findings if f.category == "sql_injection"]
    access_findings = [f for f in all_findings if f.category == "access_control"]
    deprecated_findings = [f for f in all_findings if f.category == "deprecated_api"]
    csrf_findings = [f for f in all_findings if f.category == "csrf"]
    cmd_injection_findings = [f for f in all_findings if f.category == "command_injection"]
    path_traversal_findings = [f for f in all_findings if f.category == "path_traversal"]
    secrets_findings = [f for f in all_findings if f.category == "hardcoded_secrets"]

    output.append("📊 SUMMARY")
    output.append("")
    output.append(f"Total Issues: {len(all_findings)}")
    output.append(f"  • XSS: {len(xss_findings)}")
    output.append(f"  • SQL Injection: {len(sql_findings)}")
    output.append(f"  • Access Control: {len(access_findings)}")
    output.append(f"  • CSRF Protection: {len(csrf_findings)}")
    output.append(f"  • Command Injection: {len(cmd_injection_findings)}")
    output.append(f"  • Path Traversal: {len(path_traversal_findings)}")
    output.append(f"  • Hardcoded Secrets: {len(secrets_findings)}")
    output.append(f"  • Deprecated/Unsafe API: {len(deprecated_findings)}")
    output.append("")

    # Severity breakdown
    high_findings = [f for f in all_findings if f.severity == "high"]
    medium_findings = [f for f in all_findings if f.severity == "medium"]
    low_findings = [f for f in all_findings if f.severity == "low"]

    output.append("Severity Breakdown:")
    output.append(f"  • HIGH: {len(high_findings)}")
    output.append(f"  • MEDIUM: {len(medium_findings)}")
    output.append(f"  • LOW: {len(low_findings)}")
    output.append("")

    if not all_findings:
        output.append("✅ No security issues detected using common patterns.")
        output.append("")
        output.append("This module appears to follow Drupal security best practices.")
        output.append(
            "Note: This is pattern-based detection. Manual security review is still recommended."
        )
        return "\n".join(output)

    # SUMMARY MODE: Just show counts, no details
    if mode == "summary":
        output.append("─" * 80)
        output.append("")
        output.append("📝 MODE: SUMMARY (counts only)")
        output.append("")

        if high_findings:
            output.append("⚠️  CRITICAL: Module has HIGH severity security issues!")
            output.append("")

        output.append("For detailed analysis, use:")
        output.append(
            f"  • security_audit('{module_name}', mode='high_only') - Show HIGH severity details"
        )
        output.append(
            f"  • security_audit('{module_name}', mode='findings', max_findings=20) - Show first 20 findings"
        )
        output.append(f"  • scan_xss('{module_name}') - XSS analysis only")
        output.append(f"  • scan_sql_injection('{module_name}') - SQL injection analysis only")
        output.append("")
        output.append("Resources:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")

        return "\n".join(output)

    # HIGH_ONLY MODE: Show only HIGH severity findings
    if mode == "high_only":
        if not high_findings:
            output.append("✅ No HIGH severity issues found!")
            output.append("")
            output.append(
                f"Note: Module has {len(medium_findings)} MEDIUM and {len(low_findings)} LOW issues."
            )
            output.append(
                f"Use security_audit('{module_name}', mode='findings') to see all findings."
            )
            return "\n".join(output)

        output.append("─" * 80)
        output.append("")
        output.append(f"🚨 HIGH SEVERITY ISSUES ({len(high_findings)} found)")
        output.append("")

        shown_count = 0
        for finding in high_findings[:max_findings]:
            file_display = Path(finding.file).name
            output.append(f"❌ {finding.category.upper()}: {file_display}:{finding.line}")
            output.append(f"   {finding.description}")
            output.append(f"   Code: {finding.code[:80]}{'...' if len(finding.code) > 80 else ''}")
            output.append(f"   Fix: {finding.recommendation}")
            output.append("")
            shown_count += 1

        if len(high_findings) > max_findings:
            remaining = len(high_findings) - max_findings
            output.append(f"... {remaining} more HIGH severity issues not shown")
            output.append(
                f"Use security_audit('{module_name}', mode='high_only', max_findings=100) to see more"
            )
            output.append("")

        return "\n".join(output)

    # FINDINGS MODE: Show detailed findings (limited by max_findings)
    output.append("─" * 80)
    output.append("")

    # Show findings grouped by severity, limited to max_findings total
    findings_shown = 0

    for severity, severity_findings in [
        ("HIGH", high_findings),
        ("MEDIUM", medium_findings),
        ("LOW", low_findings),
    ]:
        if not severity_findings or findings_shown >= max_findings:
            continue

        output.append(f"## {severity} SEVERITY ({len(severity_findings)} issues)")
        output.append("")

        # Show findings for this severity
        remaining_quota = max_findings - findings_shown
        for finding in severity_findings[:remaining_quota]:
            file_display = Path(finding.file).name
            output.append(f"❌ {finding.category.upper()}: {file_display}:{finding.line}")
            output.append(f"   {finding.description}")
            output.append(f"   Code: {finding.code[:80]}{'...' if len(finding.code) > 80 else ''}")
            output.append(f"   Fix: {finding.recommendation}")
            output.append("")
            findings_shown += 1

        if len(severity_findings) > remaining_quota:
            not_shown = len(severity_findings) - remaining_quota
            output.append(f"   ... {not_shown} more {severity} issues not shown")
            output.append("")

        output.append("─" * 80)
        output.append("")

    # Show what was truncated
    if findings_shown >= max_findings and findings_shown < len(all_findings):
        remaining = len(all_findings) - findings_shown
        output.append(f"⚠️  Showing {findings_shown} of {len(all_findings)} findings")
        output.append(f"   {remaining} findings not shown to prevent token overflow")
        output.append("")
        output.append("To see more findings:")
        output.append(
            f"  • security_audit('{module_name}', mode='findings', max_findings=100) - Increase limit"
        )
        output.append(
            f"  • security_audit('{module_name}', severity_filter='high') - Filter by severity"
        )
        output.append(f"  • scan_xss('{module_name}') - Category-specific scans")
        output.append("")

    # Recommendations
    output.append("📚 NEXT STEPS")
    output.append("")
    output.append("For comprehensive security audits:")
    output.append("  1. Review HIGH severity findings immediately")
    output.append("  2. Manual code review for critical paths")
    output.append("  3. Use additional tools: PHPStan, Psalm, Semgrep")
    output.append("  4. Consider professional security audit for production")
    output.append("")
    output.append("⚠️  IMPORTANT: Pattern-based analysis has limitations.")
    output.append("   May miss: multi-line patterns, complex data flow, indirect calls.")
    output.append("   Scout is excellent for first-pass screening, not security certification.")
    output.append("")
    output.append("Resources:")
    output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")
    output.append("  • https://www.drupal.org/security-team")

    return "\n".join(output)


# ============================================================================
# ANONYMOUS EXPLOIT ANALYSIS
# ============================================================================


def _parse_routing_file(routing_file: Path) -> Dict[str, Dict]:
    """
    Parse a Drupal routing.yml file to extract route definitions.

    Returns:
        Dict mapping route names to their access requirements
    """
    import yaml

    try:
        with open(routing_file, "r") as f:
            routes = yaml.safe_load(f) or {}

        route_info = {}
        for route_name, route_config in routes.items():
            if not isinstance(route_config, dict):
                continue

            # Extract access requirements
            requirements = route_config.get("requirements", {})

            # Determine if anonymous users can access
            is_anonymous_accessible = True
            access_level = "PUBLIC"

            if "_permission" in requirements:
                permission = requirements["_permission"]
                # Check if it's a restrictive permission
                if permission and permission not in ["access content"]:
                    is_anonymous_accessible = False
                    access_level = f"REQUIRES: {permission}"

            if "_role" in requirements:
                role = requirements["_role"]
                if "anonymous" not in role.lower():
                    is_anonymous_accessible = False
                    access_level = f"REQUIRES ROLE: {role}"

            if "_access" in requirements:
                if requirements["_access"] != "TRUE":
                    is_anonymous_accessible = False
                    access_level = f"CUSTOM ACCESS: {requirements['_access']}"

            # Extract controller/form info
            defaults = route_config.get("defaults", {})
            controller = defaults.get(
                "_controller", defaults.get("_form", defaults.get("_entity_form", "unknown"))
            )

            route_info[route_name] = {
                "anonymous_accessible": is_anonymous_accessible,
                "access_level": access_level,
                "controller": controller,
                "path": route_config.get("path", ""),
                "methods": route_config.get("methods", ["GET"]),
            }

        return route_info

    except Exception as e:
        logger.error(f"Error parsing routing file {routing_file}: {e}")
        return {}


def _map_findings_to_routes(
    module_dir: Path, findings: List[SecurityFinding]
) -> Dict[str, List[SecurityFinding]]:
    """
    Map security findings to their routes by matching controller/form classes.

    Returns:
        Dict mapping route names to list of findings in that route
    """
    # Find all routing files
    routing_files = list(module_dir.rglob("*.routing.yml"))

    # Parse all routes
    all_routes = {}
    for routing_file in routing_files:
        routes = _parse_routing_file(routing_file)
        all_routes.update(routes)

    # Map findings to routes
    route_findings = {}

    for finding in findings:
        # Extract class/controller name from file path
        # e.g., src/Controller/DeepChatApi.php -> DeepChatApi
        file_path = Path(finding.file)

        # Try to match with route controllers
        for route_name, route_info in all_routes.items():
            controller = route_info["controller"]

            # Check if finding file matches controller
            if file_path.stem in controller or controller.split("::")[0].endswith(file_path.stem):
                if route_name not in route_findings:
                    route_findings[route_name] = {"route_info": route_info, "findings": []}
                route_findings[route_name]["findings"].append(finding)

    return route_findings
