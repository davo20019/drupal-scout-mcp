"""
Security analysis tools for Drupal Scout MCP server.

Provides pattern-based security scanning for Drupal modules:
- scan_xss: Detect Cross-Site Scripting (XSS) vulnerabilities
- scan_sql_injection: Detect SQL injection vulnerabilities
- scan_access_control: Find missing permission checks
- scan_csrf: Review CSRF protection in custom handlers
- scan_command_injection: Detect command injection vulnerabilities
- scan_path_traversal: Detect path traversal vulnerabilities
- scan_hardcoded_secrets: Find hardcoded credentials and API keys
- scan_deprecated_api: Identify unsafe/deprecated API usage
- scan_anonymous_exploits: Identify remotely exploitable vulnerabilities (HIGH PRIORITY)
- verify_vulnerability: Explain how to manually verify vulnerabilities (EDUCATIONAL)
- security_audit: Run all security scans with prioritized report

These tools use deterministic pattern matching - no AI guessing.
All findings are concrete code patterns, not speculation.

TODO: Refactor this 2000+ line file into modular structure:
- Extract patterns to security/patterns.py
- Extract filters to security/filters.py
- Extract AST analysis to security/ast_analysis.py
- Extract scanners to security/scanners.py
- Move each tool to security/tools/*.py
See security/__init__.py for planned structure.
"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

# Import from core modules
from src.core.config import ensure_indexed

# Import MCP instance from server
from server import mcp

# Import extracted tools from security package
from src.tools.security import verify_vulnerability

# Import vulnerability detection patterns
from src.tools.security.patterns import (
    XSS_PATTERNS,
    SQL_INJECTION_PATTERNS,
    ACCESS_CONTROL_PATTERNS,
    CSRF_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    HARDCODED_SECRETS_PATTERNS,
    DEPRECATED_API_PATTERNS,
)

logger = logging.getLogger(__name__)

# Try to import tree-sitter for AST-based analysis (optional)
try:
    from tree_sitter import Language, Parser
    import tree_sitter_php

    HAS_TREE_SITTER = True
    logger.info("✅ tree-sitter-php available - enhanced security scanning enabled")
except ImportError:
    HAS_TREE_SITTER = False
    logger.info("ℹ️  tree-sitter-php not installed - using pattern-based scanning")


@dataclass
class SecurityFinding:
    """Represents a security finding with location and details."""

    severity: str  # "high", "medium", "low"
    category: str  # "xss", "sql_injection", "access_control", etc.
    file: str
    line: int
    code: str
    description: str
    recommendation: str


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _find_module_path(module_name: str) -> Optional[Path]:
    """Find module path using code_analysis module's logic."""
    # Import here to avoid circular dependency
    from src.tools.code_analysis import _find_module_path as find_path

    return find_path(module_name)


def _is_false_positive(line: str, pattern_name: str, category: str) -> bool:
    """
    Check if a finding is likely a false positive based on context.

    Args:
        line: The line of code that matched
        pattern_name: Name of the pattern that matched
        category: Category of the finding

    Returns:
        True if this is likely a false positive
    """
    line_lower = line.lower()

    # SQL injection false positives
    if category == "sql_injection":
        # Drupal's safe APIs that look like SQL
        safe_drupal_apis = [
            "->condition(",  # EntityQuery conditions are safe
            "->fields(",  # EntityQuery field selection
            "->range(",  # EntityQuery range
            "->sort(",  # EntityQuery sorting
            "gettempstore(",  # Temp storage is not SQL
            "getprivatetempstore(",  # Private temp storage
            "getsharedtempstore(",  # Shared temp storage
            "->get(",  # KeyValue store get
            "->set(",  # KeyValue store set
            "->delete(",  # KeyValue store delete (not SQL DELETE)
            "cache_get(",  # Cache API
            "cache_set(",  # Cache API
            "state_get(",  # State API
            "config_get(",  # Config API
        ]

        for safe_api in safe_drupal_apis:
            if safe_api in line_lower:
                return True

        # Check if SQL keywords are in comments or strings only (not actual SQL)
        if pattern_name == "sql_concat":
            # If the line contains SQL keywords but no actual query construction
            # Look for non-SQL contexts like variable names containing "select"
            if not any(
                keyword in line_lower for keyword in ["db_query", "->query(", "mysqli", "pdo"]
            ):
                # Likely a false positive if no database functions present
                return True

    # Access control false positives
    if category == "access_control":
        # ->save() and ->delete() on non-entity objects
        if pattern_name == "missing_permission_check":
            # Config and cache operations are not entity operations
            if any(
                keyword in line_lower
                for keyword in ["config->save(", "cache->delete(", "state->delete("]
            ):
                return True

    # Command injection false positives
    if category == "command_injection":
        # escapeshellarg or escapeshellcmd present means it's likely handled
        if "escapeshellarg" in line_lower or "escapeshellcmd" in line_lower:
            return True
        # Drush commands with hardcoded strings (no variables) are safe
        if pattern_name == "drush_shell_exec" and "$" not in line:
            return True

    # Path traversal false positives
    if category == "path_traversal":
        # realpath() or drupal_realpath() present means validation is happening
        if "realpath(" in line_lower or "drupal_realpath(" in line_lower:
            return True
        # file_create_url is safe (generates URLs, not file access)
        if "file_create_url" in line_lower:
            return True
        # Stream wrappers are generally safe (public://, private://)
        if "public://" in line or "private://" in line or "temporary://" in line:
            return True

    # Hardcoded secrets false positives
    if category == "hardcoded_secrets":
        # Example values, placeholders, or comments
        if any(
            word in line_lower
            for word in ["example", "placeholder", "your_api_key", "your_password", "xxx"]
        ):
            return True
        # Test files
        if "/test" in line_lower or "test.php" in line_lower or "phpunit" in line_lower:
            return True
        # Documentation/comments
        if line.strip().startswith(("//", "#", "*", "/*")):
            return True

    # XSS false positives
    if category == "xss":
        # drupal_set_message with t() is safe
        if "drupal_set_message" in line_lower and "t(" in line_lower:
            return True

        # Form returns are safe (Form API handles sanitization)
        if pattern_name == "unsafe_render_string":
            # return $form; is safe - Form API sanitizes
            if "return $form" in line_lower:
                return True

            # return $build; is safe - render arrays are sanitized
            if "return $build" in line_lower:
                return True

            # return $element; is safe in form context
            if "return $element" in line_lower:
                return True

            # return $requirements; is safe (system requirements)
            if "return $requirements" in line_lower:
                return True

            # return $items; is safe in field formatter context
            if "return $items" in line_lower:
                return True

            # return $variables; is safe in preprocess hooks
            if "return $variables" in line_lower:
                return True

            # return $output; when it's a render array variable
            if "return $output" in line_lower:
                return True

            # return $page; is safe (page render array)
            if "return $page" in line_lower:
                return True

            # return $entity; in load/create contexts is not XSS
            if "return $entity" in line_lower:
                return True

    return False


# ============================================================================
# AST-BASED ANALYSIS (DRUPAL-AWARE) - Optional Enhancement
# ============================================================================


def _init_php_parser():
    """Initialize PHP parser with tree-sitter (if available)."""
    if not HAS_TREE_SITTER:
        return None

    try:
        PHP_LANGUAGE = Language(tree_sitter_php.language_php())
        parser = Parser(PHP_LANGUAGE)
        return parser, PHP_LANGUAGE
    except Exception as e:
        logger.error(f"Failed to initialize tree-sitter parser: {e}")
        return None


def _has_sql_concatenation_ast(file_path: Path, line_num: int) -> bool:
    """
    Use AST to verify if a line actually contains SQL concatenation.

    Drupal-aware: Understands EntityQuery, TempStore, Config, etc.

    Returns:
        True if real SQL concatenation detected, False if safe Drupal API
    """
    if not HAS_TREE_SITTER:
        return True  # Can't verify, assume pattern is correct

    try:
        parser_info = _init_php_parser()
        if not parser_info:
            return True

        parser, language = parser_info

        # Read file and parse
        with open(file_path, "rb") as f:
            code = f.read()

        tree = parser.parse(code)

        # Query for actual SQL query construction
        # Look for string concatenation in db_query, mysqli_query, etc.
        query = language.query(
            """
            (function_call_expression
              function: (name) @func_name
              arguments: (arguments
                (binary_expression
                  operator: "."
                ) @concat
              )
            )
            """
        )

        captures = query.captures(tree.root_node)

        for node, capture_name in captures:
            if capture_name == "func_name":
                func_name = code[node.start_byte : node.end_byte].decode("utf-8").lower()

                # Check if it's a real database function
                sql_functions = ["db_query", "mysqli_query", "mysql_query", "pdo"]

                if any(sql_func in func_name for sql_func in sql_functions):
                    # Found actual SQL function with concatenation
                    node_line = node.start_point[0] + 1
                    if abs(node_line - line_num) <= 2:  # Within 2 lines
                        return True

        # Drupal safe APIs - even if pattern matched
        safe_drupal_patterns = [
            b"->condition(",
            b"->getTempStore(",
            b"->getPrivateTempStore(",
            b"->get(",
            b"->set(",
            b"cache_",
            b"state_",
            b"config_",
        ]

        # Check if line contains safe Drupal APIs
        lines = code.split(b"\n")
        if line_num <= len(lines):
            line_code = lines[line_num - 1]
            for safe_pattern in safe_drupal_patterns:
                if safe_pattern in line_code.lower():
                    return False  # Safe Drupal API

        return False  # No SQL concatenation found

    except Exception as e:
        logger.debug(f"AST analysis failed, falling back to pattern: {e}")
        return True  # Fall back to pattern matching


def _has_unsafe_echo_ast(file_path: Path, line_num: int) -> bool:
    """
    Use AST to verify if echo/print is actually unsafe.

    Drupal-aware: Distinguishes between render arrays and direct output.

    Returns:
        True if unsafe direct output, False if safe pattern
    """
    if not HAS_TREE_SITTER:
        return True  # Can't verify, assume pattern is correct

    try:
        parser_info = _init_php_parser()
        if not parser_info:
            return True

        parser, language = parser_info

        # Read file and parse
        with open(file_path, "rb") as f:
            code = f.read()

        tree = parser.parse(code)

        # Query for echo/print statements
        query = language.query(
            """
            (echo_statement
              (variable) @var
            )
            (print_intrinsic
              (variable) @var
            )
            """
        )

        captures = query.captures(tree.root_node)

        for node, capture_name in captures:
            node_line = node.start_point[0] + 1
            if abs(node_line - line_num) <= 1:
                # Found echo/print with variable - this is the real deal
                return True

        return False  # No unsafe echo found

    except Exception as e:
        logger.debug(f"AST analysis failed, falling back to pattern: {e}")
        return True


def _scan_file_for_patterns(
    file_path: Path, patterns: Dict[str, Dict], category: str
) -> List[SecurityFinding]:
    """
    Scan a file for security patterns with false positive filtering.

    Args:
        file_path: Path to file to scan
        patterns: Dictionary of patterns to search for
        category: Category name (e.g., "xss", "sql_injection")

    Returns:
        List of SecurityFinding objects (filtered for false positives)
    """
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern_name, pattern_info in patterns.items():
                pattern = pattern_info["pattern"]
                if re.search(pattern, line, re.IGNORECASE):
                    # Check for false positives before adding
                    if not _is_false_positive(line, pattern_name, category):
                        # AST validation (if available) - Drupal-aware
                        validated = True
                        if HAS_TREE_SITTER:
                            if category == "sql_injection" and pattern_name == "sql_concat":
                                # Use AST to verify actual SQL concatenation
                                validated = _has_sql_concatenation_ast(file_path, line_num)
                            elif category == "xss" and pattern_name == "unescaped_print":
                                # Use AST to verify unsafe echo/print
                                validated = _has_unsafe_echo_ast(file_path, line_num)

                        if validated:
                            findings.append(
                                SecurityFinding(
                                    severity=pattern_info["severity"],
                                    category=category,
                                    file=str(file_path),
                                    line=line_num,
                                    code=line.strip(),
                                    description=pattern_info["description"],
                                    recommendation=pattern_info["recommendation"],
                                )
                            )

    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {e}")

    return findings


def _get_php_files(module_path: Path) -> List[Path]:
    """Get all PHP files in a module."""
    php_extensions = ["*.php", "*.module", "*.install", "*.theme", "*.inc", "*.profile"]
    php_files = []

    for ext in php_extensions:
        php_files.extend(module_path.rglob(ext))

    return sorted(php_files)


def _format_findings(findings: List[SecurityFinding], title: str, max_findings: int = 50) -> str:
    """Format security findings as a readable report with limit."""
    if not findings:
        return f"✅ {title}: No issues found"

    output = []
    output.append(f"⚠️  {title}: {len(findings)} issues found")
    output.append("")

    # Group by severity
    high_findings = [f for f in findings if f.severity == "high"]
    medium_findings = [f for f in findings if f.severity == "medium"]
    low_findings = [f for f in findings if f.severity == "low"]

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

        # Limit findings per severity
        remaining_quota = max_findings - findings_shown
        for finding in severity_findings[:remaining_quota]:
            # Shorten file path for readability
            file_display = Path(finding.file).name
            output.append(f"❌ {file_display}:{finding.line}")
            output.append(f"   {finding.description}")
            output.append(f"   Code: {finding.code[:80]}{'...' if len(finding.code) > 80 else ''}")
            output.append(f"   Fix: {finding.recommendation}")
            output.append("")
            findings_shown += 1

        # Show truncation notice
        if len(severity_findings) > remaining_quota:
            not_shown = len(severity_findings) - remaining_quota
            output.append(
                f"   ... {not_shown} more {severity} issues not shown (use max_findings parameter)"
            )
            output.append("")

    # Overall truncation notice
    if findings_shown < len(findings):
        output.append(f"⚠️  Showing {findings_shown} of {len(findings)} total findings")
        output.append("")

    return "\n".join(output)


# ============================================================================
# MCP TOOL IMPLEMENTATIONS
# ============================================================================


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


@mcp.tool()
def scan_anonymous_exploits(
    module_name: str, module_path: Optional[str] = None, max_findings: int = 50
) -> str:
    """
    Identify security vulnerabilities that are exploitable by anonymous (unauthenticated) users.

    This tool combines security scanning with routing analysis to determine which
    vulnerabilities can be exploited remotely without authentication.

    Workflow:
    1. Runs security scans (XSS, SQL injection, command injection, path traversal)
    2. Parses routing.yml files to identify anonymous-accessible routes
    3. Maps vulnerabilities to routes
    4. Reports only vulnerabilities accessible to anonymous users

    This is critical for prioritizing security fixes - anonymous exploits are the
    highest priority as they can be exploited remotely without credentials.

    Args:
        module_name: Module machine name to scan
        module_path: Optional explicit module path override
        max_findings: Maximum findings to show (default: 50)

    Returns:
        Formatted report with anonymously exploitable vulnerabilities prioritized

    Examples:
        scan_anonymous_exploits("my_api_module")
        scan_anonymous_exploits("chatbot", max_findings=20)

    Use case:
        - Pre-deployment security checks
        - Identifying critical remote vulnerabilities
        - Prioritizing security fixes
        - Penetration testing preparation
    """
    ensure_indexed()

    module_dir = _find_module_path(module_name)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found. Use list_modules() to see available modules."

    output = []
    output.append(f"🎯 ANONYMOUS EXPLOIT SCAN: {module_name}")
    output.append("=" * 80)
    output.append("")
    output.append("Analyzing vulnerabilities exploitable by ANONYMOUS users...")
    output.append("(Remote exploitation without authentication)")
    output.append("")

    # Get PHP files
    php_files = _get_php_files(module_dir)

    if not php_files:
        return f"No PHP files found in module '{module_name}'"

    # Run security scans for exploitable vulnerability types
    all_findings = []

    # XSS - anonymously exploitable if in public routes
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, XSS_PATTERNS, "xss")
        all_findings.extend(findings)

    # SQL injection - anonymously exploitable
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, SQL_INJECTION_PATTERNS, "sql_injection")
        all_findings.extend(findings)

    # Command injection - anonymously exploitable
    for php_file in php_files:
        findings = _scan_file_for_patterns(
            php_file, COMMAND_INJECTION_PATTERNS, "command_injection"
        )
        all_findings.extend(findings)

    # Path traversal - anonymously exploitable
    for php_file in php_files:
        findings = _scan_file_for_patterns(php_file, PATH_TRAVERSAL_PATTERNS, "path_traversal")
        all_findings.extend(findings)

    # Filter to HIGH severity only (most critical for anonymous exploits)
    high_findings = [f for f in all_findings if f.severity == "high"]

    output.append(f"📊 Found {len(high_findings)} HIGH severity vulnerabilities")
    output.append("")
    output.append("─" * 80)
    output.append("")

    # Parse routing files
    routing_files = list(module_dir.rglob("*.routing.yml"))

    if not routing_files:
        output.append("⚠️  WARNING: No routing files found!")
        output.append("   Cannot determine anonymous accessibility without routing definitions.")
        output.append("")
        output.append("Showing all HIGH severity findings (manual route review needed):")
        output.append("")
        output.append(
            _format_findings(high_findings, "HIGH Severity Vulnerabilities", max_findings)
        )
        return "\n".join(output)

    # Parse all routes
    output.append(f"📁 Analyzing {len(routing_files)} routing file(s)...")
    output.append("")

    all_routes = {}
    for routing_file in routing_files:
        routes = _parse_routing_file(routing_file)
        all_routes.update(routes)

    # Categorize routes
    anonymous_routes = {k: v for k, v in all_routes.items() if v["anonymous_accessible"]}
    protected_routes = {k: v for k, v in all_routes.items() if not v["anonymous_accessible"]}

    output.append(f"   • {len(anonymous_routes)} routes accessible to ANONYMOUS users")
    output.append(f"   • {len(protected_routes)} routes require authentication")
    output.append("")

    if not anonymous_routes:
        output.append("✅ GOOD NEWS: No routes are accessible to anonymous users!")
        output.append("   All vulnerabilities require authentication to exploit.")
        output.append("")
        output.append(f"However, {len(high_findings)} HIGH severity issues still need fixing:")
        output.append(
            _format_findings(high_findings, "Authenticated Vulnerabilities", max_findings)
        )
        return "\n".join(output)

    # Map findings to routes
    route_findings_map = _map_findings_to_routes(module_dir, high_findings)

    # Identify anonymously exploitable findings
    anonymous_exploits = []

    for route_name, data in route_findings_map.items():
        if data["route_info"]["anonymous_accessible"]:
            for finding in data["findings"]:
                anonymous_exploits.append(
                    {"route": route_name, "route_info": data["route_info"], "finding": finding}
                )

    output.append("─" * 80)
    output.append("")

    if not anonymous_exploits:
        output.append("✅ GOOD NEWS: No HIGH severity vulnerabilities in anonymous routes!")
        output.append("")
        output.append(
            f"Note: Module has {len(anonymous_routes)} anonymous routes, but no mapped HIGH severity issues."
        )
        output.append("")
        output.append("⚠️  However, this does NOT guarantee safety:")
        output.append("   • Vulnerabilities may exist in code called by controllers")
        output.append("   • Manual code review still recommended for anonymous routes")
        output.append("")
        output.append("Anonymous accessible routes to review:")
        for route_name, route_info in list(anonymous_routes.items())[:10]:
            output.append(f"   • {route_name}")
            output.append(f"     Path: {route_info['path']}")
            output.append(f"     Controller: {route_info['controller']}")
            output.append("")
    else:
        output.append(
            f"🚨 CRITICAL: {len(anonymous_exploits)} ANONYMOUSLY EXPLOITABLE VULNERABILITIES!"
        )
        output.append("")
        output.append("These can be exploited REMOTELY without authentication:")
        output.append("")

        shown = 0
        for exploit in anonymous_exploits[:max_findings]:
            finding = exploit["finding"]
            route_info = exploit["route_info"]

            output.append(f"❌ {exploit['route']}")
            output.append(f"   Route: {route_info['path']} ({', '.join(route_info['methods'])})")
            output.append(f"   Access: {route_info['access_level']}")
            output.append(f"   Vulnerability: {finding.category.upper()} - {finding.description}")
            output.append(f"   File: {Path(finding.file).name}:{finding.line}")
            output.append(f"   Code: {finding.code[:80]}{'...' if len(finding.code) > 80 else ''}")
            output.append(f"   Fix: {finding.recommendation}")
            output.append("")
            shown += 1

        if len(anonymous_exploits) > max_findings:
            output.append(
                f"... {len(anonymous_exploits) - max_findings} more anonymous exploits not shown"
            )
            output.append("")

        output.append("─" * 80)
        output.append("")
        output.append("🚨 IMMEDIATE ACTION REQUIRED:")
        output.append("  1. These vulnerabilities are REMOTELY EXPLOITABLE")
        output.append("  2. Fix HIGH severity issues in anonymous routes FIRST")
        output.append("  3. Consider temporarily disabling anonymous access")
        output.append("  4. Review all anonymous routes for additional issues")
        output.append("")
        output.append("📚 RESOURCES:")
        output.append("  • https://www.drupal.org/docs/security-in-drupal/writing-secure-code")
        output.append("  • https://www.drupal.org/docs/drupal-apis/routing-system")

    return "\n".join(output)
