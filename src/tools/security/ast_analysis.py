"""
AST-based security analysis using tree-sitter-php (optional enhancement).

Provides deeper code analysis beyond pattern matching:
- _init_php_parser(): Initialize tree-sitter PHP parser
- _has_sql_concatenation_ast(): Verify SQL concatenation with AST
- _check_access_control_ast(): Verify access control in routes/forms
- _format_finding(): Format security findings with context

This module is optional - if tree-sitter-php is not installed, the
security tools will fall back to pattern-based scanning only.

Drupal-aware: Understands EntityQuery, TempStore, Config, Form API, etc.
"""

import logging
import re
from pathlib import Path
from typing import Optional, List, Dict

from src.tools.security.models import SecurityFinding

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
