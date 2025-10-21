"""Basic parser for PHP files to extract classes and functions."""

import re
from pathlib import Path
from typing import Dict, List


def parse_php_file(file_path: Path) -> Dict:
    """
    Parse a PHP file to extract basic structure.

    This is a simple regex-based parser, not a full AST parser.
    Extracts:
    - Namespace
    - Classes
    - Functions (including hooks)
    - Use statements

    Args:
        file_path: Path to the PHP file

    Returns:
        Dictionary with extracted PHP structures
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        return {
            "namespace": _extract_namespace(content),
            "classes": _extract_classes(content),
            "functions": _extract_functions(content),
            "hooks": _extract_hooks(content),
            "uses": _extract_uses(content),
            "keywords": _extract_php_keywords(content),
            "file_path": str(file_path),
        }

    except Exception as e:
        return {
            "error": str(e),
            "file_path": str(file_path),
            "namespace": "",
            "classes": [],
            "functions": [],
            "hooks": [],
            "uses": [],
            "keywords": [],
        }


def _extract_namespace(content: str) -> str:
    """Extract namespace declaration."""
    match = re.search(r"namespace\s+([\w\\]+)\s*;", content)
    return match.group(1) if match else ""


def _extract_classes(content: str) -> List[Dict]:
    """
    Extract class definitions.

    Returns list of:
    - name: Class name
    - extends: Parent class if any
    - implements: Implemented interfaces
    """
    classes = []

    # Pattern: class ClassName extends Parent implements Interface
    pattern = r"class\s+(\w+)(?:\s+extends\s+([\w\\]+))?(?:\s+implements\s+([\w\\,\s]+))?"

    for match in re.finditer(pattern, content):
        class_info = {
            "name": match.group(1),
            "extends": match.group(2) if match.group(2) else None,
            "implements": _parse_implements(match.group(3)) if match.group(3) else [],
        }
        classes.append(class_info)

    return classes


def _parse_implements(implements_str: str) -> List[str]:
    """Parse implements clause into list of interface names."""
    if not implements_str:
        return []
    return [i.strip() for i in implements_str.split(",")]


def _extract_functions(content: str) -> List[str]:
    """
    Extract function names (excluding hooks).
    """
    functions = []

    # Pattern: function functionName(
    pattern = r"function\s+(\w+)\s*\("

    for match in re.finditer(pattern, content):
        func_name = match.group(1)
        # Exclude hook functions (they start with module name + '_hook')
        if not func_name.startswith("hook_"):
            functions.append(func_name)

    return functions


def _extract_hooks(content: str) -> List[Dict]:
    """
    Extract Drupal hook implementations with line numbers.

    Hook functions follow pattern: modulename_hookname()

    Returns:
        List of dicts with 'name' and 'line' keys
    """
    hooks = []

    # Pattern: function modulename_hook_
    pattern = r"function\s+(\w+_hook_\w+)\s*\("

    # Split into lines to get line numbers
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        match = re.search(pattern, line)
        if match:
            hooks.append({"name": match.group(1), "line": line_num})

    return hooks


def _extract_uses(content: str) -> List[str]:
    """Extract use statements."""
    uses = []

    # Pattern: use Full\Class\Name;
    pattern = r"use\s+([\w\\]+)(?:\s+as\s+\w+)?\s*;"

    for match in re.finditer(pattern, content):
        uses.append(match.group(1))

    return uses


def _extract_php_keywords(content: str) -> List[str]:
    """
    Extract keywords from PHP content for search.

    Looks for common patterns that indicate functionality:
    - DocBlock @tags
    - Class names
    - Function names
    """
    keywords = []

    # Extract from DocBlock tags
    doc_pattern = r"@(\w+)"
    keywords.extend(re.findall(doc_pattern, content))

    # Extract class names
    class_pattern = r"class\s+(\w+)"
    keywords.extend(re.findall(class_pattern, content))

    # Extract function names
    func_pattern = r"function\s+(\w+)"
    keywords.extend(re.findall(func_pattern, content))

    # Common functionality indicators in comments
    comment_pattern = r"//\s*(.+)$|/\*\*?\s*\*\s*(.+)$"
    for match in re.finditer(comment_pattern, content, re.MULTILINE):
        comment_text = match.group(1) or match.group(2)
        if comment_text:
            # Extract words from comments
            words = re.findall(r"\b[a-zA-Z]{4,}\b", comment_text)
            keywords.extend(words)

    # Deduplicate and filter
    return list(set(k.lower() for k in keywords if len(k) > 3))
