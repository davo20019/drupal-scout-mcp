"""Parser for Drupal .info.yml files."""

import yaml
from pathlib import Path
from typing import Dict, List


def parse_info_file(file_path: Path) -> Dict:
    """
    Parse a Drupal .info.yml file.

    Args:
        file_path: Path to the .info.yml file

    Returns:
        Dictionary containing module metadata:
        - name: Human-readable module name
        - description: Module description
        - type: Module type (module, theme, profile)
        - core_version_requirement: Compatible Drupal versions
        - package: Module package/category
        - dependencies: List of required modules
        - keywords: Extracted keywords for searching
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Extract and normalize data
        parsed = {
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "type": data.get("type", "module"),
            "core_version_requirement": data.get("core_version_requirement", ""),
            "package": data.get("package", "Other"),
            "dependencies": _parse_dependencies(data.get("dependencies", [])),
            "file_path": str(file_path),
        }

        # Extract keywords from name and description for search
        parsed["keywords"] = _extract_keywords(parsed)

        return parsed

    except Exception as e:
        return {
            "error": str(e),
            "file_path": str(file_path),
            "name": "",
            "description": "",
            "keywords": [],
        }


def _parse_dependencies(dependencies: List) -> List[str]:
    """
    Parse dependency list, handling both simple and namespaced formats.

    Examples:
        - 'node'
        - 'drupal:node'
        - 'views:views'
    """
    parsed = []
    for dep in dependencies:
        if isinstance(dep, str):
            # Strip namespace if present (e.g., 'drupal:node' -> 'node')
            dep_name = dep.split(":")[-1]
            parsed.append(dep_name)
    return parsed


def _extract_keywords(info: Dict) -> List[str]:
    """
    Extract searchable keywords from module info.

    Keywords come from:
    - Module name
    - Description
    - Package
    """
    keywords = []

    # Add name words
    if info.get("name"):
        keywords.extend(_tokenize(info["name"]))

    # Add description words
    if info.get("description"):
        keywords.extend(_tokenize(info["description"]))

    # Add package as keyword
    if info.get("package"):
        keywords.extend(_tokenize(info["package"]))

    # Deduplicate and lowercase
    return list(set(k.lower() for k in keywords if len(k) > 2))


def _tokenize(text: str) -> List[str]:
    """Split text into words, removing special characters."""
    import re

    # Split on non-alphanumeric characters
    words = re.findall(r"\b[a-zA-Z0-9]{3,}\b", text)
    return words
