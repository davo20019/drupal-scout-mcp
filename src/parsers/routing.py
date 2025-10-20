"""Parser for Drupal .routing.yml files."""

import yaml
from pathlib import Path
from typing import Dict, List


def parse_routing_file(file_path: Path) -> Dict:
    """
    Parse a Drupal .routing.yml file.

    Args:
        file_path: Path to the .routing.yml file

    Returns:
        Dictionary containing:
        - routes: List of route definitions
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        routes = []

        for route_name, definition in data.items():
            if not isinstance(definition, dict):
                continue

            route_info = {
                "name": route_name,
                "path": definition.get("path", ""),
                "controller": _extract_controller(definition),
                "methods": definition.get("methods", []),
                "requirements": definition.get("requirements", {}),
                "keywords": _extract_route_keywords(route_name, definition),
            }
            routes.append(route_info)

        return {
            "routes": routes,
            "file_path": str(file_path),
        }

    except Exception as e:
        return {
            "error": str(e),
            "file_path": str(file_path),
            "routes": [],
        }


def _extract_controller(definition: Dict) -> str:
    """
    Extract controller from route definition.

    Can be in 'defaults._controller', 'defaults._form', etc.
    """
    defaults = definition.get("defaults", {})

    # Try common controller keys
    for key in ["_controller", "_form", "_entity_form", "_entity_list"]:
        if key in defaults:
            return defaults[key]

    return ""


def _extract_route_keywords(route_name: str, definition: Dict) -> List[str]:
    """
    Extract keywords from route definition.

    Keywords from:
    - Route name parts
    - Path segments
    - Controller class name
    """
    keywords = []

    # Add route name parts
    keywords.extend(route_name.split("."))
    keywords.extend(route_name.split("_"))

    # Add path segments
    path = definition.get("path", "")
    segments = [s for s in path.split("/") if s and not s.startswith("{")]
    keywords.extend(segments)

    # Add controller class name
    controller = _extract_controller(definition)
    if controller:
        class_name = controller.split("::")[0].split("\\")[-1]
        keywords.append(class_name.lower())

    return list(set(k.lower() for k in keywords if len(k) > 2))
