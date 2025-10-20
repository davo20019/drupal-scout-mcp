"""Parser for Drupal .services.yml files."""

import yaml
from pathlib import Path
from typing import Dict, List


def parse_services_file(file_path: Path) -> Dict:
    """
    Parse a Drupal .services.yml file.

    Args:
        file_path: Path to the .services.yml file

    Returns:
        Dictionary containing:
        - services: List of service definitions with metadata
        - parameters: Service container parameters
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        services = []
        service_definitions = data.get("services", {})

        for service_id, definition in service_definitions.items():
            if not isinstance(definition, dict):
                continue

            service_info = {
                "id": service_id,
                "class": definition.get("class", ""),
                "arguments": _extract_arguments(definition.get("arguments", [])),
                "tags": definition.get("tags", []),
                "public": definition.get("public", True),
                "factory": definition.get("factory", None),
                "keywords": _extract_service_keywords(service_id, definition),
            }
            services.append(service_info)

        return {
            "services": services,
            "parameters": data.get("parameters", {}),
            "file_path": str(file_path),
        }

    except Exception as e:
        return {
            "error": str(e),
            "file_path": str(file_path),
            "services": [],
            "parameters": {},
        }


def _extract_arguments(arguments: List) -> List[str]:
    """
    Extract service arguments, identifying dependencies.

    Arguments starting with '@' are service dependencies.
    """
    deps = []
    for arg in arguments:
        if isinstance(arg, str) and arg.startswith("@"):
            # Remove @ and ? (optional service marker)
            dep = arg.lstrip("@").lstrip("?")
            deps.append(dep)
    return deps


def _extract_service_keywords(service_id: str, definition: Dict) -> List[str]:
    """
    Extract keywords from service definition for search.

    Keywords from:
    - Service ID parts
    - Class name
    - Tags
    """
    keywords = []

    # Add service ID parts (e.g., 'email.sender' -> ['email', 'sender'])
    keywords.extend(service_id.split("."))
    keywords.extend(service_id.split("_"))

    # Add class name parts
    if "class" in definition:
        class_name = definition["class"].split("\\")[-1]
        keywords.append(class_name.lower())

    # Add tag names
    tags = definition.get("tags", [])
    for tag in tags:
        if isinstance(tag, dict) and "name" in tag:
            keywords.append(tag["name"])
        elif isinstance(tag, str):
            keywords.append(tag)

    return list(set(k.lower() for k in keywords if len(k) > 2))
