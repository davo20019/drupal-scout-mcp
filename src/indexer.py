"""Module indexer for scanning Drupal installations."""

import json
from pathlib import Path
from typing import Dict, List, Optional
from .parsers import parse_info_file, parse_services_file, parse_routing_file, parse_php_file


class ModuleIndexer:
    """
    Scans Drupal modules and indexes their functionality.
    """

    def __init__(self, drupal_root: Path, config: Optional[Dict] = None):
        """
        Initialize the indexer.

        Args:
            drupal_root: Path to Drupal installation root
            config: Optional configuration dictionary
        """
        self.drupal_root = Path(drupal_root)
        self.config = config or {}
        self.modules_path = self.config.get("modules_path", "modules")
        self.exclude_paths = self.config.get(
            "exclude_paths",
            [
                "*/node_modules/*",
                "*/vendor/*",
                "*/tests/*",
                "*/test/*",
            ],
        )

        # Module index
        self.modules = {}

    def index_all(self) -> Dict:
        """
        Index all modules in the Drupal installation.

        Returns:
            Dictionary with indexed modules grouped by type:
            - custom: Custom modules
            - contrib: Contributed modules
            - core: Core modules
        """
        modules_base = self.drupal_root / self.modules_path

        if not modules_base.exists():
            raise ValueError(f"Modules directory not found: {modules_base}")

        # Scan for modules
        custom_modules = (
            self._scan_directory(modules_base / "custom")
            if (modules_base / "custom").exists()
            else []
        )
        contrib_modules = (
            self._scan_directory(modules_base / "contrib")
            if (modules_base / "contrib").exists()
            else []
        )

        # Scan core modules
        core_modules_path = self.drupal_root / "core" / "modules"
        core_modules = self._scan_directory(core_modules_path) if core_modules_path.exists() else []

        # Index each module
        indexed = {
            "custom": [self._index_module(m) for m in custom_modules],
            "contrib": [self._index_module(m) for m in contrib_modules],
            "core": [self._index_module(m) for m in core_modules],
            "total": len(custom_modules) + len(contrib_modules) + len(core_modules),
        }

        # Store in instance
        self.modules = indexed

        return indexed

    def _scan_directory(self, directory: Path) -> List[Path]:
        """
        Scan a directory for Drupal modules.

        A module is identified by the presence of a .info.yml file.
        """
        modules = []

        if not directory.exists():
            return modules

        # Find all .info.yml files
        for info_file in directory.rglob("*.info.yml"):
            # Skip excluded paths
            if self._is_excluded(info_file):
                continue

            # Get module directory (parent of .info.yml)
            module_dir = info_file.parent

            modules.append(module_dir)

        return modules

    def _is_excluded(self, path: Path) -> bool:
        """Check if path matches exclusion patterns."""
        path_str = str(path)
        for pattern in self.exclude_paths:
            # Simple glob-like matching
            pattern_parts = pattern.split("*")
            if all(part in path_str for part in pattern_parts if part):
                return True
        return False

    def _index_module(self, module_dir: Path) -> Dict:
        """
        Index a single module.

        Parses all relevant files and extracts metadata.
        """
        module_name = module_dir.name

        # Find and parse .info.yml
        info_file = module_dir / f"{module_name}.info.yml"
        info = parse_info_file(info_file) if info_file.exists() else {}

        # Find and parse .services.yml
        services_file = module_dir / f"{module_name}.services.yml"
        services = (
            parse_services_file(services_file) if services_file.exists() else {"services": []}
        )

        # Find and parse .routing.yml
        routing_file = module_dir / f"{module_name}.routing.yml"
        routing = parse_routing_file(routing_file) if routing_file.exists() else {"routes": []}

        # Find and parse PHP files in src/
        src_dir = module_dir / "src"
        php_files = []
        if src_dir.exists():
            for php_file in src_dir.rglob("*.php"):
                php_files.append(parse_php_file(php_file))

        # Find and parse .module file
        module_file = module_dir / f"{module_name}.module"
        module_hooks = parse_php_file(module_file) if module_file.exists() else {}

        # Combine all data
        indexed = {
            "machine_name": module_name,
            "name": info.get("name", module_name),
            "description": info.get("description", ""),
            "type": info.get("type", "module"),
            "package": info.get("package", "Other"),
            "dependencies": info.get("dependencies", []),
            "services": services.get("services", []),
            "routes": routing.get("routes", []),
            "hooks": module_hooks.get("hooks", []),
            "classes": [cls for php in php_files for cls in php.get("classes", [])],
            "path": str(module_dir),
            "keywords": self._collect_keywords(info, services, routing, php_files, module_hooks),
        }

        return indexed

    def _collect_keywords(
        self, info: Dict, services: Dict, routing: Dict, php_files: List[Dict], module_hooks: Dict
    ) -> List[str]:
        """
        Collect all keywords from various sources for search.
        """
        keywords = set()

        # From info.yml
        keywords.update(info.get("keywords", []))

        # From services
        for service in services.get("services", []):
            keywords.update(service.get("keywords", []))

        # From routes
        for route in routing.get("routes", []):
            keywords.update(route.get("keywords", []))

        # From PHP files
        for php in php_files:
            keywords.update(php.get("keywords", []))

        # From module hooks
        keywords.update(module_hooks.get("keywords", []))

        return list(keywords)

    def get_module(self, module_name: str) -> Optional[Dict]:
        """
        Get indexed data for a specific module.
        """
        for module_type in ["custom", "contrib"]:
            for module in self.modules.get(module_type, []):
                if module["machine_name"] == module_name:
                    return module
        return None

    def find_modules_by_keyword(self, keyword: str) -> List[Dict]:
        """
        Find modules containing a keyword.
        """
        keyword = keyword.lower()
        results = []

        for module_type in ["custom", "contrib"]:
            for module in self.modules.get(module_type, []):
                # Check in keywords
                if keyword in module.get("keywords", []):
                    results.append({**module, "source_type": module_type})
                    continue

                # Check in name/description
                if keyword in module.get("name", "").lower():
                    results.append({**module, "source_type": module_type})
                    continue

                if keyword in module.get("description", "").lower():
                    results.append({**module, "source_type": module_type})
                    continue

        return results

    def save_index(self, output_file: Path):
        """Save index to JSON file for caching."""
        with open(output_file, "w") as f:
            json.dump(self.modules, f, indent=2)

    def load_index(self, input_file: Path):
        """Load index from JSON file."""
        with open(input_file, "r") as f:
            self.modules = json.load(f)
