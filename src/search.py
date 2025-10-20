"""Search functionality for finding modules and capabilities."""

from typing import Dict, List
from .indexer import ModuleIndexer


class ModuleSearch:
    """
    Search interface for querying indexed modules.
    """

    def __init__(self, indexer: ModuleIndexer):
        """
        Initialize search with an indexer.

        Args:
            indexer: ModuleIndexer instance with indexed modules
        """
        self.indexer = indexer

    def search_functionality(self, query: str, scope: str = "all") -> Dict:
        """
        Search for functionality across modules.

        Args:
            query: Search query (e.g., "email", "PDF", "API")
            scope: Search scope - "all", "custom", "contrib"

        Returns:
            Structured results with custom and contrib modules
        """
        query_terms = query.lower().split()

        results = {
            "query": query,
            "custom_modules": [],
            "contrib_modules": [],
            "total_matches": 0,
        }

        # Determine which module types to search
        types_to_search = []
        if scope in ["all", "custom"]:
            types_to_search.append("custom")
        if scope in ["all", "contrib"]:
            types_to_search.append("contrib")

        # Search each type
        for module_type in types_to_search:
            modules = self.indexer.modules.get(module_type, [])

            for module in modules:
                score = self._score_module(module, query_terms)

                if score > 0:
                    result = {
                        "module": module["machine_name"],
                        "name": module["name"],
                        "description": module["description"],
                        "score": score,
                        "matches": self._get_matches(module, query_terms),
                    }

                    if module_type == "custom":
                        results["custom_modules"].append(result)
                    else:
                        results["contrib_modules"].append(result)

        # Sort by score
        results["custom_modules"].sort(key=lambda x: x["score"], reverse=True)
        results["contrib_modules"].sort(key=lambda x: x["score"], reverse=True)
        results["total_matches"] = len(results["custom_modules"]) + len(results["contrib_modules"])

        return results

    def _score_module(self, module: Dict, query_terms: List[str]) -> float:
        """
        Score a module's relevance to query terms.

        Scoring:
        - Exact name match: 10 points
        - Name contains term: 5 points
        - Description contains term: 3 points
        - Keyword match: 2 points
        - Service name match: 2 points
        """
        score = 0.0
        name_lower = module.get("name", "").lower()
        desc_lower = module.get("description", "").lower()
        keywords = module.get("keywords", [])
        services = module.get("services", [])

        for term in query_terms:
            # Name matches (highest priority)
            if term == name_lower:
                score += 10
            elif term in name_lower:
                score += 5

            # Description matches
            if term in desc_lower:
                score += 3

            # Keyword matches
            if term in keywords:
                score += 2

            # Service matches
            for service in services:
                if term in service.get("id", "").lower():
                    score += 2
                if term in service.get("keywords", []):
                    score += 1

        return score

    def _get_matches(self, module: Dict, query_terms: List[str]) -> Dict:
        """
        Get specific matches within a module.

        Returns what matched: services, classes, hooks, etc.
        """
        matches = {
            "services": [],
            "routes": [],
            "classes": [],
            "hooks": [],
        }

        # Find matching services
        for service in module.get("services", []):
            for term in query_terms:
                if term in service.get("id", "").lower() or term in service.get("keywords", []):
                    matches["services"].append(service["id"])
                    break

        # Find matching routes
        for route in module.get("routes", []):
            for term in query_terms:
                if (
                    term in route.get("name", "").lower()
                    or term in route.get("path", "").lower()
                    or term in route.get("keywords", [])
                ):
                    matches["routes"].append(route["name"])
                    break

        # Find matching classes
        for cls in module.get("classes", []):
            for term in query_terms:
                if term in cls.get("name", "").lower():
                    matches["classes"].append(cls["name"])
                    break

        return matches

    def find_unused_contrib(self) -> List[Dict]:
        """
        Find contrib modules not used by any custom modules.

        A module is "used" if:
        - Listed in custom module dependencies
        - Services are injected in custom code
        """
        contrib_modules = self.indexer.modules.get("contrib", [])
        custom_modules = self.indexer.modules.get("custom", [])

        # Collect all custom dependencies and service usages
        used_modules = set()

        for custom in custom_modules:
            # Add dependencies
            used_modules.update(custom.get("dependencies", []))

            # Check for service usage
            for service in custom.get("services", []):
                # Check service arguments for contrib service references
                for arg in service.get("arguments", []):
                    # Service arguments like '@symfony_mailer.mailer'
                    if "." in arg:
                        module_name = arg.split(".")[0]
                        used_modules.add(module_name)

        # Find unused
        unused = []
        for contrib in contrib_modules:
            module_name = contrib["machine_name"]
            if module_name not in used_modules:
                unused.append(
                    {
                        "module": module_name,
                        "name": contrib["name"],
                        "description": contrib["description"],
                        "package": contrib.get("package", ""),
                    }
                )

        return unused

    def check_redundancy(self, functionality: str) -> Dict:
        """
        Check if functionality already exists before building.

        Args:
            functionality: Description of what you want to build

        Returns:
            Existing solutions and recommendations
        """
        # Search for existing implementations
        results = self.search_functionality(functionality, scope="all")

        return {
            "query": functionality,
            "existing_custom": results["custom_modules"][:3],  # Top 3
            "existing_contrib": results["contrib_modules"][:3],
            "recommendation": self._generate_recommendation(results),
        }

    def _generate_recommendation(self, results: Dict) -> str:
        """
        Generate a recommendation based on search results.
        """
        custom_count = len(results["custom_modules"])
        contrib_count = len(results["contrib_modules"])

        if contrib_count > 0:
            top_contrib = results["contrib_modules"][0]
            return (
                f"Consider using {top_contrib['name']} (contrib) "
                f"before building custom solution"
            )

        if custom_count > 0:
            return "Similar functionality exists in custom modules. Consider extending."

        return "No existing solutions found. Building custom is reasonable."

    def list_all_modules(self, scope: str = "all", show_unused: bool = False) -> Dict:
        """
        List all modules with summary information.

        Args:
            scope: "all", "custom", or "contrib"
            show_unused: Include usage information
        """
        result = {
            "custom": [],
            "contrib": [],
            "total": 0,
        }

        if scope in ["all", "custom"]:
            result["custom"] = self._summarize_modules(self.indexer.modules.get("custom", []))

        if scope in ["all", "contrib"]:
            result["contrib"] = self._summarize_modules(self.indexer.modules.get("contrib", []))

        result["total"] = len(result["custom"]) + len(result["contrib"])

        if show_unused:
            result["unused_contrib"] = self.find_unused_contrib()

        return result

    def _summarize_modules(self, modules: List[Dict]) -> List[Dict]:
        """Create summary information for modules."""
        summaries = []
        for module in modules:
            summaries.append(
                {
                    "machine_name": module["machine_name"],
                    "name": module["name"],
                    "description": module["description"],
                    "services_count": len(module.get("services", [])),
                    "routes_count": len(module.get("routes", [])),
                    "classes_count": len(module.get("classes", [])),
                }
            )
        return summaries

    def describe_module(self, module_name: str) -> Dict:
        """
        Get detailed information about a specific module.

        Args:
            module_name: Machine name of the module

        Returns:
            Complete module details
        """
        module = self.indexer.get_module(module_name)

        if not module:
            return {
                "error": f"Module '{module_name}' not found",
                "found": False,
            }

        return {
            "found": True,
            "module": module,
        }
