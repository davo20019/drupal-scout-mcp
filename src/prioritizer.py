"""Result prioritization and formatting for MCP responses."""

from typing import Dict, List


class ResultPrioritizer:
    """
    Prioritizes and formats search results for presentation.
    """

    @staticmethod
    def format_search_results(results: Dict) -> str:
        """
        Format search results for display to users.

        Args:
            results: Raw search results from ModuleSearch

        Returns:
            Formatted string for MCP response
        """
        output = []

        # Header
        output.append(f"🔍 Search: '{results['query']}'")
        output.append(f"Found {results['total_matches']} matches\n")

        # Custom modules section
        if results["custom_modules"]:
            output.append("✓ CUSTOM MODULES:")
            for module in results["custom_modules"][:5]:  # Top 5
                output.append(f"\n  - {module['name']} ({module['module']})")
                output.append(f"    {module['description']}")

                # Show matches
                matches = module.get("matches", {})
                if matches["services"]:
                    output.append(f"    Services: {', '.join(matches['services'][:3])}")
                if matches["classes"]:
                    output.append(f"    Classes: {', '.join(matches['classes'][:3])}")

        # Contrib modules section
        if results["contrib_modules"]:
            output.append("\n✓ CONTRIB MODULES:")
            for module in results["contrib_modules"][:5]:  # Top 5
                output.append(f"\n  - {module['name']} ({module['module']})")
                output.append(f"    {module['description']}")

                # Show matches
                matches = module.get("matches", {})
                if matches["services"]:
                    output.append(f"    Services: {', '.join(matches['services'][:3])}")

        # No results
        if not results["custom_modules"] and not results["contrib_modules"]:
            output.append("❌ No matches found")

        return "\n".join(output)

    @staticmethod
    def format_unused_modules(unused: List[Dict]) -> str:
        """
        Format unused contrib modules report.

        Args:
            unused: List of unused modules

        Returns:
            Formatted string
        """
        if not unused:
            return "✓ All contrib modules are being used!"

        output = [
            "⚠️  UNUSED CONTRIB MODULES:\n",
            f"Found {len(unused)} modules not referenced by custom code\n",
        ]

        for module in unused:
            output.append(f"  - {module['name']} ({module['module']})")
            output.append(f"    {module['description']}")
            output.append(f"    Package: {module.get('package', 'Other')}")
            output.append("")

        output.append("💡 Consider removing unused modules to reduce site complexity")

        return "\n".join(output)

    @staticmethod
    def format_redundancy_check(check_result: Dict) -> str:
        """
        Format redundancy check results.

        Args:
            check_result: Results from check_redundancy

        Returns:
            Formatted recommendation
        """
        output = [f"🔍 Checking for: '{check_result['query']}'\n"]

        # Show existing contrib solutions
        if check_result["existing_contrib"]:
            output.append("✓ EXISTING CONTRIB SOLUTIONS:")
            for module in check_result["existing_contrib"]:
                output.append(f"\n  - {module['name']} ({module['module']})")
                output.append(f"    {module['description']}")
                matches = module.get("matches", {})
                if matches["services"]:
                    output.append(f"    Services: {', '.join(matches['services'][:3])}")
            output.append("")

        # Show existing custom solutions
        if check_result["existing_custom"]:
            output.append("✓ EXISTING CUSTOM MODULES:")
            for module in check_result["existing_custom"]:
                output.append(f"\n  - {module['name']} ({module['module']})")
                output.append(f"    {module['description']}")
            output.append("")

        # Recommendation
        output.append("💡 RECOMMENDATION:")
        output.append(f"   {check_result['recommendation']}")

        return "\n".join(output)

    @staticmethod
    def format_module_list(modules_data: Dict) -> str:
        """
        Format module list.

        Args:
            modules_data: Results from list_all_modules

        Returns:
            Formatted list
        """
        output = [f"📦 Total Modules: {modules_data['total']}\n"]

        # Custom modules
        if modules_data["custom"]:
            output.append(f"CUSTOM MODULES ({len(modules_data['custom'])}):")
            for module in modules_data["custom"]:
                output.append(f"\n  {module['name']} ({module['machine_name']})")
                output.append(f"  {module['description']}")
                output.append(
                    f"  Services: {module['services_count']}, "
                    f"Routes: {module['routes_count']}, "
                    f"Classes: {module['classes_count']}"
                )
            output.append("")

        # Contrib modules
        if modules_data["contrib"]:
            output.append(f"\nCONTRIB MODULES ({len(modules_data['contrib'])}):")
            for module in modules_data["contrib"]:
                output.append(f"\n  {module['name']} ({module['machine_name']})")
                output.append(f"  {module['description']}")
                output.append(f"  Services: {module['services_count']}")
            output.append("")

        # Unused section
        if "unused_contrib" in modules_data:
            output.append(
                "\n" + ResultPrioritizer.format_unused_modules(modules_data["unused_contrib"])
            )

        return "\n".join(output)

    @staticmethod
    def format_module_detail(module_data: Dict) -> str:
        """
        Format detailed module information.

        Args:
            module_data: Results from describe_module

        Returns:
            Formatted detail view
        """
        if not module_data.get("found"):
            error_msg = module_data.get("error", "Module not found")
            return f"❌ {error_msg}\n\n💡 **Note:** This tool only describes locally installed modules.\n\nTo get details about modules from drupal.org, use:\n  • `get_drupal_org_module_details` - Get details from drupal.org\n  • `search_drupal_org` - Search for available modules"

        module = module_data["module"]

        output = [
            f"📦 {module['name']} ({module['machine_name']})",
            f"   {module['description']}\n",
            f"Type: {module.get('type', 'module')}",
            f"Package: {module.get('package', 'Other')}",
            f"Path: {module.get('path', '')}\n",
        ]

        # Dependencies
        if module.get("dependencies"):
            output.append("Dependencies:")
            for dep in module["dependencies"]:
                output.append(f"  - {dep}")
            output.append("")

        # Services
        if module.get("services"):
            output.append(f"Services ({len(module['services'])}):")
            for service in module["services"][:10]:  # Limit to 10
                output.append(f"  - {service['id']}")
                if service.get("class"):
                    output.append(f"    Class: {service['class']}")
                if service.get("arguments"):
                    output.append(f"    Uses: {', '.join(service['arguments'][:3])}")
            output.append("")

        # Routes
        if module.get("routes"):
            output.append(f"Routes ({len(module['routes'])}):")
            for route in module["routes"][:10]:
                output.append(f"  - {route['name']}")
                output.append(f"    Path: {route.get('path', '')}")
            output.append("")

        # Classes
        if module.get("classes"):
            output.append(f"Classes ({len(module['classes'])}):")
            for cls in module["classes"][:10]:
                output.append(f"  - {cls['name']}")
                if cls.get("extends"):
                    output.append(f"    Extends: {cls['extends']}")
            output.append("")

        # Hooks
        if module.get("hooks"):
            output.append(f"Hooks ({len(module['hooks'])}):")
            for hook in module["hooks"][:10]:
                output.append(f"  - {hook}")
            output.append("")

        return "\n".join(output)
