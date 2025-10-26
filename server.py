#!/usr/bin/env python3
"""
Drupal Scout MCP Server

A Model Context Protocol server for discovering functionality in Drupal sites.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional, List

from fastmcp import FastMCP

# Core utilities
from src.core.config import (
    get_config,
    get_indexer,
    get_searcher,
    get_prioritizer,
    get_drupal_org_api,
    ensure_indexed,
    reset_index,
)
from src.core.drush import run_drush_command
from src.core.database import verify_database_connection

# Existing modules
from src.drupal_org import format_drupal_org_results, generate_recommendations

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("Drupal Scout")

# CRITICAL FIX: When running as __main__, tool modules import from 'server'
# We need to ensure 'server' module points to __main__ to share the mcp instance
if __name__ == "__main__":
    sys.modules["server"] = sys.modules["__main__"]

# Import tool modules to register @mcp.tool() decorated functions
# IMPORTANT: Must import AFTER mcp instance is created (above)
import src.tools.exports  # noqa: E402, F401
import src.tools.drupal_org  # noqa: E402, F401
import src.tools.system  # noqa: E402, F401
import src.tools.entities  # noqa: E402, F401

# Note: Core utilities (config, drush, database) moved to src/core/
# Global state is now managed by core modules for better modularity
#
# Create module-level variable for prioritizer (used frequently in formatting)
prioritizer = get_prioritizer()


@mcp.tool()
def search_functionality(query: str, scope: str = "all", include_drupal_org: bool = True) -> str:
    """
    Search for functionality across Drupal modules.

    Use this to find existing implementations before building new features.
    Great for questions like:
    - "Do we have HTML email functionality?"
    - "What payment services are available?"
    - "Is there a PDF generator?"

    Args:
        query: What to search for (e.g., "email", "PDF", "API", "payment")
        scope: Where to search - "all" (default), "custom", or "contrib"
        include_drupal_org: Also search drupal.org if no local results (default: True)

    Returns:
        Formatted search results showing custom and contrib modules
    """
    ensure_indexed()

    logger.info(f"Searching for: {query} (scope: {scope})")
    results = get_searcher().search_functionality(query, scope)

    output = prioritizer.format_search_results(results)

    # If no local results and drupal.org search enabled, search drupal.org
    if include_drupal_org and results["total_matches"] == 0:
        logger.info(f"No local results, searching drupal.org for: {query}")
        drupal_org_results = get_drupal_org_api().search_modules(query, limit=5)

        if drupal_org_results:
            output += "\n\n" + "=" * 60 + "\n"
            output += (
                "💡 **No local modules found. Showing available modules from drupal.org:**\n\n"
            )
            output += format_drupal_org_results(drupal_org_results, query)

            # Generate recommendations
            local_results_list = results["custom_modules"] + results["contrib_modules"]
            output += "\n\n" + generate_recommendations(
                query, local_results_list, drupal_org_results
            )

    return output


@mcp.tool()
def list_modules(scope: str = "all", show_unused: bool = False) -> str:
    """
    List all Drupal modules with summary information.

    Great for getting an overview of what's installed.

    Args:
        scope: Which modules to list - "all" (default), "custom", or "contrib"
        show_unused: Include analysis of unused contrib modules

    Returns:
        Formatted list of modules with counts and capabilities
    """
    ensure_indexed()

    logger.info(f"Listing modules (scope: {scope}, show_unused: {show_unused})")
    modules_data = get_searcher().list_all_modules(scope, show_unused)

    return prioritizer.format_module_list(modules_data)


@mcp.tool()
def describe_module(module_name: str) -> str:
    """
    Get detailed information about a specific module.

    Shows everything: services, routes, classes, hooks, dependencies.
    Perfect for deep-diving into how a module works.

    Args:
        module_name: Machine name of the module (e.g., "symfony_mailer")

    Returns:
        Detailed module information
    """
    ensure_indexed()

    logger.info(f"Describing module: {module_name}")
    module_data = get_searcher().describe_module(module_name)

    return prioritizer.format_module_detail(module_data)


@mcp.tool()
def find_unused_contrib() -> str:
    """
    Find contrib modules that aren't used by custom code.

    **Enhanced with drush integration** - checks both code usage AND installation status!

    Identifies:
    - Modules not in any custom module dependencies
    - Modules whose services aren't injected anywhere
    - Modules that are installed but not actually enabled
    - Potential cleanup opportunities

    A module is considered "unused" if:
    1. NOT referenced in custom code (dependencies or services) AND
    2. Shows installation status (installed vs not installed)

    This helps you safely identify modules that can be removed without breaking functionality.

    Great for site optimization and reducing complexity!

    Returns:
        List of unused contrib modules with installation status and recommendations
    """
    ensure_indexed()

    logger.info("Finding unused contrib modules (with drush installation check)")
    unused = get_searcher().find_unused_contrib(check_installed=True)

    return prioritizer.format_unused_modules(unused)


@mcp.tool()
def check_redundancy(functionality: str) -> str:
    """
    Check if functionality already exists before building it.

    Ask before you build! This prevents duplicate functionality.

    Examples:
    - "Should I build a PDF export feature?"
    - "Do we need a custom email service?"
    - "Is there payment processing already?"

    Args:
        functionality: Description of what you want to build

    Returns:
        Existing solutions and recommendations
    """
    ensure_indexed()

    logger.info(f"Checking redundancy for: {functionality}")
    check_result = get_searcher().check_redundancy(functionality)

    return prioritizer.format_redundancy_check(check_result)


@mcp.tool()
def reindex_modules() -> str:
    """
    Force re-indexing of all Drupal modules.

    Use this when:
    - Modules have been added/removed
    - Configuration has changed
    - You want fresh data

    Returns:
        Confirmation of reindexing
    """
    logger.info("Forcing module reindex")

    # Clear existing index and force re-indexing
    reset_index()
    ensure_indexed()

    return f"✓ Reindexed {get_indexer().modules.get('total', 0)} modules successfully"


@mcp.tool()
def analyze_module_dependencies(module_name: str = None) -> str:
    """
    Analyze module dependency relationships (forward and reverse).

    Unlike 'drush pm:info', this provides comprehensive dependency analysis:
    - Reverse dependencies: What depends on this module?
    - Full dependency tree: Not just direct dependencies
    - Circular dependency detection
    - Safe uninstall impact analysis
    - Custom vs contrib coupling analysis

    Use this to answer:
    - "Can I safely uninstall this module?"
    - "What will break if I update/remove this?"
    - "Which modules depend on token/pathauto/etc?"
    - "Are there circular dependencies?"

    Args:
        module_name: Module to analyze, or None for system-wide dependency report

    Returns:
        Comprehensive dependency analysis with uninstall safety assessment
    """
    ensure_indexed()

    logger.info(f"Analyzing dependencies for: {module_name or 'all modules'}")

    # Build dependency graph
    dep_graph = _build_dependency_graph()

    if module_name:
        # Single module analysis
        return _analyze_single_module(module_name, dep_graph)
    else:
        # System-wide analysis
        return _analyze_all_dependencies(dep_graph)


def _build_dependency_graph() -> dict:
    """
    Build a complete dependency graph from indexed modules.

    Returns:
        dict with:
        - forward: {module: [dependencies]}
        - reverse: {module: [dependents]}
        - modules: {module: metadata}
    """
    forward = {}  # module -> what it depends on
    reverse = {}  # module -> what depends on it
    modules = {}  # module -> full module data

    all_modules = (
        get_indexer().modules.get("custom", [])
        + get_indexer().modules.get("contrib", [])
        + get_indexer().modules.get("core", [])
    )

    # Build forward dependencies
    for module in all_modules:
        module_name = module.get("module")
        if not module_name:
            continue

        modules[module_name] = module
        dependencies = module.get("dependencies", [])

        # Clean dependency names (remove version constraints)
        clean_deps = []
        for dep in dependencies:
            # Handle "drupal:module" or "module (>=version)"
            dep_name = dep.split(":")[-1].split("(")[0].strip()
            clean_deps.append(dep_name)

        forward[module_name] = clean_deps

    # Build reverse dependencies
    for module_name, deps in forward.items():
        for dep in deps:
            if dep not in reverse:
                reverse[dep] = []
            reverse[dep].append(module_name)

    return {"forward": forward, "reverse": reverse, "modules": modules}


def _find_circular_dependencies(graph: dict) -> list:
    """
    Detect circular dependencies using DFS.

    Returns:
        List of circular dependency chains
    """
    forward = graph["forward"]
    circles = []
    visited = set()
    rec_stack = set()

    def dfs(node, path):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in forward.get(node, []):
            if neighbor not in visited:
                dfs(neighbor, path[:])
            elif neighbor in rec_stack:
                # Found a circle
                circle_start = path.index(neighbor)
                circle = path[circle_start:] + [neighbor]
                circles.append(circle)

        rec_stack.remove(node)

    for module in forward.keys():
        if module not in visited:
            dfs(module, [])

    return circles


def _analyze_single_module(module_name: str, dep_graph: dict) -> str:
    """Analyze dependencies for a single module."""
    forward = dep_graph["forward"]
    reverse = dep_graph["reverse"]
    modules = dep_graph["modules"]

    # Check if module exists
    if module_name not in modules:
        return f"❌ Module '{module_name}' not found in indexed modules\n\n💡 Try: list_modules() or reindex_modules()"

    module = modules[module_name]
    output = [f"📦 **Dependency Analysis: {module.get('name', module_name)}** (`{module_name}`)\n"]

    module_type = module.get("type", "unknown")
    output.append(f"**Type:** {module_type}")
    output.append(f"**Package:** {module.get('package', 'N/A')}\n")

    # Forward dependencies (what this module needs)
    direct_deps = forward.get(module_name, [])
    if direct_deps:
        output.append(f"## ⬇️  Dependencies ({len(direct_deps)})")
        output.append(f"*Modules that {module_name} requires:*\n")

        for dep in direct_deps:
            dep_type = modules.get(dep, {}).get("type", "unknown")
            dep_icon = "📦" if dep_type == "contrib" else "🔧" if dep_type == "custom" else "⚙️ "
            output.append(f"- {dep_icon} `{dep}` ({dep_type})")
    else:
        output.append("## ⬇️  Dependencies\n*No dependencies* - This is a leaf module")

    # Reverse dependencies (what needs this module)
    dependents = reverse.get(module_name, [])
    if dependents:
        output.append(f"\n## ⬆️  Reverse Dependencies ({len(dependents)})")
        output.append(f"*Modules that depend on {module_name}:*\n")

        # Group by type
        custom_deps = [d for d in dependents if modules.get(d, {}).get("type") == "custom"]
        contrib_deps = [d for d in dependents if modules.get(d, {}).get("type") == "contrib"]
        core_deps = [d for d in dependents if modules.get(d, {}).get("type") == "core"]

        if custom_deps:
            output.append(f"**Custom modules ({len(custom_deps)}):**")
            for dep in sorted(custom_deps):
                output.append(f"- 🔧 `{dep}`")

        if contrib_deps:
            output.append(f"\n**Contrib modules ({len(contrib_deps)}):**")
            for dep in sorted(contrib_deps)[:10]:  # Limit to 10
                output.append(f"- 📦 `{dep}`")
            if len(contrib_deps) > 10:
                output.append(f"   ... and {len(contrib_deps) - 10} more")

        if core_deps:
            output.append(f"\n**Core modules ({len(core_deps)}):**")
            for dep in sorted(core_deps)[:5]:
                output.append(f"- ⚙️  `{dep}`")
    else:
        output.append(
            "\n## ⬆️  Reverse Dependencies\n*Nothing depends on this module* - Safe to remove"
        )

    # Uninstall safety analysis
    output.append("\n## 🔒 Uninstall Safety Analysis\n")

    if not dependents:
        output.append("✅ **SAFE TO UNINSTALL**")
        output.append("- No other modules depend on this")
        output.append("- Can be removed without breaking anything")
    else:
        output.append("⚠️  **CANNOT SAFELY UNINSTALL**")
        output.append(f"- {len(dependents)} module(s) depend on this")

        if custom_deps:
            output.append(f"- **{len(custom_deps)} custom module(s)** would break")
            output.append("- You must refactor custom code first")

        output.append("\n**To uninstall, you must first remove:**")
        for dep in sorted(dependents)[:5]:
            output.append(f"  1. `{dep}`")
        if len(dependents) > 5:
            output.append(f"  ... and {len(dependents) - 5} more")

    # Check for circular dependencies involving this module
    circles = _find_circular_dependencies(dep_graph)
    module_circles = [c for c in circles if module_name in c]

    if module_circles:
        output.append("\n## ⚠️  Circular Dependencies Detected\n")
        for i, circle in enumerate(module_circles, 1):
            output.append(f"**Circle {i}:** {' → '.join(circle)}")
        output.append("\n💡 Circular dependencies can cause installation/uninstallation issues")

    return "\n".join(output)


def _analyze_all_dependencies(dep_graph: dict) -> str:
    """System-wide dependency analysis."""
    forward = dep_graph["forward"]
    reverse = dep_graph["reverse"]
    modules = dep_graph["modules"]

    output = ["📊 **System-Wide Dependency Analysis**\n"]

    # Overview stats
    total_modules = len(modules)
    custom_count = sum(1 for m in modules.values() if m.get("type") == "custom")
    contrib_count = sum(1 for m in modules.values() if m.get("type") == "contrib")
    core_count = sum(1 for m in modules.values() if m.get("type") == "core")

    output.append(f"**Total Modules:** {total_modules}")
    output.append(f"- 🔧 Custom: {custom_count}")
    output.append(f"- 📦 Contrib: {contrib_count}")
    output.append(f"- ⚙️  Core: {core_count}\n")

    # Find modules with most dependents (most critical)
    most_critical = sorted(
        [(mod, len(deps)) for mod, deps in reverse.items()], key=lambda x: x[1], reverse=True
    )[:10]

    if most_critical:
        output.append("## 🔥 Most Critical Modules")
        output.append("*Modules that many others depend on:*\n")
        for module_name, dep_count in most_critical:
            module_type = modules.get(module_name, {}).get("type", "unknown")
            icon = "📦" if module_type == "contrib" else "🔧" if module_type == "custom" else "⚙️ "
            output.append(f"- {icon} **`{module_name}`** - {dep_count} modules depend on it")

    # Find orphan modules (nothing depends on them)
    orphans = [mod for mod in modules.keys() if mod not in reverse or not reverse[mod]]

    output.append(f"\n## 🍃 Independent Modules ({len(orphans)})")
    output.append("*Modules with no dependents (safe to remove):*\n")

    # Group orphans by type
    custom_orphans = [m for m in orphans if modules.get(m, {}).get("type") == "custom"]
    contrib_orphans = [m for m in orphans if modules.get(m, {}).get("type") == "contrib"]

    if custom_orphans:
        output.append(f"**Custom ({len(custom_orphans)}):**")
        for mod in sorted(custom_orphans)[:10]:
            output.append(f"- 🔧 `{mod}`")
        if len(custom_orphans) > 10:
            output.append(f"  ... and {len(custom_orphans) - 10} more")

    if contrib_orphans:
        output.append(f"\n**Contrib ({len(contrib_orphans)}):**")
        for mod in sorted(contrib_orphans)[:10]:
            output.append(f"- 📦 `{mod}`")
        if len(contrib_orphans) > 10:
            output.append(f"  ... and {len(contrib_orphans) - 10} more")

    # Circular dependencies
    circles = _find_circular_dependencies(dep_graph)

    if circles:
        output.append(f"\n## ⚠️  Circular Dependencies ({len(circles)})\n")
        for i, circle in enumerate(circles[:5], 1):
            output.append(f"**{i}.** {' → '.join(circle)}")
        if len(circles) > 5:
            output.append(f"\n... and {len(circles) - 5} more circular dependencies")
        output.append("\n💡 Use analyze_module_dependencies('module_name') for details")
    else:
        output.append("\n## ✅ No Circular Dependencies\n*Dependency tree is clean*")

    # Custom module coupling
    custom_to_contrib_deps = {}
    for module_name in modules.keys():
        if modules[module_name].get("type") == "custom":
            contrib_deps = [
                d
                for d in forward.get(module_name, [])
                if modules.get(d, {}).get("type") == "contrib"
            ]
            if contrib_deps:
                custom_to_contrib_deps[module_name] = contrib_deps

    if custom_to_contrib_deps:
        output.append("\n## 🔗 Custom Module Dependencies")
        output.append("*Contrib modules your custom code depends on:*\n")

        # Find most-used contrib modules by custom code
        contrib_usage = {}
        for contrib_deps in custom_to_contrib_deps.values():
            for dep in contrib_deps:
                contrib_usage[dep] = contrib_usage.get(dep, 0) + 1

        most_used = sorted(contrib_usage.items(), key=lambda x: x[1], reverse=True)[:10]
        for contrib, count in most_used:
            output.append(f"- 📦 **`{contrib}`** - used by {count} custom module(s)")

    output.append(
        "\n💡 **Tip:** Use `analyze_module_dependencies('module_name')` for detailed analysis"
    )

    return "\n".join(output)

    return "\n".join(output)


@mcp.tool()
def find_hook_implementations(hook_name: str) -> str:
    """
    Find all implementations of a Drupal hook across modules.

    This tool searches indexed modules to find where a specific Drupal hook
    is implemented. Useful for debugging hook execution order, finding conflicts,
    or understanding what code runs for a particular hook.

    IMPORTANT: This searches the pre-indexed modules. If you recently added
    a hook implementation, call reindex_modules() first.

    No drush needed - pure file-based search using cached index.

    Common use cases:
    - "Why isn't my hook_form_alter working?" → See execution order
    - "Which modules alter node pages?" → Find hook_node_view implementations
    - "What runs on user login?" → Find hook_user_login implementations

    Args:
        hook_name: The hook to search for (e.g., "hook_form_alter", "hook_node_insert")
                   Can be the generic hook name or module-specific implementation

    Returns:
        List of modules implementing the hook with file locations and line numbers
    """
    ensure_indexed()

    logger.info(f"Searching for hook implementations: {hook_name}")

    # Normalize hook name (remove module prefix if provided)
    # e.g., "my_module_hook_form_alter" → "hook_form_alter"
    if "_hook_" in hook_name and not hook_name.startswith("hook_"):
        # Extract just the hook part
        parts = hook_name.split("_hook_")
        if len(parts) == 2:
            hook_name = "hook_" + parts[1]

    results = {
        "custom": [],
        "contrib": [],
        "core": [],
    }

    # Search all indexed modules
    for module_type in ["custom", "contrib", "core"]:
        modules = get_indexer().modules.get(module_type, [])

        for module in modules:
            hooks = module.get("hooks", [])

            # Check if this module implements the hook
            for hook in hooks:
                # Handle both old format (strings) and new format (dicts with line numbers)
                if isinstance(hook, dict):
                    hook_impl_name = hook.get("name", "")
                    line_number = hook.get("line")
                else:
                    # Backward compatibility with old string format
                    hook_impl_name = hook
                    line_number = None

                # Check if this hook matches what we're looking for
                # Match pattern: module_name + hook_name (e.g., "my_module_hook_form_alter")
                if hook_name in hook_impl_name:
                    module_file = f"{module['machine_name']}.module"
                    file_location = f"{module_file}:{line_number}" if line_number else module_file

                    results[module_type].append(
                        {
                            "module": module["machine_name"],
                            "name": module["name"],
                            "hook_function": hook_impl_name,
                            "file": file_location,
                            "path": module["path"],
                        }
                    )

    # Count total implementations
    total = len(results["custom"]) + len(results["contrib"]) + len(results["core"])

    # Format output
    output = [f"🔍 **Hook Implementations: `{hook_name}`**\n"]

    if total == 0:
        output.append("❌ **No implementations found**\n")
        output.append(f"No modules implement `{hook_name}`.\n")
        output.append("**Possible reasons:**")
        output.append("• Hook name might be misspelled")
        output.append("• Module implementing it isn't indexed")
        output.append("• Hook implementation was recently added (try reindex_modules())")
        return "\n".join(output)

    output.append(f"**Found {total} implementation{'s' if total != 1 else ''}**\n")

    # Show custom implementations
    if results["custom"]:
        output.append(f"## 🔧 Custom Modules ({len(results['custom'])})\n")
        for impl in results["custom"]:
            output.append(f"**{impl['name']}** (`{impl['module']}`)")
            output.append(f"   • Function: `{impl['hook_function']}`")
            output.append(f"   • Location: `{impl['file']}`")
            output.append(f"   • Path: `{impl['path']}`")
            output.append("")

    # Show contrib implementations
    if results["contrib"]:
        output.append(f"## 📦 Contrib Modules ({len(results['contrib'])})\n")
        # Limit to first 10 to avoid token overload
        for impl in results["contrib"][:10]:
            output.append(f"**{impl['name']}** (`{impl['module']}`)")
            output.append(f"   • Function: `{impl['hook_function']}`")
            output.append(f"   • Location: `{impl['file']}`")
            output.append("")
        if len(results["contrib"]) > 10:
            output.append(f"*... and {len(results['contrib']) - 10} more contrib modules*\n")

    # Show core implementations
    if results["core"]:
        output.append(f"## ⚙️  Core Modules ({len(results['core'])})\n")
        # Limit to first 5
        for impl in results["core"][:5]:
            output.append(f"**{impl['name']}** (`{impl['module']}`)")
            output.append(f"   • Function: `{impl['hook_function']}`")
            output.append("")
        if len(results["core"]) > 5:
            output.append(f"*... and {len(results['core']) - 5} more core modules*\n")

    # Add debugging tips
    output.append("\n## 💡 **Debugging Tips**\n")
    output.append("**Hook execution order:**")
    output.append("• Core hooks run first")
    output.append("• Then contrib (alphabetically by module name)")
    output.append("• Then custom (alphabetically by module name)")
    output.append("• Use hook_module_implements_alter() to change order\n")

    output.append("**Common issues:**")
    output.append("• Clear cache after adding new hooks")
    output.append("• Check hook function name matches module name")
    output.append("• Verify .module file is in module root")

    return "\n".join(output)


@mcp.tool()
def get_views_summary(view_name: Optional[str] = None, entity_type: Optional[str] = None) -> str:
    """
    Get summary of Drupal Views configurations with optional filtering.

    **USE THIS TOOL** for questions about existing views, data displays, or before creating new views.

    This tool answers questions like:
    - "What views exist in the site?"
    - "Show me the displays for the content view"
    - "What filters are configured in views?"
    - "Are there any views showing articles?" → Use entity_type="node"
    - "Do we have any user views?" → Use entity_type="users"
    - "Are there views for schools?" → Use entity_type="node" (schools are content)
    - "Show me taxonomy term views" → Use entity_type="taxonomy_term"

    Provides:
    - View names and labels
    - Display types (page, block, feed, etc.)
    - Display paths and settings
    - Filters and relationships
    - Fields being displayed

    Uses drush-first approach to get active views from database,
    falls back to parsing views.view.*.yml config files.

    Saves ~700-900 tokens vs running multiple drush/grep commands.

    Args:
        view_name: Optional. Specific view machine name to get details for.
                   If omitted, returns summary of all views.
        entity_type: Optional. Filter views by entity type/base table.
                     Common values: "node", "users", "taxonomy_term", "media", "comment"
                     Also accepts base table names: "node_field_data", "users_field_data"

    Returns:
        Formatted summary of views configurations
    """
    try:
        drupal_root = Path(get_config().get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ Error: Drupal root not found. Check drupal_root in config."

        # Get views data (drush first, then file fallback)
        views_data = _get_views_data(view_name, drupal_root)

        if not views_data:
            if view_name:
                return f"❌ No view found with name '{view_name}'"
            return "ℹ️ No views found in this Drupal installation"

        # Filter by entity_type if provided
        if entity_type:
            views_data = _filter_views_by_entity_type(views_data, entity_type)

            if not views_data:
                return f"ℹ️ No views found for entity type '{entity_type}'"

        # Format output
        output = []

        if view_name:
            # Single view detailed output
            view = views_data[0]
            output.append(f"📊 View: {view['label']} ({view['id']})")
            output.append(f"   Status: {'✅ Enabled' if view.get('status') else '❌ Disabled'}")
            output.append(f"   Base Table: {view.get('base_table', 'Unknown')}")
            output.append(f"   Description: {view.get('description', 'No description')}")
            output.append("")

            displays = view.get("displays", [])
            if displays:
                output.append(f"   Displays ({len(displays)}):")
                for display in displays:
                    output.append(f"   • {display['display_title']} [{display['display_plugin']}]")
                    if display.get("path"):
                        output.append(f"     Path: {display['path']}")
                    if display.get("filters"):
                        output.append(f"     Filters: {', '.join(display['filters'])}")
                    if display.get("fields"):
                        output.append(
                            f"     Fields: {', '.join(display['fields'][:5])}{'...' if len(display['fields']) > 5 else ''}"
                        )
                    if display.get("relationships"):
                        output.append(f"     Relationships: {', '.join(display['relationships'])}")
                    output.append("")
        else:
            # Multiple views summary
            header = f"📊 Views Summary ({len(views_data)} views found)"
            if entity_type:
                header += f" - Showing '{entity_type}' views only"
            output.append(header + "\n")

            for view in views_data:
                status_icon = "✅" if view.get("status") else "❌"
                output.append(f"{status_icon} {view['label']} ({view['id']})")

                displays = view.get("displays", [])
                if displays:
                    display_types = [d["display_plugin"] for d in displays]
                    output.append(f"   Displays: {', '.join(display_types)}")

                # Show base table for context
                base_table = view.get("base_table", "")
                if base_table:
                    output.append(f"   Base: {base_table}")

                output.append("")

        result = "\n".join(output)

        return result

    except Exception as e:
        logger.error(f"Error getting views summary: {e}")
        return f"❌ Error: {str(e)}"


def _filter_views_by_entity_type(views_data: List[dict], entity_type: str) -> List[dict]:
    """
    Filter views by entity type or base table.

    Handles common entity type mappings:
    - "node" → "node", "node_field_data"
    - "users" → "users", "users_field_data"
    - "taxonomy_term" → "taxonomy_term_data", "taxonomy_term_field_data"
    - "media" → "media", "media_field_data"
    - "comment" → "comment", "comment_field_data"

    Args:
        views_data: List of view data dictionaries
        entity_type: Entity type or base table name to filter by

    Returns:
        Filtered list of views
    """
    # Map entity types to possible base table names
    entity_type_mappings = {
        "node": ["node", "node_field_data", "node_revision"],
        "users": ["users", "users_field_data"],
        "user": ["users", "users_field_data"],  # Accept both singular/plural
        "taxonomy_term": ["taxonomy_term_data", "taxonomy_term_field_data"],
        "media": ["media", "media_field_data"],
        "comment": ["comment", "comment_field_data"],
        "file": ["file_managed"],
        "block_content": ["block_content", "block_content_field_data"],
    }

    # Get possible base tables for this entity type
    possible_tables = entity_type_mappings.get(entity_type.lower(), [entity_type])

    # Filter views
    filtered = []
    for view in views_data:
        base_table = view.get("base_table", "").lower()

        # Check if base table matches any of the possible tables
        if any(table in base_table for table in possible_tables):
            filtered.append(view)

    return filtered


def _get_views_data(view_name: Optional[str], drupal_root: Path) -> List[dict]:
    """
    Get views data using drush-first, file-fallback approach.

    Args:
        view_name: Optional specific view machine name
        drupal_root: Path to Drupal root

    Returns:
        List of view data dictionaries
    """
    # Try drush first - gets active config from database
    drush_views = _get_views_from_drush(view_name)
    if drush_views:
        logger.debug(f"Retrieved {len(drush_views)} views from drush")
        return drush_views

    # Fallback: Parse config files
    logger.debug("Drush unavailable, falling back to file-based views config parsing")
    return _get_views_from_files(view_name, drupal_root)


def _get_views_from_drush(view_name: Optional[str]) -> Optional[List[dict]]:
    """Get active views configs from database via drush."""
    try:
        # Build filter condition
        filter_condition = ""
        if view_name:
            filter_condition = f"if ($view->id() != '{view_name}') continue;"

        php_code = f"""
        $views_data = [];
        $view_storage = \\Drupal::entityTypeManager()->getStorage('view');

        $views = $view_storage->loadMultiple();

        foreach ($views as $view) {{
            {filter_condition}

            $view_config = [
                'id' => $view->id(),
                'label' => $view->label(),
                'status' => $view->status(),
                'description' => $view->get('description'),
                'base_table' => $view->get('base_table'),
                'displays' => []
            ];

            $displays = $view->get('display');
            foreach ($displays as $display_id => $display_config) {{
                $display_info = [
                    'id' => $display_id,
                    'display_plugin' => $display_config['display_plugin'] ?? 'unknown',
                    'display_title' => $display_config['display_title'] ?? $display_id,
                    'path' => $display_config['display_options']['path'] ?? null,
                    'filters' => [],
                    'fields' => [],
                    'relationships' => []
                ];

                // Get filters
                if (isset($display_config['display_options']['filters'])) {{
                    $display_info['filters'] = array_keys($display_config['display_options']['filters']);
                }}

                // Get fields
                if (isset($display_config['display_options']['fields'])) {{
                    $display_info['fields'] = array_keys($display_config['display_options']['fields']);
                }}

                // Get relationships
                if (isset($display_config['display_options']['relationships'])) {{
                    $display_info['relationships'] = array_keys($display_config['display_options']['relationships']);
                }}

                $view_config['displays'][] = $display_info;
            }}

            $views_data[] = $view_config;
        }}

        echo json_encode($views_data);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=20)

        if result and isinstance(result, list):
            return result

        return None
    except Exception as e:
        logger.debug(f"Could not get views from drush: {e}")
        return None


def _get_views_from_files(view_name: Optional[str], drupal_root: Path) -> List[dict]:
    """Parse views from config files as fallback."""
    views_data = []

    config_locations = [
        drupal_root / "config" / "sync",
        drupal_root / "config" / "default",
        drupal_root / "sites" / "default" / "config" / "sync",
        drupal_root / "recipes",
    ]

    # Look for views.view.*.yml files
    pattern = "views.view.*.yml" if not view_name else f"views.view.{view_name}.yml"

    for config_dir in config_locations:
        if not config_dir.exists():
            continue

        for config_file in config_dir.rglob(pattern):
            try:
                import yaml

                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)

                if not config:
                    continue

                view_config = {
                    "id": get_config().get("id", "unknown"),
                    "label": get_config().get("label", "Unknown"),
                    "status": get_config().get("status", False),
                    "description": get_config().get("description", ""),
                    "base_table": get_config().get("base_table", ""),
                    "displays": [],
                }

                # Parse displays
                displays = get_config().get("display", {})
                for display_id, display_data in displays.items():
                    display_info = {
                        "id": display_id,
                        "display_plugin": display_data.get("display_plugin", "unknown"),
                        "display_title": display_data.get("display_title", display_id),
                        "path": None,
                        "filters": [],
                        "fields": [],
                        "relationships": [],
                    }

                    display_options = display_data.get("display_options", {})

                    # Get path
                    if "path" in display_options:
                        display_info["path"] = display_options["path"]

                    # Get filters
                    if "filters" in display_options:
                        display_info["filters"] = list(display_options["filters"].keys())

                    # Get fields
                    if "fields" in display_options:
                        display_info["fields"] = list(display_options["fields"].keys())

                    # Get relationships
                    if "relationships" in display_options:
                        display_info["relationships"] = list(
                            display_options["relationships"].keys()
                        )

                    view_config["displays"].append(display_info)

                views_data.append(view_config)

            except Exception as e:
                logger.debug(f"Error parsing {config_file}: {e}")
                continue

    return views_data


@mcp.tool()
def get_taxonomy_info(
    vocabulary: Optional[str] = None, term_name: Optional[str] = None, term_id: Optional[int] = None
) -> str:
    """
    Get comprehensive information about Drupal taxonomies, vocabularies, and terms.

    **USE THIS TOOL** before deleting, renaming, or modifying taxonomy terms/vocabularies.

    This tool answers questions like:
    - "What taxonomy vocabularies exist?"
    - "Show me all terms in the categories vocabulary"
    - "Where is the 'Technology' term used?" → Use term_name="Technology"
    - "Can I safely delete the 'Old Category' term?" → Use term_name="Old Category"
    - "Where is the Drupal term being used?" → Use term_name="Drupal", vocabulary="tags"
    - "What content uses terms from the tags vocabulary?"
    - "Show me the hierarchy of the main menu vocabulary"
    - "Which fields reference the categories vocabulary?"

    IMPORTANT: To find where a specific term is used:
    1. Use term_name parameter: get_taxonomy_info(term_name="Drupal", vocabulary="tags")
    2. If only one match, automatically shows detailed usage analysis
    3. If multiple matches, shows list with term IDs to choose from

    DO NOT try to find term IDs manually - use term_name parameter!

    Provides:
    - Vocabulary list with term counts
    - Term hierarchies (parent/child relationships)
    - Term usage in content (which nodes reference each term)
    - Term usage in views (filters, contextual filters, relationships)
    - Fields that reference each vocabulary
    - Safe-to-delete analysis for terms
    - Term metadata (name, description, weight, parent)

    Uses drush-first approach to get active taxonomy data from database,
    falls back to parsing taxonomy config files and searching codebase.

    Saves ~1000-1500 tokens vs running multiple taxonomy commands + content queries.

    **Agent-friendly:** This tool works well in loops for checking multiple terms.
    Agents can call this tool 50-100+ times to verify safe-to-delete candidates.

    Args:
        vocabulary: Optional. Vocabulary machine name (e.g., "tags", "categories").
                    If omitted, returns list of all vocabularies.
        term_name: Optional. Search for specific term by name (partial matching).
                   Example: "tech" finds "Technology", "Tech News", etc.
        term_id: Optional. Specific term ID (tid) to get detailed usage info.
                 Use this to see where a specific term is used before deleting.

    Returns:
        Formatted taxonomy information with usage analysis
    """
    try:
        drupal_root = Path(get_config().get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ Error: Drupal root not found. Check drupal_root in config."

        # Get taxonomy data (drush first, then file fallback)
        if term_id:
            # Detailed term usage analysis
            return _get_term_usage_analysis(term_id, drupal_root)
        elif term_name:
            # Search for terms by name
            return _search_terms_by_name(term_name, vocabulary, drupal_root)
        elif vocabulary:
            # Show all terms in a vocabulary
            return _get_vocabulary_terms(vocabulary, drupal_root)
        else:
            # List all vocabularies
            return _get_vocabularies_summary(drupal_root)

    except Exception as e:
        logger.error(f"Error getting taxonomy info: {e}")
        return f"❌ Error: {str(e)}"


def _get_vocabularies_summary(drupal_root: Path) -> str:
    """Get summary of all vocabularies."""
    vocabs_data = _get_vocabularies_from_drush()

    if not vocabs_data:
        # Fallback to file parsing
        vocabs_data = _get_vocabularies_from_files(drupal_root)

    if not vocabs_data:
        return "ℹ️ No taxonomy vocabularies found"

    output = [f"📚 Taxonomy Vocabularies ({len(vocabs_data)} found)\n"]

    for vocab in vocabs_data:
        output.append(f"• {vocab['label']} ({vocab['id']})")
        if vocab.get("description"):
            output.append(f"  Description: {vocab['description']}")

        term_count = vocab.get("term_count", 0)
        output.append(f"  Terms: {term_count}")

        # Show which fields reference this vocabulary
        fields = vocab.get("referencing_fields", [])
        if fields:
            field_summary = ", ".join(fields[:3])
            if len(fields) > 3:
                field_summary += f" (+{len(fields) - 3} more)"
            output.append(f"  Used by fields: {field_summary}")

        output.append("")

    return "\n".join(output)


def _get_vocabulary_terms(vocabulary: str, drupal_root: Path) -> str:
    """Get all terms in a vocabulary with hierarchy."""
    terms_data = _get_terms_from_drush(vocabulary)

    if not terms_data:
        # Fallback to file parsing
        terms_data = _get_terms_from_files(vocabulary, drupal_root)

    if not terms_data:
        return f"ℹ️ No terms found in vocabulary '{vocabulary}'"

    vocab_info = terms_data.get("vocabulary", {})
    terms = terms_data.get("terms", [])

    output = [f"📚 Vocabulary: {vocab_info.get('label', vocabulary)} ({vocabulary})"]
    if vocab_info.get("description"):
        output.append(f"   Description: {vocab_info['description']}")
    output.append(f"   Total terms: {len(terms)}\n")

    # Build hierarchy
    hierarchy = _build_term_hierarchy(terms)

    output.append("📖 Terms:")
    _append_term_tree(output, hierarchy, 0)

    return "\n".join(output)


def _search_terms_by_name(term_name: str, vocabulary: Optional[str], drupal_root: Path) -> str:
    """Search for terms by name across vocabularies."""
    results = _search_terms_from_drush(term_name, vocabulary)

    if not results:
        results = _search_terms_from_files(term_name, vocabulary, drupal_root)

    if not results:
        search_scope = f"in vocabulary '{vocabulary}'" if vocabulary else "across all vocabularies"
        return f"ℹ️ No terms found matching '{term_name}' {search_scope}"

    # If only one result, automatically show detailed usage analysis
    if len(results) == 1:
        logger.info(f"Single term found for '{term_name}', showing detailed usage analysis")
        return _get_term_usage_analysis(results[0]["tid"], drupal_root)

    # Multiple results - show summary with prominent term IDs
    output = [f"🔍 Terms matching '{term_name}' ({len(results)} found)"]
    output.append("💡 Tip: Use get_taxonomy_info(term_id=X) for detailed usage analysis\n")

    for term in results:
        output.append(f"• {term['name']} (tid: {term['tid']})")
        output.append(f"  Vocabulary: {term['vocabulary_label']} ({term['vocabulary']})")

        if term.get("description"):
            desc = (
                term["description"][:100] + "..."
                if len(term["description"]) > 100
                else term["description"]
            )
            output.append(f"  Description: {desc}")

        usage_count = term.get("usage_count", 0)
        if usage_count > 0:
            output.append(f"  ⚠️  Used in {usage_count} content item(s)")
        else:
            output.append("  ✅ Not used (safe to delete)")

        output.append("")

    return "\n".join(output)


def _get_term_usage_analysis(term_id: int, drupal_root: Path) -> str:
    """Get detailed usage analysis for a specific term."""
    # CRITICAL: Verify database connection BEFORE attempting to fetch term data
    db_ok, db_msg = verify_database_connection()
    if not db_ok:
        return (
            f"❌ ERROR: Cannot analyze term {term_id} usage\n\n"
            f"Database connection required but unavailable.\n"
            f"Reason: {db_msg}\n\n"
            f"⚠️  IMPORTANT: Do NOT delete this term without manual verification!\n\n"
            f"Troubleshooting steps:\n"
            f"1. Verify drush is working: drush status\n"
            f"2. Check database connectivity in the output above\n"
            f"3. Ensure your development environment is running (DDEV/Lando/etc.)\n"
            f"4. If database is accessible, manually check term usage:\n"
            f'   drush sqlq "SELECT COUNT(*) FROM taxonomy_index WHERE tid={term_id}"\n\n'
            f"Without database access, Scout cannot determine if this term is safe to delete."
        )

    # Lazy import to avoid circular dependency
    from src.tools.exports import _get_term_usage_from_drush

    usage_data = _get_term_usage_from_drush(term_id)

    if not usage_data:
        # Database is connected but term not found or query failed
        # Don't fallback to files - it won't work and gives false negatives
        return (
            f"❌ Term {term_id} not found or query failed\n\n"
            f"Possible reasons:\n"
            f"1. Term ID does not exist in the database\n"
            f"2. Drush query failed (check logs)\n"
            f"3. Database permissions issue\n\n"
            f'Try: drush sqlq "SELECT * FROM taxonomy_term_field_data WHERE tid={term_id}"'
        )

    term = usage_data["term"]
    diagnostics = usage_data.get("_diagnostics", {})

    output = [f"🏷️  Term: {term['name']} (tid: {term_id})"]
    output.append(f"   Vocabulary: {term['vocabulary_label']} ({term['vocabulary']})")
    output.append("   📊 Data source: Live database via drush")

    # Show diagnostics
    if diagnostics:
        output.append("   🔍 Query diagnostics:")
        output.append(f"      • Database has {diagnostics.get('total_nodes_in_db', 0)} total nodes")
        output.append(
            f"      • taxonomy_index table: {diagnostics.get('taxonomy_index_count', 0)} references for this term"
        )
        if diagnostics.get("fields_checked", 0) > 0:
            output.append(
                f"      • Checked {diagnostics.get('fields_checked', 0)} entity reference fields"
            )
            if diagnostics.get("fields_with_errors"):
                output.append(
                    f"      • {len(diagnostics.get('fields_with_errors', []))} fields had query errors"
                )
        output.append(f"      • Query method: {diagnostics.get('query_method', 'unknown')}")

    output.append("")

    if term.get("description"):
        output.append(f"   Description: {term['description']}")

    if term.get("parent"):
        output.append(f"   Parent: {term['parent']}")

    children = term.get("children", [])
    if children:
        output.append(f"   Children: {', '.join(children)}")

    output.append("")

    # Content usage
    content_usage = usage_data.get("content_usage", [])
    if content_usage:
        output.append(f"📄 Used in {len(content_usage)} content item(s):")
        for item in content_usage[:10]:  # Show first 10
            output.append(f"   • {item['title']} ({item['type']}) - nid: {item['nid']}")
        if len(content_usage) > 10:
            output.append(f"   ... and {len(content_usage) - 10} more")
        output.append("")

    # Views usage
    views_usage = usage_data.get("views_usage", [])
    if views_usage:
        output.append(f"👁️  Used in {len(views_usage)} view(s):")
        for view in views_usage:
            output.append(f"   • {view['view_label']} ({view['view_id']}) - {view['usage_type']}")
        output.append("")

    # Fields that could reference this term
    fields = usage_data.get("referencing_fields", [])
    if fields:
        output.append(f"🔗 Vocabulary referenced by {len(fields)} field(s):")
        for field in fields:
            output.append(
                f"   • {field['field_label']} ({field['field_name']}) on {', '.join(field['bundles'])}"
            )
        output.append("")

    # Safety assessment
    total_usage = len(content_usage) + len(views_usage)
    if total_usage == 0 and not children:
        output.append("✅ SAFE TO DELETE")
        output.append("   This term is not used in content, views, or as a parent term.")
        output.append("   Verified via database query.")
    elif children:
        output.append("⚠️  WARNING: Has child terms")
        output.append(f"   {len(children)} child term(s) will become orphaned if deleted.")
        output.append("   Consider reassigning children or deleting them first.")
    else:
        output.append("⚠️  CAUTION: Term is in use")
        output.append(
            f"   Used in {len(content_usage)} content item(s) and {len(views_usage)} view(s)."
        )
        output.append("   Deleting will remove term references from content.")
        output.append("   Consider merging with another term instead.")

    return "\n".join(output)


def _build_term_hierarchy(terms: List[dict]) -> List[dict]:
    """Build hierarchical tree structure from flat term list."""
    # Create lookup dict
    terms_by_id = {t["tid"]: {**t, "children": []} for t in terms}

    # Build tree
    root_terms = []
    for term in terms:
        parent_id = term.get("parent_tid", 0)
        if parent_id and parent_id in terms_by_id:
            terms_by_id[parent_id]["children"].append(terms_by_id[term["tid"]])
        else:
            root_terms.append(terms_by_id[term["tid"]])

    return root_terms


def _append_term_tree(output: List[str], terms: List[dict], level: int):
    """Recursively append term tree to output."""
    indent = "   " * level
    for term in terms:
        usage = term.get("usage_count", 0)
        usage_str = f" ({usage} uses)" if usage > 0 else ""
        output.append(f"{indent}• {term['name']} (tid: {term['tid']}){usage_str}")

        if term.get("children"):
            _append_term_tree(output, term["children"], level + 1)


def _get_vocabularies_from_drush() -> Optional[List[dict]]:
    """Get vocabularies from database via drush."""
    try:
        php_code = """
        $vocabs_data = [];
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');
        $vocabularies = $vocab_storage->loadMultiple();

        // Get term counts
        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');

        // Get fields that reference taxonomies
        $field_configs = \\Drupal::entityTypeManager()
            ->getStorage('field_config')
            ->loadMultiple();

        $vocab_fields = [];
        foreach ($field_configs as $field) {
            $settings = $field->getSettings();
            if (isset($settings['target_type']) && $settings['target_type'] === 'taxonomy_term') {
                $handler_settings = $settings['handler_settings'] ?? [];
                $target_bundles = $handler_settings['target_bundles'] ?? [];
                foreach ($target_bundles as $vocab_id) {
                    if (!isset($vocab_fields[$vocab_id])) {
                        $vocab_fields[$vocab_id] = [];
                    }
                    $vocab_fields[$vocab_id][] = $field->getName();
                }
            }
        }

        foreach ($vocabularies as $vocab) {
            $vocab_id = $vocab->id();

            // Count terms
            $term_count = $term_storage->getQuery()
                ->condition('vid', $vocab_id)
                ->accessCheck(FALSE)
                ->count()
                ->execute();

            $vocabs_data[] = [
                'id' => $vocab_id,
                'label' => $vocab->label(),
                'description' => $vocab->getDescription(),
                'term_count' => (int)$term_count,
                'referencing_fields' => $vocab_fields[$vocab_id] ?? []
            ];
        }

        echo json_encode($vocabs_data);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=20)
        return result if result and isinstance(result, list) else None

    except Exception as e:
        logger.debug(f"Could not get vocabularies from drush: {e}")
        return None


def _get_vocabularies_from_files(drupal_root: Path) -> List[dict]:
    """Parse vocabulary configs from files."""
    vocabs_data = []

    config_locations = [
        drupal_root / "config" / "sync",
        drupal_root / "config" / "default",
        drupal_root / "sites" / "default" / "config" / "sync",
        drupal_root / "recipes",
    ]

    for config_dir in config_locations:
        if not config_dir.exists():
            continue

        for vocab_file in config_dir.rglob("taxonomy.vocabulary.*.yml"):
            try:
                import yaml

                with open(vocab_file, "r") as f:
                    config = yaml.safe_load(f)

                if config:
                    vocabs_data.append(
                        {
                            "id": get_config().get("vid", ""),
                            "label": get_config().get("name", ""),
                            "description": get_config().get("description", ""),
                            "term_count": 0,  # Can't get from files
                            "referencing_fields": [],  # Would need to parse field configs
                        }
                    )
            except Exception as e:
                logger.debug(f"Error parsing {vocab_file}: {e}")
                continue

    return vocabs_data


def _get_terms_from_drush(vocabulary: str) -> Optional[dict]:
    """Get terms from a vocabulary via drush."""
    try:
        php_code = f"""
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');
        $vocab = $vocab_storage->load('{vocabulary}');

        if (!$vocab) {{
            echo json_encode(null);
            exit;
        }}

        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');
        $terms = $term_storage->loadByProperties(['vid' => '{vocabulary}']);

        // Get usage counts from entity_usage or count manually
        $database = \\Drupal::database();

        $terms_data = [];
        foreach ($terms as $term) {{
            $tid = $term->id();

            // Count usage in node fields (simplified - checks common field tables)
            $usage_count = 0;
            try {{
                // This is a simplified count - real implementation would check all entity reference fields
                $usage_count = $database->select('node__field_tags', 'n')
                    ->condition('field_tags_target_id', $tid)
                    ->countQuery()
                    ->execute()
                    ->fetchField();
            }} catch (\\Exception $e) {{
                // Field doesn't exist
            }}

            $parent = $term_storage->loadParents($tid);
            $parent_tid = $parent ? key($parent) : 0;

            $terms_data[] = [
                'tid' => (int)$tid,
                'name' => $term->getName(),
                'description' => $term->getDescription(),
                'weight' => $term->getWeight(),
                'parent_tid' => (int)$parent_tid,
                'usage_count' => (int)$usage_count
            ];
        }}

        $result = [
            'vocabulary' => [
                'id' => $vocab->id(),
                'label' => $vocab->label(),
                'description' => $vocab->getDescription()
            ],
            'terms' => $terms_data
        ];

        echo json_encode($result);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=25)
        return result if result else None

    except Exception as e:
        logger.debug(f"Could not get terms from drush: {e}")
        return None


def _get_terms_from_files(vocabulary: str, drupal_root: Path) -> Optional[dict]:
    """Parse terms from migration or content files (limited fallback)."""
    # This is a limited fallback - terms are usually only in DB
    # Could parse content files or migration configs if needed
    return None


def _search_terms_from_drush(term_name: str, vocabulary: Optional[str]) -> Optional[List[dict]]:
    """Search for terms by name via drush."""
    try:
        vocab_filter = ""
        if vocabulary:
            vocab_filter = f"->condition('vid', '{vocabulary}')"

        php_code = f"""
        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');

        $query = $term_storage->getQuery()
            ->condition('name', '%{term_name}%', 'LIKE')
            {vocab_filter}
            ->accessCheck(FALSE)
            ->range(0, 20);

        $tids = $query->execute();
        $terms = $term_storage->loadMultiple($tids);

        $results = [];
        foreach ($terms as $term) {{
            $tid = $term->id();
            $vid = $term->bundle();
            $vocab = $vocab_storage->load($vid);

            // Simple usage count (would need to check all reference fields in production)
            $database = \\Drupal::database();
            $usage_count = 0;

            $results[] = [
                'tid' => (int)$tid,
                'name' => $term->getName(),
                'description' => $term->getDescription(),
                'vocabulary' => $vid,
                'vocabulary_label' => $vocab ? $vocab->label() : $vid,
                'usage_count' => $usage_count
            ];
        }}

        echo json_encode($results);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=20)
        return result if result and isinstance(result, list) else None

    except Exception as e:
        logger.debug(f"Could not search terms from drush: {e}")
        return None


def _search_terms_from_files(
    term_name: str, vocabulary: Optional[str], drupal_root: Path
) -> List[dict]:
    """Search terms in files (limited fallback)."""
    return []


@mcp.tool()
def get_all_taxonomy_usage(
    vocabulary: str,
    check_code: bool = True,
    max_sample_nodes: int = 5,
    limit: int = 100,
    summary_only: bool = False,
) -> str:
    """
    Get comprehensive usage analysis for ALL terms in a vocabulary with one optimized query.

    This is MUCH more efficient than calling get_taxonomy_info() for each term individually.
    For 562 terms: approximately 5,000 tokens instead of 129,000 tokens (96% savings).

    **RESPONSE SIZE LIMITS:**
    - Default limit: 100 terms (fits well within MCP 25K token limit)
    - For vocabularies with 100+ terms, results are automatically limited
    - Use summary_only=True for ultra-compact output (just counts, no samples)
    - Increase limit carefully: limit=200 may approach token limits

    **CRITICAL: If you only receive 100 terms but vocabulary has MORE:**
    - The response includes "total_terms" vs "returned_terms" to show truncation
    - Example: {"total_terms": 751, "returned_terms": 100, "truncated": true}
    - You MUST inform the user results are truncated and suggest:
      A) Increase limit (e.g., limit=751) for full dataset - may exceed token limits
      B) Use summary_only=True with limit=0 for complete compact view
      C) Continue with first 100 terms only
    - DO NOT silently export incomplete data without warning the user!

    **PERFORMANCE NOTE:**
    - Small vocabularies (1-50 terms): 5-10 seconds
    - Medium vocabularies (50-200 terms): 15-30 seconds
    - Large vocabularies (200-500 terms): 30-60 seconds
    - Very large vocabularies (500+ terms): 60-120 seconds
    - Progress messages will appear in real-time showing completion status

    **RECOMMENDED WORKFLOW - For Vocabularies with 200+ Terms:**

    DO NOT call this tool directly with full mode. The response will exceed MCP token limits.
    Instead, use this optimized two-phase approach:

    **Phase 1: Get candidates yourself (fast, ~5-10K tokens)**
    ```
    result = get_all_taxonomy_usage(vocabulary="topics", summary_only=True, check_code=False)
    candidates = [term for term in result["terms"] if term["needs_check"] == True]

    # Show user: "Found {total_terms} terms, {len(candidates)} candidates for deletion"
    ```

    **Phase 2: Delegate deep-checking to Task agent**
    ```
    If len(candidates) > 20:
        Use Task tool with:
          subagent_type: "general-purpose"
          description: "Deep-check taxonomy term candidates"
          prompt: '''
            Verify which of these taxonomy terms are truly safe to delete: {candidate_ids}

            For each term ID, call get_taxonomy_info(term_id=X) to check:
            - Content usage (should already be 0)
            - Views usage
            - Custom code references
            - Config file references

            Return a concise list of:
            - Terms that are SAFE to delete (with term ID and name)
            - Terms that are NOT safe (with reason why)
          '''

    Else if len(candidates) <= 20:
        # Few candidates, check them yourself without agent
        for candidate in candidates:
            details = get_taxonomy_info(term_id=candidate["tid"])
    ```

    **Benefits of this approach:**
    - User sees candidate count immediately (good UX)
    - Agent only handles the slow part (deep checks)
    - If <20 candidates, no need for agent overhead
    - Agent can be split into multiple if too many candidates

    **USE THIS TOOL** when you need to:
    - Audit all terms in a vocabulary for cleanup
    - Generate CSV/table of term usage across entire vocabulary
    - Find unused terms for deletion
    - Analyze term usage patterns

    The tool performs:
    1. Database queries to find content using each term
    2. Code scanning to find hardcoded term IDs/names (optional, if check_code=True)
    3. Config file scanning for term references (optional, if check_code=True)

    Note: Views analysis not included in batch mode. Use get_taxonomy_info(term_id=X) for views checking.

    Returns structured JSON data that AI can format as CSV, markdown table, or any format.

    Args:
        vocabulary: Vocabulary machine name (e.g., "topics", "tags", "categories")
        check_code: If True, scans custom code for hardcoded term references.
                    Slower but more thorough. Default: True
        max_sample_nodes: Max number of sample nodes to return per term. Default: 5
        limit: Max number of terms to return. Default: 100. Set to 0 for all terms (risky for large vocabs).
        summary_only: If True, returns minimal data (no samples, descriptions, or children). Default: False

    Returns:
        JSON string with metadata and term data:
        {
            "total_terms": 562,
            "returned_terms": 100,
            "truncated": true/false,
            "summary_only": true/false,
            "message": "..." (if truncated),
            "terms": [...]
        }

        In summary_only mode, each term includes:
        - tid: Term ID
        - name: Term name
        - count: Number of content items using this term
        - needs_check: TRUE if 0 content usage (candidate for deletion, needs full check)

        In full mode, each term includes:
        - tid, name, description, parent, children
        - content_usage: [{nid, title, type}, ...] (sample nodes)
        - content_count: Total number of content items using this term
        - code_usage: [{file, line, context}, ...] (if check_code=True)
        - config_usage: [{config_name, config_type}, ...] (if check_code=True)
        - fields_with_usage: List of field names where term is used
        - safe_to_delete: boolean (content + code + config analysis)
        - warnings: List of reasons why deletion might be problematic

    Example response format:
    [
        {
            "tid": 123,
            "name": "General",
            "content_count": 4646,
            "content_usage": [{"nid": 1, "title": "Example", "type": "article"}],
            "code_usage": [{"file": "custom/mymodule/mymodule.module", "line": 45}],
            "safe_to_delete": false,
            "warnings": ["Used in 4,646 content items", "Referenced in custom code"]
        }
    ]

    Saves approximately 70-90% tokens compared to individual term queries.
    """
    try:
        drupal_root = Path(get_config().get("drupal_root", ""))

        if not drupal_root.exists():
            return json.dumps(
                {
                    "_error": True,
                    "message": "Could not determine Drupal root. Check drupal_root in config.",
                }
            )

        # Verify database connection first
        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Database connection required. {db_msg}",
                    "troubleshooting": [
                        "Verify drush is working: drush status",
                        "Check database connectivity",
                        "Ensure development environment is running (DDEV/Lando/etc.)",
                    ],
                }
            )

        # Lazy import to avoid circular dependency
        from src.tools.exports import _get_all_terms_usage_from_drush

        # Get all term usage data in one optimized query
        usage_data = _get_all_terms_usage_from_drush(vocabulary, max_sample_nodes, summary_only)

        if not usage_data:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Could not fetch terms for vocabulary '{vocabulary}'",
                    "suggestion": "Verify vocabulary machine name is correct. Use get_taxonomy_info() with no parameters to list all vocabularies.",
                }
            )

        total_terms = len(usage_data)

        # Apply limit if needed
        if limit > 0 and len(usage_data) > limit:
            usage_data = usage_data[:limit]
            truncated = True
        else:
            truncated = False

        # Add code/config usage if requested (only for returned terms)
        if check_code and not summary_only:
            # Lazy import to avoid circular dependency
            from src.tools.exports import _add_code_usage_to_terms

            usage_data = _add_code_usage_to_terms(usage_data, drupal_root)

        # Add metadata about results
        result = {
            "total_terms": total_terms,
            "returned_terms": len(usage_data),
            "truncated": truncated,
            "summary_only": summary_only,
            "terms": usage_data,
        }

        if truncated:
            result["message"] = (
                f"⚠️  TRUNCATED RESULTS: Showing {len(usage_data)} of {total_terms} terms. "
                f"The vocabulary has {total_terms} total terms, but only {len(usage_data)} are included. "
                f"Options: (1) Increase limit={total_terms} for all terms, "
                f"(2) Use summary_only=True with limit=0 for compact full view, "
                f"(3) Continue with current {len(usage_data)} terms. "
                f"DO NOT export to CSV without informing user of truncation!"
            )

        # Return as JSON for AI to format
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Error in get_all_taxonomy_usage: {e}", exc_info=True)
        return json.dumps({"_error": True, "message": str(e)})


def main():
    """Main entry point for the MCP server."""
    # Note: Pre-indexing and drush testing moved to lazy initialization
    # to avoid delaying MCP server startup which can cause connection issues
    logger.info("🚀 Starting Drupal Scout MCP Server...")
    logger.info(f"   📦 {len(mcp._tool_manager._tools)} tools registered")
    logger.info("   (Modules will be indexed on first request)")

    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()
