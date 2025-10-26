#!/usr/bin/env python3
"""
Drupal Scout MCP Server

A Model Context Protocol server for discovering functionality in Drupal sites.
"""

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
import src.tools.taxonomy  # noqa: E402, F401

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
