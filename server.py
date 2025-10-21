#!/usr/bin/env python3
"""
Drupal Scout MCP Server

A Model Context Protocol server for discovering functionality in Drupal sites.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP
from src.indexer import ModuleIndexer
from src.search import ModuleSearch
from src.prioritizer import ResultPrioritizer
from src.drupal_org import DrupalOrgAPI, format_drupal_org_results, generate_recommendations

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("Drupal Scout")

# Global state
indexer: Optional[ModuleIndexer] = None
searcher: Optional[ModuleSearch] = None
prioritizer = ResultPrioritizer()
drupal_org_api = DrupalOrgAPI()
config = {}


def load_config() -> dict:
    """Load configuration from config.json or environment."""
    config_path = Path.home() / ".config" / "drupal-scout" / "config.json"

    if config_path.exists():
        with open(config_path, "r") as f:
            return json.load(f)

    # Try local config
    local_config = Path("config.json")
    if local_config.exists():
        with open(local_config, "r") as f:
            return json.load(f)

    # No default - user must configure
    raise ValueError(
        "Configuration not found. Please create config.json with:\n"
        "{\n"
        '  "drupal_root": "/path/to/your/drupal",\n'
        '  "modules_path": "modules"\n'
        "}"
    )


def ensure_indexed():
    """Ensure modules are indexed before operations."""
    global indexer, searcher, config

    if indexer is None:
        config = load_config()
        drupal_root = Path(config["drupal_root"])

        if not drupal_root.exists():
            raise ValueError(
                f"Drupal root not found: {drupal_root}\n"
                f"Please configure drupal_root in config.json"
            )

        logger.info(f"Indexing modules from: {drupal_root}")
        indexer = ModuleIndexer(drupal_root, config)
        indexer.index_all()

        searcher = ModuleSearch(indexer)
        logger.info(f"Indexed {indexer.modules.get('total', 0)} modules")


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
    results = searcher.search_functionality(query, scope)

    output = prioritizer.format_search_results(results)

    # If no local results and drupal.org search enabled, search drupal.org
    if include_drupal_org and results["total_matches"] == 0:
        logger.info(f"No local results, searching drupal.org for: {query}")
        drupal_org_results = drupal_org_api.search_modules(query, limit=5)

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
    modules_data = searcher.list_all_modules(scope, show_unused)

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
    module_data = searcher.describe_module(module_name)

    return prioritizer.format_module_detail(module_data)


@mcp.tool()
def find_unused_contrib() -> str:
    """
    Find contrib modules that aren't used by custom code.

    Identifies:
    - Modules not in any custom module dependencies
    - Modules whose services aren't injected anywhere
    - Potential cleanup opportunities

    Great for site optimization and reducing complexity!

    Returns:
        List of unused contrib modules with recommendations
    """
    ensure_indexed()

    logger.info("Finding unused contrib modules")
    unused = searcher.find_unused_contrib()

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
    check_result = searcher.check_redundancy(functionality)

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
    global indexer, searcher

    logger.info("Forcing module reindex")

    # Clear existing index
    indexer = None
    searcher = None

    # Re-index
    ensure_indexed()

    return f"✓ Reindexed {indexer.modules.get('total', 0)} modules successfully"


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
        indexer.modules.get("custom", [])
        + indexer.modules.get("contrib", [])
        + indexer.modules.get("core", [])
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


@mcp.tool()
def search_drupal_org(query: str, limit: int = 10) -> str:
    """
    Search for available modules on drupal.org.

    Use this to discover modules you could install for new functionality.
    Great when you need to find solutions for features you don't have yet.

    Args:
        query: What to search for (e.g., "commerce", "SEO", "migration")
        limit: Maximum number of results to return (default: 10)

    Returns:
        List of available modules from drupal.org with details
    """
    logger.info(f"Searching drupal.org for: {query}")

    modules = drupal_org_api.search_modules(query, limit=limit)

    if not modules:
        return f"❌ No modules found on drupal.org for '{query}'"

    return format_drupal_org_results(modules, query)


@mcp.tool()
def get_popular_drupal_modules(category: str = "", limit: int = 20) -> str:
    """
    Get popular/recommended Drupal modules from drupal.org.

    Useful for discovering commonly used solutions and best practices.

    Args:
        category: Optional category filter (e.g., "Commerce", "SEO", "Media")
        limit: Number of modules to return (default: 20)

    Returns:
        List of popular modules sorted by usage
    """
    logger.info(f"Fetching popular modules (category: {category or 'all'})")

    modules = drupal_org_api.get_popular_modules(category if category else None, limit=limit)

    if not modules:
        return "❌ Could not fetch popular modules from drupal.org"

    output = ["📊 **Most Popular Drupal Modules**"]

    if category:
        output[0] += f" in category '{category}'"

    output.append(f"\nShowing top {len(modules)} by installation count:\n")

    for i, module in enumerate(modules, 1):
        output.append(f"{i}. **{module['name']}** (`{module['machine_name']}`)")
        output.append(f"   {module['description'][:150]}...")

        usage = module.get("project_usage", 0)
        if usage > 0:
            usage_str = f"{usage:,}" if usage < 1000000 else f"{usage/1000000:.1f}M"
            output.append(f"   📊 {usage_str} installations")

        output.append(f"   🔗 {module['url']}")
        output.append("")

    output.append("\n💡 **Tips:**")
    output.append("   • Higher installation count = more mature/trusted")
    output.append("   • Check maintenance status before installing")
    output.append("   • Review recent activity in issue queue")

    return "\n".join(output)


@mcp.tool()
def get_module_recommendation(need: str) -> str:
    """
    Get recommendation for a specific need.

    Combines local module analysis with drupal.org suggestions.

    Args:
        need: Description of what you need (e.g., "user authentication with OAuth")

    Returns:
        Comprehensive recommendation with options and next steps
    """
    logger.info(f"Getting recommendation for: {need}")

    # Search locally first
    try:
        ensure_indexed()
        local_results = searcher.search_functionality(need, scope="all")
        local_modules = local_results["custom_modules"] + local_results["contrib_modules"]
    except Exception as e:
        logger.warning(f"Could not search locally: {e}")
        local_modules = []

    # Search drupal.org
    drupal_org_modules = drupal_org_api.search_modules(need, limit=5)

    # Generate comprehensive recommendation
    output = [
        f"🎯 **Recommendation for: '{need}'**\n",
    ]

    # Local analysis
    if local_modules:
        output.append("✅ **You already have:**\n")
        for mod in local_modules[:3]:
            output.append(f"   • {mod['name']} ({mod['module']})")
            output.append(f"     {mod['description'][:100]}...")
        output.append("\n   💡 Consider using/extending existing modules first\n")
    else:
        output.append("❌ **No existing local modules found**\n")

    # drupal.org suggestions
    if drupal_org_modules:
        output.append("📦 **Available from drupal.org:**\n")

        # Rank by installations
        top_modules = sorted(
            drupal_org_modules, key=lambda x: x.get("project_usage", 0), reverse=True
        )[:3]

        for i, mod in enumerate(top_modules, 1):
            output.append(f"\n   **Option {i}: {mod['name']}**")
            output.append(f"   • Machine name: `{mod['machine_name']}`")
            output.append(f"   • {mod['description'][:150]}...")

            usage = mod.get("project_usage", 0)
            if usage:
                output.append(f"   • Installations: {usage:,}")

            maint = mod.get("maintenance_status")
            if maint:
                output.append(f"   • Status: {maint}")

            output.append(f"   • URL: {mod['url']}")

    output.append("\n\n🎬 **Recommended Action Plan:**\n")

    if local_modules:
        output.append("1. **Evaluate existing modules** - Review what you already have")
        output.append("2. **Check if extensible** - Can you extend current functionality?")
        output.append("3. **Compare with contrib** - Are drupal.org options better?")
    else:
        if drupal_org_modules:
            top_choice = sorted(
                drupal_org_modules, key=lambda x: x.get("project_usage", 0), reverse=True
            )[0]
            output.append(f"1. **Try: {top_choice['name']}** - Most popular option")
            output.append("2. **Install in dev environment** - Test before production")
            output.append("3. **Review documentation** - Understand features and limitations")
            output.append("4. **Check issue queue** - Look for known problems")
        else:
            output.append("1. **Build custom solution** - No suitable contrib found")
            output.append("2. **Consider similar modules** - Search with different keywords")
            output.append("3. **Check Drupal ecosystem** - Ask community for recommendations")

    return "\n".join(output)


@mcp.tool()
def get_drupal_org_module_details(module_name: str, include_issues: bool = False) -> str:
    """
    Get detailed information about a module from drupal.org.

    Use this to learn more about modules you found on drupal.org
    before installing them. Different from describe_module which
    only works for locally installed modules.

    Args:
        module_name: Machine name of the module (e.g., "webform", "simplesamlphp_auth")
        include_issues: Include recent issues for deeper analysis (maintainer activity,
                       common problems, migration patterns, technical debt).
                       Automatically enabled for complex decision-making queries.

    Returns:
        Detailed module information from drupal.org
    """
    logger.info(f"Fetching drupal.org details for: {module_name} (include_issues={include_issues})")

    details = drupal_org_api.get_module_details(module_name, include_issues=include_issues)

    if not details:
        return f"❌ Module '{module_name}' not found on drupal.org\n\nTip: Use search_drupal_org to find available modules"

    output = [
        f"📦 **{details['name']}** ({details['machine_name']})\n",
    ]

    # Description
    if details.get("description"):
        output.append(f"{details['description']}\n")

    # Project URL
    if details.get("url"):
        output.append(f"🔗 **Project page:** {details['url']}\n")

    # Drupal Version Compatibility - CRITICAL INFO
    drupal_versions = details.get("drupal_versions", [])
    if drupal_versions:
        versions_str = ", ".join(drupal_versions)
        output.append(f"✅ **Compatible with:** {versions_str}\n")

    # Security & Trust indicators
    security_badges = []
    if details.get("security_coverage") == "covered":
        security_badges.append("🛡️  Security coverage")

    star_count = details.get("star_count", 0)
    if star_count > 0:
        security_badges.append(f"⭐ {star_count} stars")

    if security_badges:
        output.append(f"**Trust indicators:** {' • '.join(security_badges)}\n")

    # Usage statistics - Total
    usage = details.get("project_usage", 0)
    if usage:
        usage_str = f"{usage:,}" if usage < 1000000 else f"{usage/1000000:.1f}M"
        output.append(f"📊 **Total installations:** {usage_str}")

    # Usage by version - Show top 3
    usage_by_version = details.get("usage_by_version", {})
    if usage_by_version and isinstance(usage_by_version, dict):
        # Sort by usage count
        sorted_versions = sorted(
            [
                (k, v)
                for k, v in usage_by_version.items()
                if isinstance(v, (int, str)) and str(v).isdigit()
            ],
            key=lambda x: int(x[1]),
            reverse=True,
        )[:3]
        if sorted_versions:
            output.append("   **By version:**")
            for version, count in sorted_versions:
                output.append(f"   • {version}: {int(count):,} sites")

    # Dates
    created = details.get("created_date")
    updated = details.get("last_updated")
    if created or updated:
        output.append("\n📅 **Timeline:**")
        if created:
            output.append(f"   • Created: {created}")
        if updated:
            output.append(f"   • Last updated: {updated}")

    # Status
    maint = details.get("maintenance_status")
    dev = details.get("development_status")
    if maint or dev:
        output.append("\n⚙️  **Status:**")
        if maint:
            output.append(f"   • Maintenance: {maint}")
        if dev:
            output.append(f"   • Development: {dev}")

    # Supporting organizations
    org_count = details.get("supporting_orgs_count", 0)
    if org_count > 0:
        output.append(f"\n🏢 **Backed by {org_count} organization{'s' if org_count != 1 else ''}**")

    # Categories
    if details.get("categories"):
        output.append(f"\n🏷️  **Categories:** {', '.join(details['categories'])}")

    # Issue queue link
    if details.get("has_issue_queue"):
        nid = details.get("nid", "")
        if nid:
            output.append(
                f"\n🐛 **Issue queue:** https://www.drupal.org/project/issues/{details['machine_name']}"
            )

    # Documentation links
    doc_links = details.get("documentation_links", [])
    if doc_links:
        output.append(f"\n📖 **Documentation:** {doc_links[0]}")

    # Recent Issues - for qualitative analysis
    recent_issues = details.get("recent_issues", [])
    if recent_issues:
        output.append(f"\n\n🔍 **Recent Issue Activity** ({len(recent_issues)} recent issues)")
        output.append(
            "   *Analyze for maintainer activity, common problems, and community health*\n"
        )

        for i, issue in enumerate(recent_issues[:10], 1):  # Show top 10
            output.append(f"   {i}. **{issue['title']}**")

            # Add metadata
            metadata = []
            if issue.get("status") and issue["status"] != "Unknown":
                metadata.append(f"Status: {issue['status']}")
            if issue.get("priority") and issue["priority"] != "Unknown":
                metadata.append(f"Priority: {issue['priority']}")
            if issue.get("category") and issue["category"] != "Unknown":
                metadata.append(f"Category: {issue['category']}")

            if metadata:
                output.append(f"      {' • '.join(metadata)}")

            if issue.get("url"):
                output.append(f"      🔗 {issue['url']}")
            output.append("")

        if len(recent_issues) > 10:
            output.append(f"   *(Showing 10 of {len(recent_issues)} recent issues)*\n")

        output.append("   💡 **What to look for:**")
        output.append("      • Migration patterns (e.g., from other modules)")
        output.append("      • Common technical issues (Symfony, dependencies, etc.)")
        output.append("      • Maintainer responsiveness")
        output.append("      • Setup complexity discussions")

    # Installation guide
    output.append("\n\n💻 **To install:**")
    output.append("```bash")
    output.append(f"composer require drupal/{details['machine_name']}")
    output.append(f"drush en {details['machine_name']}")
    output.append("```")

    output.append("\n📚 **Next steps:**")
    output.append("   1. Review the project page for full documentation")
    if details.get("has_issue_queue"):
        output.append("   2. Check issue queue for known problems")
    output.append("   3. Verify compatibility with your Drupal version")
    output.append("   4. Test in development environment first")

    return "\n".join(output)


@mcp.tool()
def search_module_issues(module_name: str, problem_description: str, limit: int = 10) -> str:
    """
    Search a module's issue queue for problems similar to yours.

    Perfect for troubleshooting! When you encounter an error or problem,
    this tool searches the module's issue queue to find others who had
    similar issues - complete with links to solutions, patches, and workarounds.

    Automatically filters issues based on your Drupal version to show only
    relevant results.

    Args:
        module_name: Machine name of the module (e.g., "samlauth", "webform")
        problem_description: Describe your problem (e.g., "Azure AD authentication error",
                           "AttributeConsumingService configuration issue")
        limit: Maximum number of matching issues to return (default: 10)

    Returns:
        List of matching issues sorted by relevance with links to solutions
    """
    logger.info(f"Searching issues in '{module_name}' for: {problem_description}")

    # Try to detect Drupal version from local installation
    drupal_version = None
    try:
        if indexer and indexer.drupal_root:
            # Try to read Drupal version from core
            version_file = indexer.drupal_root / "core" / "lib" / "Drupal.php"
            if version_file.exists():
                import re

                with open(version_file, "r") as f:
                    content = f.read()
                    match = re.search(r"const VERSION = '([^']+)'", content)
                    if match:
                        full_version = match.group(1)
                        # Extract major version (e.g., "10.2.3" -> "10")
                        drupal_version = full_version.split(".")[0]
                        logger.info(
                            f"Detected Drupal version: {full_version} (major: {drupal_version})"
                        )
    except Exception as e:
        logger.debug(f"Could not detect Drupal version: {e}")

    matches = drupal_org_api.search_issues(
        module_name, problem_description, limit=limit, drupal_version=drupal_version
    )

    if not matches:
        return f"❌ No matching issues found in '{module_name}' for your problem.\n\n💡 **Tips:**\n   • Try broader keywords\n   • Check if the module name is correct\n   • The issue might be very new or very old (we search recent issues)"

    output = [
        f"🔍 **Found {len(matches)} matching issue{'s' if len(matches) != 1 else ''} in {module_name}**",
        f'   Searching for: "{problem_description}"\n',
    ]

    # Map status codes to human-readable labels
    status_map = {
        "1": "Active",
        "2": "Fixed",
        "3": "Closed (duplicate)",
        "4": "Postponed",
        "5": "Closed (won't fix)",
        "6": "Closed (works as designed)",
        "7": "Closed (fixed)",
        "8": "Needs review",
        "13": "Needs work",
        "14": "Reviewed & tested",
        "15": "Patch (to be ported)",
        "16": "Postponed (maintainer needs more info)",
        "17": "Closed (outdated)",
        "18": "Closed (cannot reproduce)",
    }

    # Map priority codes to labels
    priority_map = {
        "400": "Critical",
        "300": "Major",
        "200": "Normal",
        "100": "Minor",
    }

    # Map category codes to labels
    category_map = {
        "1": "Bug report",
        "2": "Task",
        "3": "Feature request",
        "4": "Support request",
        "5": "Plan",
    }

    for i, issue in enumerate(matches, 1):
        relevance = issue.get("relevance_score", 0)
        output.append(f"{i}. **{issue['title']}**")

        # Add metadata
        metadata = []

        status_code = str(issue.get("status", "Unknown"))
        status = status_map.get(status_code, f"Status {status_code}")
        metadata.append(f"Status: {status}")

        priority_code = str(issue.get("priority", ""))
        if priority_code in priority_map:
            priority = priority_map[priority_code]
            metadata.append(f"Priority: {priority}")

        category_code = str(issue.get("category", ""))
        if category_code in category_map:
            category = category_map[category_code]
            metadata.append(f"Type: {category}")

        # Show relevance for highly matching issues
        if relevance > 2:
            metadata.append(f"Relevance: {'⭐' * min(relevance, 5)}")

        if metadata:
            output.append(f"   {' • '.join(metadata)}")

        # Last updated
        import datetime

        changed = issue.get("changed", 0)
        if changed:
            try:
                changed_date = datetime.datetime.fromtimestamp(int(changed))
                time_ago = datetime.datetime.now() - changed_date
                if time_ago.days < 7:
                    time_str = f"{time_ago.days} day{'s' if time_ago.days != 1 else ''} ago"
                elif time_ago.days < 30:
                    weeks = time_ago.days // 7
                    time_str = f"{weeks} week{'s' if weeks != 1 else ''} ago"
                elif time_ago.days < 365:
                    months = time_ago.days // 30
                    time_str = f"{months} month{'s' if months != 1 else ''} ago"
                else:
                    years = time_ago.days // 365
                    time_str = f"{years} year{'s' if years != 1 else ''} ago"
                output.append(f"   Last updated: {time_str}")
            except (ValueError, OSError):
                pass

        # Link
        if issue.get("url"):
            output.append(f"   🔗 {issue['url']}")
        output.append("")

    output.append("\n💡 **Next steps:**")
    output.append("   1. Check the issue discussion for solutions or patches")
    output.append("   2. Look for 'Fixed' or 'Reviewed & tested' issues with patches")
    output.append("   3. If no solution exists, consider commenting on the most relevant issue")
    output.append("   4. Check if the issue has a recommended workaround")

    return "\n".join(output)


def main():
    """Main entry point for the MCP server."""
    logger.info("Starting Drupal Scout MCP Server")

    # Pre-index if config exists
    try:
        ensure_indexed()
        logger.info("Initial indexing complete")
    except Exception as e:
        logger.warning(f"Could not pre-index: {e}")
        logger.info("Will index on first request")

    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()
