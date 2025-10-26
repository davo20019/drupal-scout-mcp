"""
Drupal.org search and discovery tools.

Provides tools for searching and analyzing modules from drupal.org:
- search_drupal_org: Search for modules on drupal.org
- get_popular_drupal_modules: Get popular modules by category
- get_module_recommendation: Get recommendations based on needs
- get_drupal_org_module_details: Get detailed module information
- search_module_issues: Search module issue queues

These tools help discover new modules and troubleshoot existing ones.
"""

import datetime
import logging
import re
from typing import Optional

# Import from core modules
from src.core.config import (
    ensure_indexed,
    get_drupal_org_api,
    get_indexer,
    get_searcher,
)
from src.drupal_org import format_drupal_org_results

# Import MCP instance from server
from server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def search_drupal_org(query: str, limit: int = 10) -> str:
    """
    Search for available modules on drupal.org.

    Use this to discover modules you could install for new functionality.
    Great when you need to find solutions for features you don't have yet.

    **SEARCH TIPS FOR AI - IMPORTANT:**
    - drupal.org search works best with SHORT, SPECIFIC terms
    - Use SINGLE WORDS instead of phrases: "openai" NOT "AI artificial intelligence"
    - If no results, try SYNONYMS or RELATED terms individually
    - For compound topics, search each term separately

    **Common successful searches:**
    - AI/ML: "openai", "anthropic", "chatgpt", "llm", "ai_interpolator" (search EACH separately)
    - SEO: "metatag", "pathauto", "redirect", "xmlsitemap"
    - Commerce: "commerce", "ubercart", "payment"
    - Forms: "webform", "entityform"

    **Strategy when user asks for broad topics:**
    - User: "install AI modules" → Try: search_drupal_org("openai"), then search_drupal_org("anthropic")
    - User: "e-commerce modules" → Try: search_drupal_org("commerce")
    - Break broad requests into multiple specific searches

    Args:
        query: What to search for - USE SHORT TERMS (e.g., "openai", "commerce", "metatag")
               Single words work best. Avoid long phrases.
        limit: Maximum number of results to return (default: 10)

    Returns:
        List of available modules from drupal.org with details, or suggestions if no results
    """
    logger.info(f"Searching drupal.org for: {query}")

    modules = get_drupal_org_api().search_modules(query, limit=limit)

    if not modules:
        # Provide helpful suggestions based on query
        suggestions = {
            "ai": ["openai", "anthropic", "chatgpt", "llm"],
            "artificial intelligence": ["openai", "anthropic", "ai"],
            "machine learning": ["openai", "ai", "ml"],
            "chatbot": ["chatgpt", "openai", "anthropic"],
            "seo": ["metatag", "pathauto", "redirect", "xmlsitemap"],
            "ecommerce": ["commerce", "ubercart"],
            "e-commerce": ["commerce", "ubercart"],
            "email": ["smtp", "mailsystem", "mimemail"],
        }

        query_lower = query.lower()
        suggested_terms = []
        for key, terms in suggestions.items():
            if key in query_lower or query_lower in key:
                suggested_terms = terms
                break

        if suggested_terms:
            suggestion_text = "\n\n💡 TRY THESE SPECIFIC SEARCHES INSTEAD:\n" + "\n".join(
                [f'   - search_drupal_org("{term}")' for term in suggested_terms]
            )
            suggestion_text += "\n\n(drupal.org search works better with short, specific terms)"
        else:
            suggestion_text = "\n\n💡 TIP: Try shorter, more specific terms. Single words work best.\n   Example: Instead of 'user authentication oauth', try 'oauth' or 'saml'"

        return f"❌ No modules found on drupal.org for '{query}'{suggestion_text}"

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

    modules = get_drupal_org_api().get_popular_modules(category if category else None, limit=limit)

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
        local_results = get_searcher().search_functionality(need, scope="all")
        local_modules = local_results["custom_modules"] + local_results["contrib_modules"]
    except Exception as e:
        logger.warning(f"Could not search locally: {e}")
        local_modules = []

    # Search drupal.org
    drupal_org_modules = get_drupal_org_api().search_modules(need, limit=5)

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

    details = get_drupal_org_api().get_module_details(module_name, include_issues=include_issues)

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
        if get_indexer() and get_indexer().drupal_root:
            # Try to read Drupal version from core
            version_file = get_indexer().drupal_root / "core" / "lib" / "Drupal.php"
            if version_file.exists():
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

    matches = get_drupal_org_api().search_issues(
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
