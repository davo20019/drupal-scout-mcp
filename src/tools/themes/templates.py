"""
Template discovery tools for Drupal Scout MCP.

Provides template file discovery and override analysis.
"""

import logging
import subprocess
from pathlib import Path
from typing import List, Optional

# Import from core modules
from src.core.config import load_config
from src.core.drush import get_drush_command

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def find_theme_templates(theme_name: str, pattern: Optional[str] = None) -> str:
    """
    Find Twig template files in a theme with optional pattern filtering.

    Searches for .html.twig files and shows their location and what they override.
    Perfect for finding which templates exist and where they come from.

    Args:
        theme_name: Machine name of theme (e.g., "olivero", "my_custom_theme")
        pattern: Optional search pattern (e.g., "node--", "page", "views-view")
                If provided, only shows templates matching this pattern

    Returns:
        List of template files with their paths and override information

    Examples:
        find_theme_templates("olivero")
        find_theme_templates("my_custom_theme", "node--")
        find_theme_templates("olivero", "views")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root. Check drupal_root in config."

        # Find theme path
        theme_path = _find_theme_path(drupal_root, theme_name)
        if not theme_path:
            return f"❌ ERROR: Theme '{theme_name}' not found"

        # Find all .html.twig files
        template_files = list(theme_path.rglob("*.html.twig"))

        # Filter by pattern if provided
        if pattern:
            template_files = [f for f in template_files if pattern.lower() in f.stem.lower()]

        if not template_files:
            if pattern:
                return f"No templates found matching pattern '{pattern}' in theme '{theme_name}'"
            return f"No templates found in theme '{theme_name}'"

        # Build output
        output = []
        output.append(f"🎨 TEMPLATES IN {theme_name.upper()}")
        if pattern:
            output.append(f"   (filtered by: {pattern})")
        output.append("=" * 80)
        output.append("")
        output.append(f"Found {len(template_files)} template(s):")
        output.append("")

        # Group by directory
        by_directory = {}
        for tpl in template_files:
            rel_path = tpl.relative_to(theme_path)
            directory = str(rel_path.parent) if rel_path.parent != Path(".") else "root"
            if directory not in by_directory:
                by_directory[directory] = []
            by_directory[directory].append(tpl.name)

        # Display grouped by directory
        for directory in sorted(by_directory.keys()):
            if directory == "root":
                output.append("📁 Theme Root:")
            else:
                output.append(f"📁 {directory}/:")

            for filename in sorted(by_directory[directory]):
                # Detect what this template might override
                override_info = _detect_template_override(filename)
                if override_info:
                    output.append(f"   • {filename}")
                    output.append(f"     {override_info}")
                else:
                    output.append(f"   • {filename}")

            output.append("")

        # Add suggestions
        output.append("💡 Tips:")
        output.append("   - Use pattern to filter: find_theme_templates('olivero', 'node--')")
        output.append("   - See overrides: get_theme_template_overrides('olivero')")
        output.append("   - Get suggestions: get_template_suggestions('node', 'article')")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error finding theme templates")
        return f"❌ ERROR: Failed to find templates: {str(e)}"


@mcp.tool()
def get_theme_template_overrides(theme_name: str) -> str:
    """
    Show which core/contrib templates are overridden by a theme.

    Analyzes theme templates and identifies which core or contrib module
    templates they override. Perfect for understanding theme customizations.

    Args:
        theme_name: Machine name of theme (e.g., "olivero", "my_custom_theme")

    Returns:
        List of overridden templates with their source locations

    Examples:
        get_theme_template_overrides("olivero")
        get_theme_template_overrides("my_custom_theme")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root. Check drupal_root in config."

        # Find theme path
        theme_path = _find_theme_path(drupal_root, theme_name)
        if not theme_path:
            return f"❌ ERROR: Theme '{theme_name}' not found"

        # Find all .html.twig files in theme
        template_files = list(theme_path.rglob("*.html.twig"))

        if not template_files:
            return f"No templates found in theme '{theme_name}'"

        # Find corresponding core/contrib templates
        overrides = []
        for tpl in template_files:
            filename = tpl.name
            # Search for this template in core and contrib
            sources = _find_template_sources(drupal_root, filename)
            if sources:
                overrides.append({"theme_file": tpl, "sources": sources})

        # Build output
        output = []
        output.append(f"🔄 TEMPLATE OVERRIDES IN {theme_name.upper()}")
        output.append("=" * 80)
        output.append("")

        if not overrides:
            output.append("✅ No templates override core/contrib")
            output.append("   (All templates are custom to this theme)")
            return "\n".join(output)

        output.append(f"Found {len(overrides)} template override(s):")
        output.append("")

        # Group by source type
        core_overrides = []
        contrib_overrides = []
        other_overrides = []

        for override in overrides:
            rel_path = override["theme_file"].relative_to(theme_path)
            filename = override["theme_file"].name

            for source in override["sources"]:
                if "/core/" in str(source):
                    core_overrides.append((filename, str(rel_path), source))
                elif "/contrib/" in str(source):
                    contrib_overrides.append((filename, str(rel_path), source))
                else:
                    other_overrides.append((filename, str(rel_path), source))

        # Display core overrides
        if core_overrides:
            output.append("🎯 CORE TEMPLATE OVERRIDES:")
            for filename, theme_rel, source in sorted(core_overrides):
                source_rel = _make_relative_to_drupal(drupal_root, source)
                output.append(f"   • {filename}")
                output.append(f"     Theme: {theme_rel}")
                output.append(f"     Overrides: {source_rel}")
            output.append("")

        # Display contrib overrides
        if contrib_overrides:
            output.append("📦 CONTRIB TEMPLATE OVERRIDES:")
            for filename, theme_rel, source in sorted(contrib_overrides):
                source_rel = _make_relative_to_drupal(drupal_root, source)
                output.append(f"   • {filename}")
                output.append(f"     Theme: {theme_rel}")
                output.append(f"     Overrides: {source_rel}")
            output.append("")

        # Display other overrides
        if other_overrides:
            output.append("📁 OTHER TEMPLATE OVERRIDES:")
            for filename, theme_rel, source in sorted(other_overrides):
                source_rel = _make_relative_to_drupal(drupal_root, source)
                output.append(f"   • {filename}")
                output.append(f"     Theme: {theme_rel}")
                output.append(f"     Overrides: {source_rel}")
            output.append("")

        output.append("💡 Tip: Use find_theme_templates() to see all templates with patterns")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting theme template overrides")
        return f"❌ ERROR: Failed to get overrides: {str(e)}"


@mcp.tool()
def get_view_template_info(view_name: str, display_id: Optional[str] = None) -> str:
    """
    Get template naming suggestions and information for overriding a view.

    Shows exactly which template names you can use to override a view and where
    to place them. Perfect for view theming without guessing filenames.

    Args:
        view_name: Machine name of the view (e.g., "taxonomy_term", "frontpage", "content")
        display_id: Optional display ID (e.g., "page_1", "block_1", "default")
                   If not provided, shows suggestions for all displays

    Returns:
        Template suggestions with specificity hierarchy and placement instructions

    Examples:
        get_view_template_info("taxonomy_term")
        get_view_template_info("content", "page_1")
        get_view_template_info("frontpage", "default")
    """
    try:
        output = []
        output.append(f"📋 VIEW TEMPLATE INFO: {view_name.upper()}")
        if display_id:
            output.append(f"   Display: {display_id}")
        output.append("=" * 80)
        output.append("")

        # Generate template suggestions
        suggestions = []

        if display_id:
            # Specific display suggestions (most specific to least)
            suggestions.extend(
                [
                    (
                        f"views-view--{view_name}--{display_id}.html.twig",
                        "Only this display of this view (MOST SPECIFIC)",
                        "⭐ Use this to override just this display",
                    ),
                    (
                        f"views-view--{view_name}.html.twig",
                        f"All displays of the '{view_name}' view",
                        "Use this to override the entire view",
                    ),
                ]
            )
        else:
            # View-level suggestions
            suggestions.append(
                (
                    f"views-view--{view_name}.html.twig",
                    f"All displays of the '{view_name}' view",
                    "Use this to override the entire view",
                )
            )

        # General view suggestions
        suggestions.extend(
            [
                (
                    "views-view.html.twig",
                    "All views on the site (LEAST SPECIFIC)",
                    "Rarely used - affects every view",
                ),
            ]
        )

        output.append("TEMPLATE SUGGESTIONS (most specific to least):")
        output.append("")

        for i, (template, description, usage) in enumerate(suggestions, 1):
            output.append(f"{i}. {template}")
            output.append(f"   Description: {description}")
            output.append(f"   Usage: {usage}")
            output.append("")

        # Additional view templates
        output.append("OTHER VIEW TEMPLATES YOU CAN OVERRIDE:")
        output.append("")

        additional = [
            ("views-view-field.html.twig", "Individual field output"),
            ("views-view-fields.html.twig", "Row with fields (fields style)"),
            ("views-view-unformatted.html.twig", "Unformatted list of rows"),
            ("views-view-table.html.twig", "Table format"),
            ("views-view-grid.html.twig", "Grid format"),
            ("views-view-list.html.twig", "HTML list format"),
        ]

        for template, description in additional:
            # Can add view-specific naming
            if display_id:
                specific = template.replace(".html.twig", f"--{view_name}--{display_id}.html.twig")
                output.append(f"• {specific}")
                output.append(f"  Or: {template.replace('.html.twig', f'--{view_name}.html.twig')}")
            else:
                output.append(f"• {template.replace('.html.twig', f'--{view_name}.html.twig')}")
            output.append(f"  ({description})")
            output.append("")

        # Placement instructions
        output.append("📁 WHERE TO PLACE TEMPLATES:")
        output.append("")
        output.append("1. In your active theme's templates directory:")
        output.append("   your_theme/templates/")
        output.append("")
        output.append("2. Or in a views subdirectory (for organization):")
        output.append("   your_theme/templates/views/")
        output.append("")
        output.append("3. Clear cache after adding templates:")
        output.append("   drush cr")
        output.append("")

        # Quick guide
        output.append("🎯 QUICK GUIDE:")
        output.append("")
        output.append("To override the ENTIRE view:")
        output.append(f"  1. Create: {suggestions[0][0]}")
        output.append("  2. Copy base template from:")
        output.append("     core/modules/views/templates/views-view.html.twig")
        output.append("  3. Modify as needed")
        output.append("  4. Clear cache: drush cr")
        output.append("")

        output.append("💡 Tips:")
        output.append("   - Use find_theme_templates() to see existing view templates")
        output.append("   - More specific templates take precedence")
        output.append("   - Check Views UI for template suggestions (enable Twig debugging)")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting view template info")
        return f"❌ ERROR: Failed to get view template info: {str(e)}"


@mcp.tool()
def get_template_suggestions(entity_type: str, bundle: Optional[str] = None) -> str:
    """
    Get available template file naming suggestions for an entity type.

    Shows the template suggestion hierarchy that Drupal uses to find templates.
    Perfect for understanding which template names you can use for customization.

    Args:
        entity_type: Entity type (e.g., "node", "user", "taxonomy_term", "block")
        bundle: Optional bundle/content type (e.g., "article", "page", "tags")

    Returns:
        List of template suggestions in order of specificity (most specific first)

    Examples:
        get_template_suggestions("node", "article")
        get_template_suggestions("block")
        get_template_suggestions("taxonomy_term", "tags")
        get_template_suggestions("user")
    """
    try:
        output = []
        output.append(f"📝 TEMPLATE SUGGESTIONS FOR: {entity_type.upper()}")
        if bundle:
            output.append(f"   Bundle: {bundle}")
        output.append("=" * 80)
        output.append("")

        suggestions = _generate_template_suggestions(entity_type, bundle)

        output.append("Template naming options (most specific to least specific):")
        output.append("")

        for i, (suggestion, description) in enumerate(suggestions, 1):
            output.append(f"{i}. {suggestion}")
            output.append(f"   {description}")
            output.append("")

        output.append("💡 How to use:")
        output.append("   1. Create a template with any of these names in your theme")
        output.append("   2. Drupal will use the MOST SPECIFIC match it finds")
        output.append("   3. More specific = higher priority")
        output.append("")
        output.append("   Example: node--article--123.html.twig beats node--article.html.twig")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting template suggestions")
        return f"❌ ERROR: Failed to get suggestions: {str(e)}"


def _find_theme_path(drupal_root: Path, theme_name: str) -> Optional[Path]:
    """Find theme path using drush."""
    drush_cmd = get_drush_command()
    cmd = drush_cmd + ["theme:list", "--format=json", "--fields=name,path"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=str(drupal_root)
        )
        if result.returncode == 0 and result.stdout:
            import json

            themes = json.loads(result.stdout.strip())
            if theme_name in themes:
                theme_path = Path(themes[theme_name]["path"])
                if not theme_path.is_absolute():
                    theme_path = drupal_root / theme_path
                    if not theme_path.exists():
                        theme_path = drupal_root / "web" / themes[theme_name]["path"]
                return theme_path if theme_path.exists() else None
    except Exception:
        pass

    # Fallback: search filesystem
    possible_paths = [
        drupal_root / "themes" / "custom" / theme_name,
        drupal_root / "themes" / "contrib" / theme_name,
        drupal_root / "web" / "themes" / "custom" / theme_name,
        drupal_root / "web" / "themes" / "contrib" / theme_name,
        drupal_root / "core" / "themes" / theme_name,
    ]

    for path in possible_paths:
        if path.exists():
            return path

    return None


def _detect_template_override(filename: str) -> Optional[str]:
    """Detect what a template might override based on naming conventions."""
    stem = filename.replace(".html.twig", "")

    overrides = {
        "page": "Core page template",
        "node": "Core node template",
        "block": "Core block template",
        "field": "Core field template",
        "views-view": "Views module template",
        "comment": "Core comment template",
        "user": "Core user template",
        "taxonomy-term": "Core taxonomy template",
        "region": "Core region template",
        "html": "Core HTML wrapper template",
        "maintenance-page": "Core maintenance mode template",
    }

    for key, description in overrides.items():
        if stem.startswith(key):
            return f"↻ Likely overrides: {description}"

    return None


def _find_template_sources(drupal_root: Path, filename: str) -> List[Path]:
    """Find where a template originally comes from (core/contrib)."""
    sources = []

    # Search in core
    core_paths = [
        drupal_root / "core" / "themes",
        drupal_root / "core" / "modules",
    ]

    # Search in contrib
    contrib_paths = [
        drupal_root / "modules" / "contrib",
        drupal_root / "web" / "modules" / "contrib",
    ]

    search_paths = core_paths + contrib_paths

    for search_path in search_paths:
        if search_path.exists():
            matches = list(search_path.rglob(filename))
            sources.extend(matches)

    return sources


def _make_relative_to_drupal(drupal_root: Path, path: Path) -> str:
    """Make path relative to drupal root for display."""
    try:
        return str(Path(path).relative_to(drupal_root))
    except ValueError:
        return str(path)


def _generate_template_suggestions(entity_type: str, bundle: Optional[str] = None) -> List[tuple]:
    """Generate template suggestions based on entity type and bundle."""
    suggestions = []

    # Common patterns for different entity types
    if entity_type == "node":
        if bundle:
            suggestions.extend(
                [
                    (
                        f"node--{bundle}--[nid].html.twig",
                        f"Specific {bundle} node by ID (e.g., node--{bundle}--123.html.twig)",
                    ),
                    (
                        f"node--{bundle}--[view-mode].html.twig",
                        f"Specific {bundle} by view mode (e.g., node--{bundle}--teaser.html.twig)",
                    ),
                    (
                        f"node--{bundle}.html.twig",
                        f"All {bundle} nodes",
                    ),
                ]
            )
        suggestions.extend(
            [
                (
                    "node--[nid].html.twig",
                    "Specific node by ID (e.g., node--123.html.twig)",
                ),
                (
                    "node--[view-mode].html.twig",
                    "All nodes in view mode (e.g., node--teaser.html.twig)",
                ),
                ("node.html.twig", "All nodes (base template)"),
            ]
        )

    elif entity_type == "block":
        if bundle:
            suggestions.append(
                (
                    f"block--{bundle}.html.twig",
                    f"All {bundle} blocks",
                )
            )
        suggestions.extend(
            [
                (
                    "block--[plugin-id].html.twig",
                    "Specific block plugin (e.g., block--system-branding-block.html.twig)",
                ),
                (
                    "block--[region].html.twig",
                    "All blocks in region (e.g., block--sidebar.html.twig)",
                ),
                ("block.html.twig", "All blocks (base template)"),
            ]
        )

    elif entity_type == "taxonomy_term":
        if bundle:
            suggestions.extend(
                [
                    (
                        f"taxonomy-term--{bundle}--[tid].html.twig",
                        f"Specific {bundle} term by ID",
                    ),
                    (
                        f"taxonomy-term--{bundle}.html.twig",
                        f"All {bundle} terms",
                    ),
                ]
            )
        suggestions.extend(
            [
                (
                    "taxonomy-term--[tid].html.twig",
                    "Specific term by ID (e.g., taxonomy-term--5.html.twig)",
                ),
                ("taxonomy-term.html.twig", "All taxonomy terms (base template)"),
            ]
        )

    elif entity_type == "user":
        suggestions.extend(
            [
                (
                    "user--[uid].html.twig",
                    "Specific user by ID (e.g., user--1.html.twig)",
                ),
                (
                    "user--[view-mode].html.twig",
                    "Users in view mode (e.g., user--compact.html.twig)",
                ),
                ("user.html.twig", "All users (base template)"),
            ]
        )

    elif entity_type == "field":
        if bundle:
            suggestions.append(
                (
                    f"field--{bundle}.html.twig",
                    f"All fields on {bundle}",
                )
            )
        suggestions.extend(
            [
                (
                    "field--[field-name]--[bundle].html.twig",
                    "Specific field on bundle (e.g., field--body--article.html.twig)",
                ),
                (
                    "field--[field-name].html.twig",
                    "Specific field all bundles (e.g., field--body.html.twig)",
                ),
                (
                    "field--[field-type].html.twig",
                    "All fields of type (e.g., field--text-with-summary.html.twig)",
                ),
                ("field.html.twig", "All fields (base template)"),
            ]
        )

    elif entity_type == "page":
        suggestions.extend(
            [
                (
                    "page--[path].html.twig",
                    "Specific path (e.g., page--node--123.html.twig, page--admin.html.twig)",
                ),
                (
                    "page--[type].html.twig",
                    "Page by type (e.g., page--article.html.twig)",
                ),
                ("page.html.twig", "All pages (base template)"),
            ]
        )

    else:
        # Generic entity template suggestions
        if bundle:
            suggestions.append(
                (
                    f"{entity_type}--{bundle}.html.twig",
                    f"All {bundle} {entity_type}s",
                )
            )
        suggestions.append(
            (
                f"{entity_type}.html.twig",
                f"All {entity_type}s (base template)",
            )
        )

    return suggestions
