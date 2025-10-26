"""
Views tools for Drupal Scout MCP server.

This module provides tools for inspecting Drupal Views configurations.
Uses drush-first approach for accuracy, with file-based fallback when
drush is unavailable.

Tools:
- get_views_summary: Get views configurations with optional filtering
"""

import logging
from pathlib import Path
from typing import List, Optional

# Import MCP instance from server (used for @mcp.tool() decorator)
from server import mcp

# Import core utilities
from src.core.config import get_config
from src.core.drush import run_drush_command

logger = logging.getLogger(__name__)


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
