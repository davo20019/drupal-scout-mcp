"""
Block placement analysis tools for Drupal Scout MCP.

Provides block assignment and visibility information per theme.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Optional

# Import from core modules
from src.core.config import load_config
from src.core.drush import get_drush_command
from src.core.database import verify_database_connection

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def get_theme_blocks(theme_name: str) -> str:
    """
    Get detailed block placement information for a theme.

    Shows:
    - Blocks assigned to each region
    - Block weights (display order)
    - Visibility conditions (summary)
    - Empty regions (no blocks assigned)
    - Block plugin types

    Perfect for:
    - Understanding block layout
    - Planning block placement
    - Finding empty regions
    - Debugging block visibility issues

    Args:
        theme_name: Machine name of theme (e.g., "olivero", "claro", "my_custom_theme")

    Returns:
        Formatted block placement information grouped by region

    Examples:
        get_theme_blocks("olivero")
        get_theme_blocks("my_custom_theme")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root. Check drupal_root in config."

        # Verify database connection
        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return f"❌ ERROR: Database connection required\n\n{db_msg}\n\nRun check_scout_health() for detailed diagnostics"

        # Get blocks for theme
        blocks_data = _get_blocks_for_theme(drupal_root, theme_name)

        if not blocks_data:
            return f"❌ ERROR: Could not load blocks for theme '{theme_name}'\n\nCheck:\n- Theme name is correct\n- Theme is installed\n- Database connection is working"

        # Get theme regions for completeness
        theme_regions = _get_theme_regions(drupal_root, theme_name)

        # Build output
        output = []
        output.append(f"🧩 BLOCK PLACEMENT: {theme_name}")
        output.append("=" * 80)
        output.append("")

        if not blocks_data.get("regions"):
            output.append("⚠️  No blocks placed in any region")
            output.append("")
            if theme_regions:
                output.append(f"Available regions ({len(theme_regions)}):")
                for region_key, region_label in theme_regions.items():
                    output.append(f"  - {region_label} ({region_key})")
            return "\n".join(output)

        total_blocks = sum(len(blocks) for blocks in blocks_data["regions"].values())
        output.append(f"Total blocks: {total_blocks}")
        output.append(f"Regions with blocks: {len(blocks_data['regions'])}")
        output.append("")

        # Show blocks by region
        for region_key, blocks in sorted(blocks_data["regions"].items()):
            region_label = (
                theme_regions.get(region_key, region_key) if theme_regions else region_key
            )
            output.append(f"REGION: {region_label} ({region_key})")
            output.append(f"  Blocks: {len(blocks)}")
            output.append("  " + "-" * 76)

            for block in blocks:
                output.append(f"  [{block['weight']:>3}] {block['label']}")
                output.append(f"       ID: {block['id']}")
                output.append(f"       Plugin: {block['plugin']}")

                # Visibility conditions
                visibility_summary = _format_visibility_summary(block.get("visibility_details", {}))
                if visibility_summary:
                    output.append(f"       Visibility: {visibility_summary}")
                else:
                    output.append("       Visibility: Always visible")

                output.append("")

        # Show empty regions
        if theme_regions:
            empty_regions = [
                (key, label)
                for key, label in theme_regions.items()
                if key not in blocks_data["regions"]
            ]
            if empty_regions:
                output.append(f"EMPTY REGIONS ({len(empty_regions)}):")
                for region_key, region_label in empty_regions:
                    output.append(f"  - {region_label} ({region_key})")
                output.append("")

        # Summary stats
        output.append("BLOCK TYPES:")
        plugin_counts = {}
        for blocks in blocks_data["regions"].values():
            for block in blocks:
                plugin = block["plugin"]
                plugin_counts[plugin] = plugin_counts.get(plugin, 0) + 1

        for plugin, count in sorted(plugin_counts.items(), key=lambda x: -x[1]):
            output.append(f"  - {plugin}: {count}")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting theme blocks")
        return f"❌ ERROR: Failed to get theme blocks: {str(e)}"


def _get_blocks_for_theme(drupal_root: Path, theme_name: str) -> Optional[Dict]:
    """Get all blocks for a theme with detailed information."""
    drush_cmd = get_drush_command()

    php_script = f"""
$theme = '{theme_name}';
$block_storage = \\Drupal::entityTypeManager()->getStorage('block');
$blocks = $block_storage->loadByProperties(['theme' => $theme]);

$result = ['regions' => []];

foreach ($blocks as $block_id => $block) {{
  if (!$block->status()) {{
    continue; // Skip disabled blocks
  }}

  $region = $block->getRegion();
  $visibility = $block->getVisibility();

  // Parse visibility conditions for summary
  $visibility_details = [];
  foreach ($visibility as $plugin_id => $config) {{
    if ($plugin_id === 'request_path') {{
      $pages = $config['pages'] ?? '';
      $negate = $config['negate'] ?? false;
      $visibility_details['pages'] = [
        'type' => $negate ? 'exclude' : 'include',
        'paths' => array_filter(explode("\\n", $pages)),
      ];
    }} elseif ($plugin_id === 'user_role') {{
      $roles = $config['roles'] ?? [];
      $negate = $config['negate'] ?? false;
      $visibility_details['roles'] = [
        'type' => $negate ? 'exclude' : 'include',
        'roles' => array_values($roles),
      ];
    }} elseif ($plugin_id === 'node_type') {{
      $bundles = $config['bundles'] ?? [];
      $negate = $config['negate'] ?? false;
      $visibility_details['content_types'] = [
        'type' => $negate ? 'exclude' : 'include',
        'types' => array_values($bundles),
      ];
    }} elseif ($plugin_id === 'language') {{
      $langcodes = $config['langcodes'] ?? [];
      $negate = $config['negate'] ?? false;
      $visibility_details['languages'] = [
        'type' => $negate ? 'exclude' : 'include',
        'languages' => array_values($langcodes),
      ];
    }} else {{
      $visibility_details[$plugin_id] = 'configured';
    }}
  }}

  $result['regions'][$region][] = [
    'id' => $block->id(),
    'label' => $block->label(),
    'weight' => $block->getWeight(),
    'plugin' => $block->getPluginId(),
    'has_visibility' => !empty($visibility),
    'visibility_details' => $visibility_details,
  ];
}}

// Sort blocks by weight within each region
foreach ($result['regions'] as $region => &$blocks) {{
  usort($blocks, function($a, $b) {{
    return $a['weight'] <=> $b['weight'];
  }});
}}

echo json_encode($result, JSON_UNESCAPED_SLASHES);
"""

    try:
        cmd = drush_cmd + ["eval", php_script]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=str(drupal_root)
        )

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout.strip())
    except Exception as e:
        logger.error(f"Error getting blocks for theme: {e}")

    return None


def _get_theme_regions(drupal_root: Path, theme_name: str) -> Optional[Dict[str, str]]:
    """Get theme regions from theme info."""
    drush_cmd = get_drush_command()

    php_script = f"""
$theme_name = '{theme_name}';
$theme_handler = \\Drupal::service('theme_handler');

if (!$theme_handler->themeExists($theme_name)) {{
  echo json_encode(null);
  exit;
}}

$theme_list = $theme_handler->listInfo();
$theme = $theme_list[$theme_name];
$regions = $theme->info['regions'] ?? [];

echo json_encode($regions, JSON_UNESCAPED_SLASHES);
"""

    try:
        cmd = drush_cmd + ["eval", php_script]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=str(drupal_root)
        )

        if result.returncode == 0 and result.stdout:
            regions = json.loads(result.stdout.strip())
            return regions if regions else None
    except Exception as e:
        logger.debug(f"Error getting theme regions: {e}")

    return None


def _format_visibility_summary(visibility_details: Dict) -> str:
    """Format visibility conditions into human-readable summary."""
    if not visibility_details:
        return ""

    parts = []

    # Page visibility
    if "pages" in visibility_details:
        pages_info = visibility_details["pages"]
        action = "Only on" if pages_info["type"] == "include" else "Hidden on"
        path_count = len(pages_info["paths"])
        if path_count == 1:
            parts.append(f"{action}: {pages_info['paths'][0]}")
        else:
            parts.append(f"{action} {path_count} pages")

    # Role visibility
    if "roles" in visibility_details:
        roles_info = visibility_details["roles"]
        action = "Only for" if roles_info["type"] == "include" else "Hidden from"
        roles = ", ".join(roles_info["roles"])
        parts.append(f"{action} roles: {roles}")

    # Content type visibility
    if "content_types" in visibility_details:
        types_info = visibility_details["content_types"]
        action = "Only on" if types_info["type"] == "include" else "Hidden on"
        types = ", ".join(types_info["types"])
        parts.append(f"{action} content types: {types}")

    # Language visibility
    if "languages" in visibility_details:
        lang_info = visibility_details["languages"]
        action = "Only for" if lang_info["type"] == "include" else "Hidden from"
        langs = ", ".join(lang_info["languages"])
        parts.append(f"{action} languages: {langs}")

    # Other conditions
    other_conditions = [
        key
        for key in visibility_details.keys()
        if key not in ["pages", "roles", "content_types", "languages"]
    ]
    if other_conditions:
        parts.append(f"Custom conditions: {', '.join(other_conditions)}")

    return " | ".join(parts)
