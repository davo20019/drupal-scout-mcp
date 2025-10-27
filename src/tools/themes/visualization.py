"""
Theme region visualization tool for Drupal Scout MCP.

Provides HTML visualization of theme regions and block placement.
"""

import json
import logging
import subprocess
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Import from core modules
from src.core.config import load_config
from src.core.drush import get_drush_command
from src.core.database import verify_database_connection

# Import shared export utilities
from src.tools.exports.common import validate_export_path

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def visualize_theme_regions(theme_name: str, output_path: Optional[str] = None) -> str:
    """
    Generate HTML visualization of theme regions with block placement.

    Creates an interactive HTML file showing:
    - Visual layout of theme regions (header, sidebars, content, footer)
    - Blocks placed in each region with weights
    - Empty vs populated regions
    - Color-coded for easy identification

    Perfect for:
    - Understanding theme layout structure
    - Block placement planning
    - Identifying unused regions
    - Visual documentation of theme structure

    Args:
        theme_name: Machine name of theme (e.g., "olivero", "claro", "my_custom_theme")
        output_path: Optional HTML file path. If not provided, auto-generates:
                     {drupal_root}/theme_regions_{theme_name}_{timestamp}.html

    Returns:
        JSON with file path and region summary:
        {
            "success": True,
            "file_path": "/path/to/drupal/theme_regions_olivero_20251026.html",
            "theme_name": "olivero",
            "total_regions": 8,
            "total_blocks": 15,
            "regions": {...}
        }

    Examples:
        Visualize Olivero theme:
        visualize_theme_regions("olivero")

        Visualize custom theme:
        visualize_theme_regions("my_custom_theme")

        Save to specific location:
        visualize_theme_regions("olivero", "/tmp/olivero_layout.html")
    """
    try:
        # Load config and verify
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return json.dumps(
                {
                    "_error": True,
                    "message": "Could not determine Drupal root. Check drupal_root in config.",
                }
            )

        # Verify database connection
        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Database connection required. {db_msg}",
                    "help": "Run check_scout_health() for detailed diagnostics",
                }
            )

        # Auto-generate path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(drupal_root / f"theme_regions_{theme_name}_{timestamp}.html")

        # Validate path
        is_valid, error_msg = validate_export_path(output_path, drupal_root)
        if not is_valid:
            return json.dumps({"_error": True, "message": f"Invalid export path: {error_msg}"})

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Get theme info and regions
        theme_info = _get_theme_info(drupal_root, theme_name)
        if not theme_info:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Theme '{theme_name}' not found. Check theme name and ensure it's installed.",
                }
            )

        # Get block placement
        blocks_by_region = _get_theme_blocks_data(drupal_root, theme_name)

        # Generate HTML
        html_content = _generate_html_visualization(
            theme_name=theme_name,
            theme_info=theme_info,
            blocks_by_region=blocks_by_region,
        )

        # Write file
        output_file.write_text(html_content, encoding="utf-8")

        # Build response
        total_blocks = sum(len(blocks) for blocks in blocks_by_region.values())
        response = {
            "success": True,
            "file_path": str(output_file),
            "theme_name": theme_name,
            "theme_label": theme_info.get("name", theme_name),
            "total_regions": len(theme_info.get("regions", {})),
            "total_blocks": total_blocks,
            "regions": {
                region: {
                    "label": label,
                    "block_count": len(blocks_by_region.get(region, [])),
                }
                for region, label in theme_info.get("regions", {}).items()
            },
            "message": f"Open {output_file.name} in your browser to view the visual layout",
        }

        return json.dumps(response, indent=2)

    except Exception as e:
        logger.exception("Error generating theme region visualization")
        return json.dumps({"_error": True, "message": f"Visualization failed: {str(e)}"})


def _get_theme_info(drupal_root: Path, theme_name: str) -> Optional[Dict]:
    """Get theme information from .info.yml file."""
    # Try to find theme path using drush
    drush_cmd = get_drush_command()
    cmd = drush_cmd + ["theme:list", "--format=json", "--fields=name,path,status"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=str(drupal_root)
        )

        if result.returncode == 0 and result.stdout:
            themes = json.loads(result.stdout.strip())
            if theme_name in themes:
                theme_path = Path(themes[theme_name]["path"])
                if not theme_path.is_absolute():
                    theme_path = drupal_root / theme_path
                    if not theme_path.exists():
                        theme_path = drupal_root / "web" / themes[theme_name]["path"]

                if theme_path.exists():
                    # Read .info.yml
                    info_file = theme_path / f"{theme_name}.info.yml"
                    if info_file.exists():
                        with open(info_file, "r") as f:
                            info = yaml.safe_load(f)
                            info["path"] = str(theme_path)
                            return info
    except Exception as e:
        logger.debug(f"Error getting theme info via drush: {e}")

    # Fallback: search filesystem
    possible_paths = [
        drupal_root / "themes" / "custom" / theme_name,
        drupal_root / "themes" / "contrib" / theme_name,
        drupal_root / "themes" / theme_name,
        drupal_root / "web" / "themes" / "custom" / theme_name,
        drupal_root / "web" / "themes" / "contrib" / theme_name,
        drupal_root / "core" / "themes" / theme_name,
    ]

    for path in possible_paths:
        info_file = path / f"{theme_name}.info.yml"
        if info_file.exists():
            with open(info_file, "r") as f:
                info = yaml.safe_load(f)
                info["path"] = str(path)
                return info

    return None


def _get_theme_blocks_data(drupal_root: Path, theme_name: str) -> Dict[str, List[Dict]]:
    """Get blocks assigned to each region for the theme."""
    drush_cmd = get_drush_command()

    php_script = f"""
$theme = '{theme_name}';
$blocks = \\Drupal::entityTypeManager()->getStorage('block')->loadByProperties(['theme' => $theme]);

$result = [];
foreach ($blocks as $block_id => $block) {{
  if ($block->status()) {{
    $region = $block->getRegion();
    $result[$region][] = [
      'id' => $block->id(),
      'label' => $block->label(),
      'weight' => $block->getWeight(),
      'plugin' => $block->getPluginId(),
      'visibility' => !empty($block->getVisibility()) ? 'Has conditions' : 'Always visible',
    ];
  }}
}}

// Sort blocks by weight within each region
foreach ($result as $region => &$blocks) {{
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
        logger.error(f"Error getting block data: {e}")

    return {}


def _detect_region_layout(regions: Dict[str, str]) -> Dict[str, str]:
    """
    Detect region positioning based on common naming patterns.

    Returns dict mapping region to position: 'header', 'sidebar', 'content', 'footer'
    """
    layout = {}

    for region_key, region_label in regions.items():
        region_lower = region_key.lower()
        label_lower = region_label.lower()

        # Header regions
        if any(word in region_lower or word in label_lower for word in ["header", "top", "banner"]):
            layout[region_key] = "header"
        # Footer regions
        elif any(word in region_lower or word in label_lower for word in ["footer", "bottom"]):
            layout[region_key] = "footer"
        # Left sidebar
        elif any(
            word in region_lower or word in label_lower
            for word in ["sidebar_first", "left", "sidebar-first"]
        ):
            layout[region_key] = "sidebar_left"
        # Right sidebar
        elif any(
            word in region_lower or word in label_lower
            for word in ["sidebar_second", "right", "sidebar-second", "aside"]
        ):
            layout[region_key] = "sidebar_right"
        # Content/main region
        elif any(
            word in region_lower or word in label_lower for word in ["content", "main", "primary"]
        ):
            layout[region_key] = "content"
        # Navigation/menu
        elif any(word in region_lower or word in label_lower for word in ["nav", "menu"]):
            layout[region_key] = "navigation"
        # Default to other
        else:
            layout[region_key] = "other"

    return layout


def _generate_html_visualization(
    theme_name: str,
    theme_info: Dict,
    blocks_by_region: Dict[str, List[Dict]],
) -> str:
    """Generate HTML visualization of theme layout."""

    regions = theme_info.get("regions", {})
    layout_map = _detect_region_layout(regions)

    # Group regions by position
    header_regions = [r for r, pos in layout_map.items() if pos == "header"]
    nav_regions = [r for r, pos in layout_map.items() if pos == "navigation"]
    sidebar_left_regions = [r for r, pos in layout_map.items() if pos == "sidebar_left"]
    content_regions = [r for r, pos in layout_map.items() if pos == "content"]
    sidebar_right_regions = [r for r, pos in layout_map.items() if pos == "sidebar_right"]
    footer_regions = [r for r, pos in layout_map.items() if pos == "footer"]
    other_regions = [r for r, pos in layout_map.items() if pos == "other"]

    def render_region(region_key: str) -> str:
        """Render a single region with its blocks."""
        label = regions.get(region_key, region_key)
        blocks = blocks_by_region.get(region_key, [])
        block_count = len(blocks)

        blocks_html = ""
        if blocks:
            blocks_html = "<div class='blocks'>"
            for block in blocks:
                blocks_html += f"""
                <div class='block'>
                    <div class='block-title'>{block['label']}</div>
                    <div class='block-meta'>Weight: {block['weight']} | {block['visibility']}</div>
                </div>
                """
            blocks_html += "</div>"
        else:
            blocks_html = "<div class='empty-region'>No blocks</div>"

        return f"""
        <div class='region'>
            <div class='region-header'>
                <div class='region-name'>{label}</div>
                <div class='region-machine-name'>{region_key}</div>
                <div class='region-count'>{block_count} block{"s" if block_count != 1 else ""}</div>
            </div>
            {blocks_html}
        </div>
        """

    # Build HTML structure
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{theme_info.get('name', theme_name)} - Region Layout</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
        }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 14px; }}
        .layout {{
            padding: 20px;
        }}
        .row {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .row.full {{
            flex-direction: column;
        }}
        .col-left {{ flex: 0 0 250px; }}
        .col-center {{ flex: 1; }}
        .col-right {{ flex: 0 0 250px; }}
        .region {{
            background: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            min-height: 100px;
        }}
        .region-header {{
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 2px solid #dee2e6;
        }}
        .region-name {{
            font-size: 18px;
            font-weight: 600;
            color: #212529;
            margin-bottom: 4px;
        }}
        .region-machine-name {{
            font-size: 12px;
            font-family: 'Courier New', monospace;
            color: #6c757d;
            margin-bottom: 4px;
        }}
        .region-count {{
            font-size: 12px;
            color: #0d6efd;
            font-weight: 500;
        }}
        .blocks {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .block {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
        }}
        .block-title {{
            font-size: 14px;
            font-weight: 500;
            color: #212529;
            margin-bottom: 4px;
        }}
        .block-meta {{
            font-size: 11px;
            color: #6c757d;
        }}
        .empty-region {{
            text-align: center;
            color: #adb5bd;
            font-style: italic;
            padding: 20px;
        }}
        .section-label {{
            font-size: 14px;
            font-weight: 600;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
            padding-left: 5px;
        }}
        /* Color coding by region type */
        .region {{ border-left: 4px solid #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{theme_info.get('name', theme_name)}</h1>
            <div class="meta">
                Machine name: {theme_name} |
                {len(regions)} regions |
                {sum(len(b) for b in blocks_by_region.values())} blocks placed
            </div>
        </div>

        <div class="layout">
"""

    # Header regions
    if header_regions:
        html += '<div class="section-label">Header Area</div>'
        html += '<div class="row full">'
        for region in header_regions:
            html += render_region(region)
        html += "</div>"

    # Navigation regions
    if nav_regions:
        html += '<div class="section-label">Navigation Area</div>'
        html += '<div class="row full">'
        for region in nav_regions:
            html += render_region(region)
        html += "</div>"

    # Main content area (sidebars + content)
    if sidebar_left_regions or content_regions or sidebar_right_regions:
        html += '<div class="section-label">Main Content Area</div>'
        html += '<div class="row">'

        if sidebar_left_regions:
            html += '<div class="col-left">'
            for region in sidebar_left_regions:
                html += render_region(region)
            html += "</div>"

        if content_regions:
            html += '<div class="col-center">'
            for region in content_regions:
                html += render_region(region)
            html += "</div>"

        if sidebar_right_regions:
            html += '<div class="col-right">'
            for region in sidebar_right_regions:
                html += render_region(region)
            html += "</div>"

        html += "</div>"

    # Footer regions
    if footer_regions:
        html += '<div class="section-label">Footer Area</div>'
        html += '<div class="row full">'
        for region in footer_regions:
            html += render_region(region)
        html += "</div>"

    # Other regions
    if other_regions:
        html += '<div class="section-label">Other Regions</div>'
        html += '<div class="row full">'
        for region in other_regions:
            html += render_region(region)
        html += "</div>"

    html += """
        </div>
    </div>
</body>
</html>
"""

    return html
