"""
Theme information tools for Drupal Scout MCP.

Provides theme metadata and status information.
"""

import json
import logging
import subprocess
import yaml
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
def describe_theme(theme_name: str) -> str:
    """
    Get comprehensive information about a specific theme.

    Returns detailed theme metadata including:
    - Name, description, version, type
    - Base theme and inheritance chain
    - Regions defined
    - Libraries defined
    - Dependencies and requirements
    - Installation and default status
    - Theme path location

    Perfect for:
    - Understanding theme structure
    - Checking theme compatibility
    - Finding available regions
    - Library discovery

    Args:
        theme_name: Machine name of theme (e.g., "olivero", "claro", "my_custom_theme")

    Returns:
        Formatted theme information with all metadata

    Examples:
        describe_theme("olivero")
        describe_theme("my_custom_theme")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root. Check drupal_root in config."

        # Get theme info from .info.yml
        theme_info = _find_and_parse_theme_info(drupal_root, theme_name)
        if not theme_info:
            return f"❌ ERROR: Theme '{theme_name}' not found\n\nCheck:\n- Theme name spelling\n- Theme is installed\n- Theme path is accessible"

        # Get installation status
        theme_status = _get_theme_status(drupal_root, theme_name)

        # Build output
        output = []
        output.append(f"📦 THEME: {theme_info.get('name', theme_name)}")
        output.append(f"   Machine name: {theme_name}")
        output.append("=" * 80)
        output.append("")

        # Basic info
        if "description" in theme_info:
            output.append(f"Description: {theme_info['description']}")
            output.append("")

        output.append(f"Type: {theme_info.get('type', 'theme')}")
        if "version" in theme_info:
            output.append(f"Version: {theme_info['version']}")
        if "core_version_requirement" in theme_info:
            output.append(f"Drupal Compatibility: {theme_info['core_version_requirement']}")
        output.append(f"Path: {theme_info.get('path', 'unknown')}")
        output.append("")

        # Status
        output.append("STATUS:")
        if theme_status:
            output.append(f"  Installed: {'Yes' if theme_status.get('installed') else 'No'}")
            output.append(f"  Default theme: {'Yes' if theme_status.get('is_default') else 'No'}")
            output.append(f"  Admin theme: {'Yes' if theme_status.get('is_admin') else 'No'}")
        else:
            output.append("  Status: Unknown (database not available)")
        output.append("")

        # Base theme
        if "base theme" in theme_info:
            output.append(f"Base Theme: {theme_info['base theme']}")
            # Show inheritance chain
            chain = _get_theme_inheritance_chain(drupal_root, theme_name, theme_info)
            if len(chain) > 1:
                output.append(f"  Inheritance: {' → '.join(chain)}")
            output.append("")

        # Regions
        if "regions" in theme_info:
            regions = theme_info["regions"]
            output.append(f"REGIONS ({len(regions)} defined):")
            for region_key, region_label in regions.items():
                output.append(f"  - {region_label} ({region_key})")
            output.append("")

        # Libraries
        libraries = _get_theme_libraries(drupal_root, theme_name, theme_info.get("path"))
        if libraries:
            output.append(f"LIBRARIES ({len(libraries)} defined):")
            for lib_name, lib_info in libraries.items():
                output.append(f"  - {lib_name}")
                if "css" in lib_info:
                    for category, files in lib_info["css"].items():
                        for file_path in files.keys():
                            output.append(f"      CSS: {file_path}")
                if "js" in lib_info:
                    for file_path in lib_info["js"].keys():
                        output.append(f"      JS: {file_path}")
                if "dependencies" in lib_info:
                    output.append(f"      Dependencies: {', '.join(lib_info['dependencies'])}")
            output.append("")

        # Dependencies
        if "dependencies" in theme_info and theme_info["dependencies"]:
            output.append(f"DEPENDENCIES ({len(theme_info['dependencies'])}):")
            for dep in theme_info["dependencies"]:
                output.append(f"  - {dep}")
            output.append("")

        # Theme-specific settings
        if "regions_hidden" in theme_info:
            output.append("HIDDEN REGIONS:")
            for region in theme_info["regions_hidden"]:
                output.append(f"  - {region}")
            output.append("")

        # Breakpoints
        breakpoints = _get_theme_breakpoints(drupal_root, theme_name, theme_info.get("path"))
        if breakpoints:
            output.append(f"BREAKPOINTS ({len(breakpoints)} defined):")
            for bp_name, bp_info in breakpoints.items():
                label = bp_info.get("label", bp_name)
                media_query = bp_info.get("mediaQuery", "")
                output.append(f"  - {label}: {media_query}")
            output.append("")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error describing theme")
        return f"❌ ERROR: Failed to describe theme: {str(e)}"


@mcp.tool()
def get_theme_regions(theme_name: str) -> str:
    """
    Get theme region layout as text (for AI context and quick reference).

    Shows region structure in ASCII layout format with block counts.
    Perfect for AI to understand theme structure and answer questions
    about regions and block placement.

    This is the TEXT version - for visual HTML, use visualize_theme_regions().

    Args:
        theme_name: Machine name of theme (e.g., "olivero", "claro", "my_custom_theme")

    Returns:
        ASCII representation of theme regions with block counts

    Examples:
        get_theme_regions("olivero")
        get_theme_regions("my_custom_theme")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root. Check drupal_root in config."

        # Get theme info
        theme_info = _find_and_parse_theme_info(drupal_root, theme_name)
        if not theme_info:
            return f"❌ ERROR: Theme '{theme_name}' not found"

        regions = theme_info.get("regions", {})
        if not regions:
            return f"❌ ERROR: No regions defined in theme '{theme_name}'"

        # Get block counts per region
        blocks_by_region = {}
        db_ok, _ = verify_database_connection()
        if db_ok:
            blocks_data = _get_blocks_for_theme_simple(drupal_root, theme_name)
            blocks_by_region = blocks_data

        # Detect layout
        layout_map = _detect_region_layout(regions)

        # Group regions by position
        header_regions = [r for r, pos in layout_map.items() if pos == "header"]
        nav_regions = [r for r, pos in layout_map.items() if pos == "navigation"]
        sidebar_left_regions = [r for r, pos in layout_map.items() if pos == "sidebar_left"]
        content_regions = [r for r, pos in layout_map.items() if pos == "content"]
        sidebar_right_regions = [r for r, pos in layout_map.items() if pos == "sidebar_right"]
        footer_regions = [r for r, pos in layout_map.items() if pos == "footer"]
        other_regions = [r for r, pos in layout_map.items() if pos == "other"]

        # Build simple, honest list
        output = []
        total_regions = len(regions)
        total_blocks = sum(len(blocks) for blocks in blocks_by_region.values())

        output.append(
            f"🎨 {theme_info.get('name', theme_name).upper()} REGIONS ({total_regions} total, {total_blocks} blocks placed):"
        )
        output.append("")

        # Group by position
        full_width = []
        main_content = []

        # Full-width regions (header, footer, full-width navigation)
        full_width.extend(header_regions)
        full_width.extend([r for r in footer_regions if "top" in r.lower()])
        full_width.extend([r for r in nav_regions if "secondary" in r.lower()])
        full_width.extend([r for r in footer_regions if "bottom" in r.lower()])

        # Main content area regions
        main_content.extend([(r, "Left") for r in sidebar_left_regions])
        main_content.extend([(r, "Center") for r in content_regions])
        main_content.extend([(r, "Right") for r in sidebar_right_regions])
        main_content.extend(
            [
                (r, "Navigation")
                for r in nav_regions
                if "primary" in r.lower() or "main" in r.lower()
            ]
        )

        # Display full-width regions
        if full_width:
            output.append("FULL-WIDTH REGIONS:")
            for region in full_width:
                label = regions.get(region, region)
                block_count = len(blocks_by_region.get(region, []))
                block_text = f"{block_count} block" + ("s" if block_count != 1 else "")
                output.append(f"  ▓ {label} ({block_text})")
            output.append("")

        # Display main content area
        if main_content:
            output.append("MAIN CONTENT AREA:")
            for region, position in main_content:
                label = regions.get(region, region)
                block_count = len(blocks_by_region.get(region, []))
                block_text = f"{block_count} block" + ("s" if block_count != 1 else "")

                # Icon based on position
                if position == "Left":
                    icon = "◄"
                elif position == "Right":
                    icon = "►"
                else:
                    icon = "■"

                # Mark empty regions
                empty_marker = " - Empty" if block_count == 0 else ""

                output.append(f"  {icon} {label} ({block_text}) [{position}{empty_marker}]")
            output.append("")

        # Other regions
        if other_regions:
            output.append("OTHER REGIONS:")
            for region in other_regions:
                label = regions[region]
                block_count = len(blocks_by_region.get(region, []))
                block_text = f"{block_count} block" + ("s" if block_count != 1 else "")
                empty_marker = " - Empty" if block_count == 0 else ""
                output.append(f"  • {label} ({block_text}){empty_marker}")
            output.append("")

        output.append("💡 Tip: Use get_theme_blocks() for detailed block placement information")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting theme regions")
        return f"❌ ERROR: Failed to get theme regions: {str(e)}"


def _detect_region_layout(regions: Dict[str, str]) -> Dict[str, str]:
    """
    Detect region positioning based on common naming patterns.

    Returns dict mapping region to position: 'header', 'sidebar_left', 'sidebar_right',
    'content', 'footer', 'navigation', 'other'
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


def _get_blocks_for_theme_simple(drupal_root: Path, theme_name: str) -> Dict[str, list]:
    """Get simplified block counts per region."""
    drush_cmd = get_drush_command()

    php_script = f"""
$theme = '{theme_name}';
$blocks = \\Drupal::entityTypeManager()->getStorage('block')->loadByProperties(['theme' => $theme]);

$result = [];
foreach ($blocks as $block) {{
  if ($block->status()) {{
    $region = $block->getRegion();
    $result[$region][] = ['id' => $block->id()];
  }}
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
    except Exception:
        pass

    return {}


@mcp.tool()
def get_active_themes() -> str:
    """
    Get information about active and installed themes.

    Shows:
    - Default (frontend) theme
    - Admin theme
    - All installed themes with status
    - Theme paths and compatibility

    Perfect for:
    - Quick theme status overview
    - Finding which themes are enabled
    - Checking default vs admin themes

    Returns:
        Formatted list of active themes with status information

    Examples:
        get_active_themes()
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root. Check drupal_root in config."

        # Try to get theme list via drush
        db_ok, _ = verify_database_connection()

        output = []
        output.append("🎨 ACTIVE THEMES")
        output.append("=" * 80)
        output.append("")

        if db_ok:
            themes = _get_all_themes_with_status(drupal_root)

            if not themes:
                return "❌ No themes found. Check database connection."

            # Show default and admin themes
            default_theme = next((t for t in themes if t.get("is_default")), None)
            admin_theme = next((t for t in themes if t.get("is_admin")), None)

            if default_theme:
                output.append(
                    f"🌟 Default Theme: {default_theme['name']} ({default_theme['machine_name']})"
                )
                output.append(f"   Path: {default_theme.get('path', 'unknown')}")
                output.append("")

            if admin_theme:
                output.append(
                    f"⚙️  Admin Theme: {admin_theme['name']} ({admin_theme['machine_name']})"
                )
                output.append(f"   Path: {admin_theme.get('path', 'unknown')}")
                output.append("")

            # Show all installed themes
            installed = [t for t in themes if t.get("installed")]
            if installed:
                output.append(f"INSTALLED THEMES ({len(installed)}):")
                for theme in installed:
                    marker = ""
                    if theme.get("is_default"):
                        marker = " [DEFAULT]"
                    elif theme.get("is_admin"):
                        marker = " [ADMIN]"

                    output.append(f"  ✓ {theme['name']} ({theme['machine_name']}){marker}")
                    if theme.get("version"):
                        output.append(f"     Version: {theme['version']}")
                    if theme.get("core_version_requirement"):
                        output.append(f"     Compatibility: {theme['core_version_requirement']}")
                output.append("")

            # Show uninstalled themes
            uninstalled = [t for t in themes if not t.get("installed")]
            if uninstalled:
                output.append(f"AVAILABLE (Not Installed) ({len(uninstalled)}):")
                for theme in uninstalled:
                    output.append(f"  ○ {theme['name']} ({theme['machine_name']})")
                output.append("")

        else:
            output.append("⚠️  Database not available - showing filesystem themes only")
            output.append("")

            # Fallback: search filesystem
            themes = _find_themes_filesystem(drupal_root)
            if themes:
                output.append(f"THEMES FOUND ({len(themes)}):")
                for theme_name, theme_path in themes.items():
                    output.append(f"  - {theme_name}")
                    output.append(f"    Path: {theme_path}")
            else:
                output.append("No themes found in filesystem")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting active themes")
        return f"❌ ERROR: Failed to get active themes: {str(e)}"


def _find_and_parse_theme_info(drupal_root: Path, theme_name: str) -> Optional[Dict]:
    """Find and parse theme .info.yml file."""
    # Try drush first
    drush_cmd = get_drush_command()
    cmd = drush_cmd + ["theme:list", "--format=json", "--fields=name,path"]

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
                info_file = theme_path / f"{theme_name}.info.yml"
                if info_file.exists():
                    with open(info_file, "r") as f:
                        info = yaml.safe_load(f)
                        info["path"] = str(theme_path)
                        return info
    except Exception:
        pass

    # Fallback: filesystem search
    possible_paths = [
        drupal_root / "themes" / "custom" / theme_name,
        drupal_root / "themes" / "contrib" / theme_name,
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


def _get_theme_status(drupal_root: Path, theme_name: str) -> Optional[Dict]:
    """Get theme installation and status info."""
    drush_cmd = get_drush_command()

    php_script = f"""
$theme_name = '{theme_name}';
$theme_handler = \\Drupal::service('theme_handler');
$config = \\Drupal::config('system.theme');

$result = [
  'installed' => $theme_handler->themeExists($theme_name),
  'is_default' => $config->get('default') === $theme_name,
  'is_admin' => $config->get('admin') === $theme_name,
];

echo json_encode($result);
"""

    try:
        cmd = drush_cmd + ["eval", php_script]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=str(drupal_root)
        )
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout.strip())
    except Exception:
        pass

    return None


def _get_theme_inheritance_chain(drupal_root: Path, theme_name: str, theme_info: Dict) -> list[str]:
    """Get theme inheritance chain (theme -> base -> base's base -> etc)."""
    chain = [theme_name]
    current_info = theme_info

    while "base theme" in current_info:
        base_theme = current_info["base theme"]
        if base_theme == "false" or not base_theme:
            break
        chain.append(base_theme)
        # Try to get base theme info
        base_info = _find_and_parse_theme_info(drupal_root, base_theme)
        if not base_info:
            break
        current_info = base_info

    return chain


def _get_theme_libraries(drupal_root: Path, theme_name: str, theme_path: Optional[str]) -> Dict:
    """Parse theme libraries from .libraries.yml file."""
    if not theme_path:
        return {}

    libraries_file = Path(theme_path) / f"{theme_name}.libraries.yml"
    if libraries_file.exists():
        try:
            with open(libraries_file, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.debug(f"Error parsing libraries file: {e}")

    return {}


def _get_theme_breakpoints(drupal_root: Path, theme_name: str, theme_path: Optional[str]) -> Dict:
    """Parse theme breakpoints from .breakpoints.yml file."""
    if not theme_path:
        return {}

    breakpoints_file = Path(theme_path) / f"{theme_name}.breakpoints.yml"
    if breakpoints_file.exists():
        try:
            with open(breakpoints_file, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.debug(f"Error parsing breakpoints file: {e}")

    return {}


def _get_all_themes_with_status(drupal_root: Path) -> list[Dict]:
    """Get all themes with their status."""
    drush_cmd = get_drush_command()

    php_script = """
$theme_handler = \\Drupal::service('theme_handler');
$config = \\Drupal::config('system.theme');
$default_theme = $config->get('default');
$admin_theme = $config->get('admin');

$all_themes = $theme_handler->rebuildThemeData();
$result = [];

foreach ($all_themes as $name => $theme) {
  $result[] = [
    'machine_name' => $name,
    'name' => $theme->info['name'] ?? $name,
    'description' => $theme->info['description'] ?? '',
    'version' => $theme->info['version'] ?? null,
    'core_version_requirement' => $theme->info['core_version_requirement'] ?? null,
    'path' => $theme->getPath(),
    'installed' => $theme->status == 1,
    'is_default' => $name === $default_theme,
    'is_admin' => $name === $admin_theme,
    'base_theme' => $theme->info['base theme'] ?? null,
  ];
}

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
        logger.debug(f"Error getting themes with status: {e}")

    return []


def _find_themes_filesystem(drupal_root: Path) -> Dict[str, str]:
    """Fallback: find themes by searching filesystem."""
    themes = {}
    search_paths = [
        drupal_root / "themes",
        drupal_root / "web" / "themes",
        drupal_root / "core" / "themes",
    ]

    for search_path in search_paths:
        if not search_path.exists():
            continue

        for item in search_path.rglob("*.info.yml"):
            theme_name = item.stem
            themes[theme_name] = str(item.parent)

    return themes
