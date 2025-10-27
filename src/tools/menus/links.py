"""Menu link discovery tools for Drupal Scout MCP."""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from src.core.config import load_config
from src.core.database import verify_database_connection
from src.core.drush import get_drush_command
from server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def get_menu_link_info(path: str) -> str:
    """
    Find menu link(s) for a given path and show menu and edit links.

    Perfect for answering "give me the menu and edit link for /blog"

    Handles:
    - Internal paths (/blog, /node/123)
    - Path aliases (resolves /blog to /node/123 automatically)
    - Full site URLs (https://drupalcms.ddev.site/blog)
    - External URLs (https://example.com, https://twitter.com/user)

    Args:
        path: The path/URL to search for
               - Internal path: "/blog", "/node/123", "/admin/content"
               - Path alias: "/blog" (finds menu with /node/123)
               - Site URL: "https://drupalcms.ddev.site/blog"
               - External URL: "https://example.com"

    Returns:
        Menu information including:
        - Menu name and label
        - Menu link title
        - Menu link edit URL
        - Internal path vs alias (for Drupal paths)
        - External URL indicator
        - Parent menu items (breadcrumb)
        - Link weight and enabled status

    Examples:
        get_menu_link_info("/blog")
        get_menu_link_info("https://drupalcms.ddev.site/blog")
        get_menu_link_info("/node/123")
        get_menu_link_info("https://example.com")  # External link
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))
        if not drupal_root.exists():
            return "❌ ERROR: Drupal root not found"

        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return f"❌ ERROR: Database required\n{db_msg}"

        drush_cmd = get_drush_command()

        # Handle both internal paths and external URLs
        is_external_search = path.startswith("http://") or path.startswith("https://")

        if is_external_search:
            # For external URLs, we'll search for the full URL
            # But also try the path component in case it's the site's own domain
            from urllib.parse import urlparse

            parsed = urlparse(path)
            clean_path = parsed.path if parsed.path else "/"
            full_url = path
        else:
            clean_path = path
            full_url = None

        # Ensure path starts with /
        if clean_path and not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        # PHP script to find menu links
        php = f"""
$search_path = "{clean_path}";
$external_url = {f'"{full_url}"' if full_url else 'NULL'};

// STEP 1: Resolve path alias to internal path
$alias_manager = \\Drupal::service('path_alias.manager');
$path_validator = \\Drupal::service('path.validator');

// Try to get internal path from alias
$internal_path_from_alias = $alias_manager->getPathByAlias($search_path);
$search_paths = [$search_path];

// If alias resolved to something different, add it to search paths
if ($internal_path_from_alias !== $search_path) {{
    $search_paths[] = $internal_path_from_alias;
}}

// Also try to validate as URL and get route
$url_object = $path_validator->getUrlIfValid($search_path);
$search_route_name = NULL;
$search_route_params = NULL;

if ($url_object && $url_object->isRouted()) {{
    $search_route_name = $url_object->getRouteName();
    $search_route_params = $url_object->getRouteParameters();

    // For node paths, add /node/NID format
    if ($search_route_name === 'entity.node.canonical' && isset($search_route_params['node'])) {{
        $search_paths[] = '/node/' . $search_route_params['node'];
    }}
}}

// STEP 2: Find menu links that match any of our search paths
// Get all menus
$menu_storage = \\Drupal::entityTypeManager()->getStorage('menu');
$menus = $menu_storage->loadMultiple();

$menu_tree = \\Drupal::menuTree();
$parameters = new \\Drupal\\Core\\Menu\\MenuTreeParameters();

$results = [];
$all_menu_links = [];

// Collect all menu links from all menus
foreach ($menus as $menu_id => $menu) {{
    $tree = $menu_tree->load($menu_id, $parameters);
    foreach ($tree as $element) {{
        $menu_link = $element->link;
        $menu_link_id = $menu_link->getPluginId();
        $all_menu_links[$menu_link_id] = [
            'link' => $menu_link,
            'menu_id' => $menu_id,
            'menu_label' => $menu->label(),
        ];
    }}
}}

foreach ($all_menu_links as $menu_link_id => $data) {{
    $menu_link = $data['link'];
    $menu_id = $data['menu_id'];
    $menu_label = $data['menu_label'];
    $url = $menu_link->getUrlObject();

    try {{
        $link_path = $url->toString();

        // Also get internal path for routed URLs
        if ($url->isRouted()) {{
            $route_name = $url->getRouteName();
            $route_params = $url->getRouteParameters();

            // Build internal path for comparison
            if ($route_name === 'entity.node.canonical' && isset($route_params['node'])) {{
                $internal_path = '/node/' . $route_params['node'];
            }} else {{
                $internal_path = $link_path;
            }}
        }} else {{
            $internal_path = $link_path;
        }}

        // Get alias for this internal path too
        $link_alias = $alias_manager->getAliasByPath($internal_path);

        // Check if this link matches any of our search paths
        $match = false;

        // Check for external URL match first
        if ($external_url && !$url->isRouted()) {{
            // This is an external link in the menu
            $external_link_url = $link_path;
            if ($external_link_url === $external_url ||
                rtrim($external_link_url, '/') === rtrim($external_url, '/')) {{
                $match = true;
            }}
        }}

        // Check route-based match (most reliable for entities)
        if (!$match && $search_route_name && $url->isRouted()) {{
            $link_route_name = $route_name;

            if ($link_route_name === $search_route_name) {{
                // Same route, check parameters
                if ($search_route_name === 'entity.node.canonical') {{
                    // For nodes, compare node ID
                    if (isset($route_params['node']) && isset($search_route_params['node']) &&
                        $route_params['node'] == $search_route_params['node']) {{
                        $match = true;
                    }}
                }} elseif ($search_route_name === 'entity.taxonomy_term.canonical') {{
                    if (isset($route_params['taxonomy_term']) && isset($search_route_params['taxonomy_term']) &&
                        $route_params['taxonomy_term'] == $search_route_params['taxonomy_term']) {{
                        $match = true;
                    }}
                }} else {{
                    // For other routes, do generic param comparison
                    $match = true;
                    foreach ($search_route_params as $key => $value) {{
                        if (!isset($route_params[$key]) || $route_params[$key] != $value) {{
                            $match = false;
                            break;
                        }}
                    }}
                }}
            }}
        }}

        // Check internal paths
        if (!$match) {{
            foreach ($search_paths as $search) {{
                if ($link_path === $search ||
                    $internal_path === $search ||
                    $link_alias === $search ||
                    rtrim($link_path, '/') === rtrim($search, '/') ||
                    rtrim($internal_path, '/') === rtrim($search, '/') ||
                    rtrim($link_alias, '/') === rtrim($search, '/')) {{
                    $match = true;
                    break;
                }}
            }}
        }}

        if ($match) {{
            // We already have menu_id and menu_label from the data structure
            $menu_name = $menu_id;

            // Get parent chain
            $parent_chain = [];
            $parent_id = $menu_link->getParent();
            $menu_link_manager = \\Drupal::service('plugin.manager.menu.link');
            while ($parent_id) {{
                try {{
                    $parent_link = $menu_link_manager->createInstance($parent_id);
                    if ($parent_link) {{
                        $parent_chain[] = [
                            'title' => $parent_link->getTitle(),
                            'id' => $parent_id,
                        ];
                        $parent_id = $parent_link->getParent();
                    }} else {{
                        break;
                    }}
                }} catch (\\Exception $e) {{
                    break;
                }}
            }}
            $parent_chain = array_reverse($parent_chain);

            $result = [
                'title' => $menu_link->getTitle(),
                'menu_name' => $menu_name,
                'menu_label' => $menu_label,
                'link_id' => $menu_link_id,
                'path' => $link_path,
                'internal_path' => $internal_path,
                'alias' => $link_alias,
                'is_external' => !$url->isRouted(),
                'weight' => $menu_link->getWeight(),
                'enabled' => $menu_link->isEnabled(),
                'expanded' => $menu_link->isExpanded(),
                'parent_chain' => $parent_chain,
            ];

            // Try to get edit URL for content entity menu links
            if (strpos($menu_link_id, 'menu_link_content:') === 0) {{
                $uuid = str_replace('menu_link_content:', '', $menu_link_id);

                // Load the menu link content entity
                $menu_link_storage = \\Drupal::entityTypeManager()->getStorage('menu_link_content');
                $menu_link_entities = $menu_link_storage->loadByProperties(['uuid' => $uuid]);

                if (!empty($menu_link_entities)) {{
                    $menu_link_entity = reset($menu_link_entities);
                    $edit_url = '/admin/structure/menu/item/' . $menu_link_entity->id() . '/edit';
                    $result['edit_url'] = $edit_url;
                    $result['entity_id'] = $menu_link_entity->id();
                }}
            }}

            $results[] = $result;
        }}
    }} catch (\\Exception $e) {{
        // Skip links that can't be processed
        continue;
    }}
}}

if (empty($results)) {{
    echo json_encode(['_not_found' => true]);
}} else {{
    echo json_encode($results, JSON_PRETTY_PRINT);
}}
"""

        result = subprocess.run(
            drush_cmd + ["eval", php],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(drupal_root),
        )

        if result.returncode != 0:
            return f"❌ ERROR: {result.stderr}"

        data = json.loads(result.stdout.strip())

        # Check if not found
        if isinstance(data, dict) and data.get("_not_found"):
            output = []
            output.append("NO MENU LINKS FOUND")
            output.append("=" * 80)
            output.append("")
            output.append(f"Path: {clean_path}")
            output.append("")
            output.append("This path is not in any menu.")
            output.append("")
            output.append("💡 Tips:")
            output.append("- Check if the path is correct")
            output.append("- Try the actual node path (e.g., /node/123)")
            output.append("- Path aliases might not be in menus")
            output.append("- Use list_menu_links() to see all menu items")
            return "\n".join(output)

        # Format output
        output = []
        output.append(f"🔗 MENU LINK INFO: {clean_path}")
        output.append("=" * 80)
        output.append("")
        output.append(f"Found {len(data)} menu link(s):")
        output.append("")

        for idx, link in enumerate(data, 1):
            if len(data) > 1:
                output.append(f"LINK #{idx}")
                output.append("-" * 80)

            output.append(f"Title: {link['title']}")
            output.append(f"Menu: {link['menu_label']} ({link['menu_name']})")

            # Show path info
            if link.get("is_external"):
                output.append(f"External URL: {link['path']}")
            else:
                # Show internal path and alias if different
                if link.get("internal_path") and link["internal_path"] != link["path"]:
                    output.append(f"Internal path: {link['internal_path']}")
                if link.get("alias") and link["alias"] != link["internal_path"]:
                    output.append(f"Alias: {link['alias']}")
                if not link.get("internal_path") or link["path"] == link["internal_path"]:
                    output.append(f"Path: {link['path']}")

            output.append("")

            # Edit link
            if "edit_url" in link:
                output.append("✏️  EDIT LINK:")
                output.append(f"   {link['edit_url']}")
                output.append(f"   Entity ID: {link['entity_id']}")
            else:
                output.append("✏️  EDIT LINK:")
                output.append("   Not available (system-defined link, not editable via UI)")
            output.append("")

            # Status
            status = "Enabled" if link["enabled"] else "Disabled"
            expanded = "Yes" if link["expanded"] else "No"
            output.append(f"Status: {status}")
            output.append(f"Weight: {link['weight']}")
            output.append(f"Expanded: {expanded}")
            output.append("")

            # Parent chain
            if link["parent_chain"]:
                output.append("Parent menu items (breadcrumb):")
                for parent in link["parent_chain"]:
                    output.append(f"  → {parent['title']}")
                output.append(f"  → {link['title']} (current)")
                output.append("")
            else:
                output.append("Parent: Top-level menu item")
                output.append("")

            output.append(f"Link ID: {link['link_id']}")

            if idx < len(data):
                output.append("")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting menu link info")
        return f"❌ ERROR: {str(e)}"


@mcp.tool()
def list_menu_links(menu_name: Optional[str] = None, enabled_only: bool = True) -> str:
    """
    List all menu links, optionally filtered by menu.

    Args:
        menu_name: Optional menu machine name (e.g., "main", "footer", "admin")
        enabled_only: Only show enabled links (default: True)

    Returns:
        Hierarchical list of menu links

    Examples:
        list_menu_links("main")
        list_menu_links("footer", enabled_only=False)
        list_menu_links()  # All menus
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))
        if not drupal_root.exists():
            return "❌ ERROR: Drupal root not found"

        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return f"❌ ERROR: Database required\n{db_msg}"

        drush_cmd = get_drush_command()

        # PHP script to list menu links
        php = f"""
$menu_filter = {f'"{menu_name}"' if menu_name else 'NULL'};
$enabled_only = {str(enabled_only).lower()};

$menu_link_manager = \\Drupal::service('plugin.manager.menu.link');
$menu_tree = \\Drupal::menuTree();

// Get menus to process
if ($menu_filter) {{
    $menus = [$menu_filter];
}} else {{
    $menu_storage = \\Drupal::entityTypeManager()->getStorage('menu');
    $menu_entities = $menu_storage->loadMultiple();
    $menus = array_keys($menu_entities);
}}

$results = [];

foreach ($menus as $menu_name) {{
    $parameters = $menu_tree->getCurrentRouteMenuTreeParameters($menu_name);
    $parameters->onlyEnabledLinks();

    $tree = $menu_tree->load($menu_name, $parameters);

    $menu_storage = \\Drupal::entityTypeManager()->getStorage('menu');
    $menu = $menu_storage->load($menu_name);
    $menu_label = $menu ? $menu->label() : $menu_name;

    $links = [];
    _extract_menu_links($tree, $links, 0, $enabled_only);

    if (!empty($links)) {{
        $results[$menu_name] = [
            'label' => $menu_label,
            'links' => $links,
        ];
    }}
}}

function _extract_menu_links($tree, &$links, $depth, $enabled_only) {{
    foreach ($tree as $element) {{
        $link = $element->link;

        if ($enabled_only && !$link->isEnabled()) {{
            continue;
        }}

        try {{
            $url = $link->getUrlObject();
            $path = $url->toString();
        }} catch (\\Exception $e) {{
            $path = '(invalid)';
        }}

        $links[] = [
            'title' => $link->getTitle(),
            'path' => $path,
            'weight' => $link->getWeight(),
            'enabled' => $link->isEnabled(),
            'depth' => $depth,
        ];

        if ($element->hasChildren) {{
            _extract_menu_links($element->subtree, $links, $depth + 1, $enabled_only);
        }}
    }}
}}

echo json_encode($results, JSON_PRETTY_PRINT);
"""

        result = subprocess.run(
            drush_cmd + ["eval", php],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(drupal_root),
        )

        if result.returncode != 0:
            return f"❌ ERROR: {result.stderr}"

        data = json.loads(result.stdout.strip())

        # Format output
        output = []
        if menu_name:
            output.append(f"📋 MENU LINKS: {menu_name}")
        else:
            output.append("📋 ALL MENU LINKS")
        output.append("=" * 80)
        output.append("")

        if not data:
            output.append("No menu links found.")
            if menu_name:
                output.append(f"\nMenu '{menu_name}' may not exist or has no links.")
            return "\n".join(output)

        for menu_id, menu_data in data.items():
            output.append(f"MENU: {menu_data['label']} ({menu_id})")
            output.append("-" * 80)
            output.append("")

            for link in menu_data["links"]:
                indent = "  " * link["depth"]
                status = "" if link["enabled"] else " [DISABLED]"
                output.append(f"{indent}• {link['title']}{status}")
                output.append(f"{indent}  Path: {link['path']}")
                output.append(f"{indent}  Weight: {link['weight']}")

            output.append("")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error listing menu links")
        return f"❌ ERROR: {str(e)}"
