"""
Entity and field tools for Drupal Scout MCP server.

This module provides comprehensive tools for inspecting Drupal entity structures,
fields, and displays. Uses drush-first approach for accuracy, with file-based
fallback when drush is unavailable.

Tools:
- get_entity_structure: Get entity bundles, fields, and display configs
- get_field_info: Comprehensive field information and usage across bundles
"""

from pathlib import Path
from typing import List, Optional
import logging

# Import MCP instance from server (used for @mcp.tool() decorator)
from server import mcp

# Import core utilities
from src.core.config import get_config, ensure_indexed
from src.core.drush import run_drush_command

logger = logging.getLogger(__name__)


@mcp.tool()
def get_entity_structure(entity_type: str) -> str:
    """
    Get comprehensive structure information for a Drupal entity type.

    **USE THIS TOOL** for any questions about content types, bundles, or entity fields.

    This tool answers questions like:
    - "What are the content types?" → Use entity_type="node"
    - "What content types are created?" → Use entity_type="node"
    - "How many content types do we have?" → Use entity_type="node"
    - "List all content types" → Use entity_type="node"
    - "What bundles exist for nodes?" → Use entity_type="node"
    - "What fields does the Article content type have?" → Use entity_type="node"
    - "What are all the content types and their fields?" → Use entity_type="node"
    - "How many taxonomy vocabularies exist?" → Use entity_type="taxonomy_term"
    - "What fields does the user entity have?" → Use entity_type="user"

    NOTE: In Drupal, "content types" are bundles of the "node" entity type.
    Always use entity_type="node" for content type questions.

    Returns information about:
    - Bundles (e.g., content types for nodes, vocabularies for taxonomy)
    - Fields for each bundle (name, type, required/optional)
    - View displays and their configurations
    - Form displays and their widget configurations
    - Entity type definition (via drush if available)

    Saves significant tokens by combining what would require multiple commands:
    - drush ev for entity type info
    - grep for field configs
    - grep for view/form displays
    - Multiple file searches

    Args:
        entity_type: Machine name of entity type
                    - "node" for content types
                    - "user" for user profiles
                    - "taxonomy_term" for vocabularies
                    - "media" for media types
                    - "paragraph" for paragraph types

    Returns:
        Structured information about entity bundles, fields, and displays
    """
    ensure_indexed()

    logger.info(f"Getting entity structure for: {entity_type}")

    drupal_root = Path(get_config().get("drupal_root"))

    # Try to get entity info from drush first (most accurate)
    entity_info = _get_entity_info_from_drush(entity_type)

    # Get field configs from files
    field_configs = _get_field_configs(entity_type, drupal_root)

    # Get view display configs
    view_displays = _get_display_configs(entity_type, "view", drupal_root)

    # Get form display configs
    form_displays = _get_display_configs(entity_type, "form", drupal_root)

    # Format output
    output = [f"📦 **Entity Structure: `{entity_type}`**\n"]

    # Check if entity type was not found
    if entity_info and entity_info.get("_not_found"):
        output.append("⚠️  **Entity Type Not Found**\n")
        output.append(f"The entity type `{entity_type}` does not exist in your Drupal site.\n")
        output.append("**Common reasons:**\n")
        output.append("• The module providing this entity type is not enabled")
        output.append("• The entity type name may be incorrect")
        output.append("• The module needs to be installed first\n")

        # Try to suggest the module name from the entity type
        # Common patterns: webform_submission -> webform, commerce_product -> commerce
        suggested_module = entity_type.split("_")[0]
        output.append("**Suggestions:**\n")
        output.append(f"• Check if `{suggested_module}` module is installed:")
        output.append(f"  `drush pm:list --filter={suggested_module}`")
        output.append("• Enable the module if available:")
        output.append(f"  `drush en {suggested_module} -y`")
        output.append("• Install via composer if not present:")
        output.append(f"  `composer require drupal/{suggested_module}`\n")

        return "\n".join(output)

    # Entity type info (if available from drush)
    if entity_info and not entity_info.get("_not_found"):
        output.append("## Entity Type Information\n")
        output.append(f"**Label:** {entity_info.get('label', 'N/A')}")
        output.append(f"**Provider:** {entity_info.get('provider', 'N/A')}")
        output.append(f"**Bundles:** {', '.join(entity_info.get('bundles', []))}\n")

    # Field information
    if field_configs:
        output.append(f"## Fields ({len(field_configs)})\n")

        # Group by bundle
        bundles = {}
        for field in field_configs:
            bundle = field["bundle"]
            if bundle not in bundles:
                bundles[bundle] = []
            bundles[bundle].append(field)

        for bundle, fields in bundles.items():
            output.append(f"### Bundle: `{bundle}` ({len(fields)} fields)\n")
            for field in fields[:15]:  # Limit to avoid token overload
                field_name = field["field_name"]
                field_type = field.get("type", "unknown")
                required = "required" if field.get("required") else "optional"
                output.append(f"- **`{field_name}`** ({field_type}, {required})")

            if len(fields) > 15:
                output.append(f"  *... and {len(fields) - 15} more fields*")
            output.append("")
    else:
        output.append("## Fields\n")
        output.append("❌ No field configurations found\n")

    # View displays
    if view_displays:
        output.append(f"## View Displays ({len(view_displays)})\n")
        for display in view_displays[:10]:
            output.append(f"- **`{display['bundle']}.{display['mode']}`**")
            if display.get("fields"):
                output.append(f"  Fields: {', '.join(display['fields'][:5])}")
        if len(view_displays) > 10:
            output.append(f"*... and {len(view_displays) - 10} more displays*\n")

    # Form displays
    if form_displays:
        output.append(f"\n## Form Displays ({len(form_displays)})\n")
        for display in form_displays[:10]:
            output.append(f"- **`{display['bundle']}.{display['mode']}`**")
            if display.get("widgets"):
                output.append(f"  Widgets: {', '.join(display['widgets'][:5])}")
        if len(form_displays) > 10:
            output.append(f"*... and {len(form_displays) - 10} more displays*")

    if not field_configs and not view_displays and not form_displays:
        output.append("\n⚠️  **No configuration found for this entity type**\n")
        output.append("**Possible reasons:**")
        output.append("• Entity type doesn't exist")
        output.append("• Configs not exported to config/sync")
        output.append("• Entity type name might be incorrect")

    return "\n".join(output)


def _get_entity_info_from_drush(entity_type: str) -> Optional[dict]:
    """Get entity type info using drush eval."""
    # Try to get entity definition via drush
    php_code = f"""
    $entity_type_manager = \\Drupal::entityTypeManager();
    $definition = $entity_type_manager->getDefinition('{entity_type}');
    echo json_encode([
        'label' => $definition->getLabel()->__toString(),
        'provider' => $definition->getProvider(),
        'bundles' => array_keys(\\Drupal::service('entity_type.bundle.info')->getBundleInfo('{entity_type}'))
    ]);
    """

    result = run_drush_command(["ev", php_code.strip()], timeout=10, return_raw_error=True)

    # Check if drush returned an error
    if result and result.get("_error"):
        error_msg = result.get("_error_message", "")

        # Check if entity type doesn't exist
        if "does not exist" in error_msg or "is not defined" in error_msg:
            logger.debug(f"Entity type '{entity_type}' not found - likely module not enabled")
            return {"_not_found": True, "_error_message": error_msg, "_entity_type": entity_type}

        logger.debug(f"Could not get entity info from drush: {error_msg}")
        return None

    return result


def _get_field_configs(entity_type: str, drupal_root: Path) -> List[dict]:
    """
    Get field configurations for an entity type.

    Tries drush first (most accurate - active config from DB),
    falls back to file parsing if drush unavailable.
    """
    fields = []

    # Try drush first - gets active config from database
    drush_fields = _get_field_configs_from_drush(entity_type)
    if drush_fields:
        return drush_fields

    # Fallback: Parse config files
    logger.debug("Drush unavailable, falling back to file-based config parsing")

    config_locations = [
        drupal_root / "config" / "sync",  # Standard config sync
        drupal_root / "config" / "default",  # Default config
        drupal_root / "sites" / "default" / "config" / "sync",  # Sites-specific
        drupal_root / "recipes",  # Drupal CMS recipes
    ]

    # Look for field.field.{entity_type}.*.yml files
    pattern = f"field.field.{entity_type}.*.yml"

    for config_dir in config_locations:
        if not config_dir.exists():
            continue

        # Use rglob to search recursively (for recipes structure)
        for config_file in config_dir.rglob(pattern):
            try:
                import yaml

                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)

                    if config:
                        fields.append(
                            {
                                "field_name": config.get("field_name"),
                                "bundle": config.get("bundle"),
                                "type": config.get("field_type"),
                                "required": config.get("required", False),
                                "label": config.get("label"),
                            }
                        )
            except Exception as e:
                logger.debug(f"Error parsing {config_file}: {e}")
                continue

    return fields


def _get_field_configs_from_drush(entity_type: str) -> Optional[List[dict]]:
    """Get active field configs from database via drush."""
    try:
        php_code = f"""
        $fields = [];
        $field_configs = \\Drupal::entityTypeManager()
            ->getStorage('field_config')
            ->loadByProperties(['entity_type' => '{entity_type}']);

        foreach ($field_configs as $field_config) {{
            $fields[] = [
                'field_name' => $field_config->getName(),
                'bundle' => $field_config->getTargetBundle(),
                'type' => $field_config->getType(),
                'required' => $field_config->isRequired(),
                'label' => $field_config->getLabel()
            ];
        }}

        echo json_encode($fields);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=15)

        if result and isinstance(result, list):
            return result

        return None
    except Exception as e:
        logger.debug(f"Could not get field configs from drush: {e}")
        return None


def _get_display_configs(entity_type: str, display_type: str, drupal_root: Path) -> List[dict]:
    """
    Get display configurations for an entity type.

    Tries drush first (active config from DB),
    falls back to file parsing if drush unavailable.

    Args:
        entity_type: Entity type machine name
        display_type: "view" or "form"
        drupal_root: Drupal root path
    """
    displays = []

    # Try drush first - gets active config from database
    drush_displays = _get_display_configs_from_drush(entity_type, display_type)
    if drush_displays:
        return drush_displays

    # Fallback: Parse config files
    logger.debug("Drush unavailable, falling back to file-based display config parsing")

    config_locations = [
        drupal_root / "config" / "sync",
        drupal_root / "config" / "default",
        drupal_root / "sites" / "default" / "config" / "sync",
        drupal_root / "recipes",
    ]

    # Look for core.entity_{view|form}_display.{entity_type}.*.yml
    pattern = f"core.entity_{display_type}_display.{entity_type}.*.yml"

    for config_dir in config_locations:
        if not config_dir.exists():
            continue

        # Use rglob to search recursively
        for config_file in config_dir.rglob(pattern):
            try:
                import yaml

                with open(config_file, "r") as f:
                    config = yaml.safe_load(f)

                    if config:
                        # Extract bundle and mode from filename
                        # e.g., core.entity_view_display.node.article.default.yml
                        parts = config_file.stem.split(".")
                        bundle = parts[2] if len(parts) > 2 else "unknown"
                        mode = parts[3] if len(parts) > 3 else "default"

                        display_info = {"bundle": bundle, "mode": mode}

                        # Extract field list
                        content = config.get("content", {})
                        if display_type == "view":
                            display_info["fields"] = list(content.keys())
                        else:  # form
                            display_info["widgets"] = list(content.keys())

                        displays.append(display_info)
            except Exception as e:
                logger.debug(f"Error parsing {config_file}: {e}")
                continue

    return displays


def _get_display_configs_from_drush(entity_type: str, display_type: str) -> Optional[List[dict]]:
    """Get active display configs from database via drush."""
    try:
        storage_type = f"entity_{display_type}_display"
        php_code = f"""
        $displays = [];
        $display_configs = \\Drupal::entityTypeManager()
            ->getStorage('{storage_type}')
            ->loadByProperties(['targetEntityType' => '{entity_type}']);

        foreach ($display_configs as $display) {{
            $content = $display->get('content');
            $displays[] = [
                'bundle' => $display->getTargetBundle(),
                'mode' => $display->getMode(),
                '{"fields" if display_type == "view" else "widgets"}' => array_keys($content)
            ];
        }}

        echo json_encode($displays);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=15)

        if result and isinstance(result, list):
            return result

        return None
    except Exception as e:
        logger.debug(f"Could not get display configs from drush: {e}")
        return None


@mcp.tool()
def get_field_info(field_name: Optional[str] = None, entity_type: Optional[str] = None) -> str:
    """
    Get comprehensive information about Drupal fields.

    **USE THIS TOOL** for questions about fields, where they're used, field types, and data structure.

    This tool answers questions like:
    - "What fields exist in the site?"
    - "Where is the field_image field used?"
    - "What type of field is field_phone_number?"
    - "What fields does the article content type have?"
    - "Do we have a field for storing addresses?"
    - "Show me all email fields"
    - "What content types use field_category?"

    Provides:
    - Field machine names and labels
    - Field types (text, entity_reference, image, etc.)
    - Where fields are used (entity types and bundles)
    - Field settings (required, cardinality, max length, etc.)
    - Storage details (single/multi-value)

    Uses drush-first approach to get active field configs from database,
    falls back to parsing field.field.*.yml and field.storage.*.yml files.

    Saves ~800-1000 tokens vs running multiple drush field commands + greps.

    Args:
        field_name: Optional. Specific field machine name (e.g., "field_image").
                    If omitted, returns summary of all fields.
                    Supports partial matching (e.g., "email" finds field_email, field_user_email)
        entity_type: Optional. Filter fields by entity type.
                     Common values: "node", "user", "taxonomy_term", "media"
                     Example: entity_type="node" shows only node fields

    Returns:
        Formatted field information with usage details
    """
    try:
        drupal_root = Path(get_config().get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ Error: Drupal root not found. Check drupal_root in config."

        # Get field data (drush first, then file fallback)
        fields_data = _get_fields_data(field_name, entity_type, drupal_root)

        if not fields_data:
            if field_name:
                return f"ℹ️ No fields found matching '{field_name}'"
            if entity_type:
                return f"ℹ️ No fields found for entity type '{entity_type}'"
            return "ℹ️ No fields found in this Drupal installation"

        # Format output
        output = []

        if field_name and len(fields_data) == 1:
            # Single field detailed output
            field = fields_data[0]
            output.append(f"🔧 Field: {field.get('label', 'Unknown')} ({field['field_name']})")
            output.append(f"   Type: {field.get('field_type', 'Unknown')}")
            output.append(f"   Entity Type: {field.get('entity_type', 'Unknown')}")

            # Storage info
            cardinality = field.get("cardinality", 1)
            if cardinality == -1:
                output.append("   Storage: Unlimited values")
            elif cardinality == 1:
                output.append("   Storage: Single value")
            else:
                output.append(f"   Storage: Up to {cardinality} values")

            # Settings
            settings_parts = []
            if field.get("required"):
                settings_parts.append("Required")
            if field.get("translatable"):
                settings_parts.append("Translatable")

            max_length = field.get("max_length")
            if max_length:
                settings_parts.append(f"Max length: {max_length}")

            target_type = field.get("target_type")
            if target_type:
                settings_parts.append(f"References: {target_type}")

            if settings_parts:
                output.append(f"   Settings: {', '.join(settings_parts)}")

            # Usage across bundles
            bundles = field.get("bundles", [])
            if bundles:
                output.append(f"\n   Used in {len(bundles)} bundle(s):")
                for bundle in bundles:
                    bundle_label = bundle.get("bundle_label", bundle.get("bundle", "Unknown"))
                    req_indicator = " (required)" if bundle.get("required") else ""
                    output.append(f"   • {bundle_label}{req_indicator}")

            # Description if available
            description = field.get("description")
            if description:
                output.append(f"\n   Description: {description}")

        else:
            # Multiple fields summary
            header = f"🔧 Fields Summary ({len(fields_data)} fields found)"
            if entity_type:
                header += f" - Entity type: {entity_type}"
            if field_name:
                header += f" - Matching: {field_name}"
            output.append(header + "\n")

            # Group by entity type for better readability
            by_entity_type = {}
            for field in fields_data:
                et = field.get("entity_type", "unknown")
                if et not in by_entity_type:
                    by_entity_type[et] = []
                by_entity_type[et].append(field)

            for et, fields in sorted(by_entity_type.items()):
                output.append(f"📦 {et.upper()}:")
                for field in sorted(fields, key=lambda f: f["field_name"]):
                    bundles = field.get("bundles", [])
                    bundle_names = [b.get("bundle", "") for b in bundles]
                    bundles_str = ", ".join(bundle_names[:3])
                    if len(bundle_names) > 3:
                        bundles_str += f" (+{len(bundle_names) - 3} more)"

                    field_label = field.get("label", field["field_name"])
                    field_type = field.get("field_type", "unknown")

                    output.append(f"   • {field_label} ({field['field_name']})")
                    output.append(f"     Type: {field_type} | Bundles: {bundles_str}")
                output.append("")

        result = "\n".join(output)
        return result

    except Exception as e:
        logger.error(f"Error getting field info: {e}")
        return f"❌ Error: {str(e)}"


def _get_fields_data(
    field_name: Optional[str], entity_type: Optional[str], drupal_root: Path
) -> List[dict]:
    """
    Get fields data using drush-first, file-fallback approach.

    Args:
        field_name: Optional field name (supports partial matching)
        entity_type: Optional entity type filter
        drupal_root: Path to Drupal root

    Returns:
        List of field data dictionaries
    """
    # Try drush first - gets active config from database
    drush_fields = _get_fields_from_drush(field_name, entity_type)
    if drush_fields:
        logger.debug(f"Retrieved {len(drush_fields)} fields from drush")
        return drush_fields

    # Fallback: Parse config files
    logger.debug("Drush unavailable, falling back to file-based field config parsing")
    return _get_fields_from_files(field_name, entity_type, drupal_root)


def _get_fields_from_drush(
    field_name: Optional[str], entity_type: Optional[str]
) -> Optional[List[dict]]:
    """Get active field configs from database via drush."""
    try:
        # Build filters
        entity_filter = ""
        if entity_type:
            entity_filter = (
                f"if ($field_config->getTargetEntityTypeId() != '{entity_type}') continue;"
            )

        field_filter = ""
        if field_name:
            # Support partial matching
            field_filter = (
                f"if (strpos($field_config->getName(), '{field_name}') === false) continue;"
            )

        php_code = f"""
        $fields_data = [];

        // Get field storage configs for type and cardinality info
        $field_storages = \\Drupal::entityTypeManager()
            ->getStorage('field_storage_config')
            ->loadMultiple();

        $storage_info = [];
        foreach ($field_storages as $storage) {{
            $storage_info[$storage->getTargetEntityTypeId()][$storage->getName()] = [
                'field_type' => $storage->getType(),
                'cardinality' => $storage->getCardinality(),
                'settings' => $storage->getSettings(),
            ];
        }}

        // Get field configs for usage and settings
        $field_configs = \\Drupal::entityTypeManager()
            ->getStorage('field_config')
            ->loadMultiple();

        foreach ($field_configs as $field_config) {{
            {entity_filter}
            {field_filter}

            $entity_type_id = $field_config->getTargetEntityTypeId();
            $field_name = $field_config->getName();

            // Get storage info
            $storage = $storage_info[$entity_type_id][$field_name] ?? null;

            // Create or find existing field entry
            $field_key = $entity_type_id . '.' . $field_name;

            if (!isset($fields_data[$field_key])) {{
                $settings = $field_config->getSettings();
                $field_entry = [
                    'field_name' => $field_name,
                    'entity_type' => $entity_type_id,
                    'label' => $field_config->getLabel(),
                    'description' => $field_config->getDescription(),
                    'field_type' => $storage['field_type'] ?? 'unknown',
                    'cardinality' => $storage['cardinality'] ?? 1,
                    'translatable' => $field_config->isTranslatable(),
                    'bundles' => []
                ];

                // Add type-specific settings
                if (isset($settings['max_length'])) {{
                    $field_entry['max_length'] = $settings['max_length'];
                }}
                if (isset($settings['target_type'])) {{
                    $field_entry['target_type'] = $settings['target_type'];
                }}

                $fields_data[$field_key] = $field_entry;
            }}

            // Add bundle info
            $bundle = $field_config->getTargetBundle();
            $bundle_entity_type = \\Drupal::entityTypeManager()->getDefinition($entity_type_id);
            $bundle_entity_type_id = $bundle_entity_type->getBundleEntityType();

            $bundle_label = $bundle;
            if ($bundle_entity_type_id) {{
                $bundle_entity = \\Drupal::entityTypeManager()
                    ->getStorage($bundle_entity_type_id)
                    ->load($bundle);
                if ($bundle_entity) {{
                    $bundle_label = $bundle_entity->label();
                }}
            }}

            $fields_data[$field_key]['bundles'][] = [
                'bundle' => $bundle,
                'bundle_label' => $bundle_label,
                'required' => $field_config->isRequired()
            ];
        }}

        echo json_encode(array_values($fields_data));
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=25)

        if result and isinstance(result, list):
            return result

        return None
    except Exception as e:
        logger.debug(f"Could not get fields from drush: {e}")
        return None


def _get_fields_from_files(
    field_name: Optional[str], entity_type: Optional[str], drupal_root: Path
) -> List[dict]:
    """Parse field configs from files as fallback."""
    fields_data = {}

    config_locations = [
        drupal_root / "config" / "sync",
        drupal_root / "config" / "default",
        drupal_root / "sites" / "default" / "config" / "sync",
        drupal_root / "recipes",
    ]

    # First, get field storage configs for type info
    storage_info = {}
    for config_dir in config_locations:
        if not config_dir.exists():
            continue

        for storage_file in config_dir.rglob("field.storage.*.yml"):
            try:
                import yaml

                with open(storage_file, "r") as f:
                    storage_config = yaml.safe_load(f)

                if not storage_config:
                    continue

                entity_type_id = storage_config.get("entity_type", "")
                field_name_storage = storage_config.get("field_name", "")

                if entity_type_id and field_name_storage:
                    key = f"{entity_type_id}.{field_name_storage}"
                    storage_info[key] = {
                        "field_type": storage_config.get("type", "unknown"),
                        "cardinality": storage_config.get("cardinality", 1),
                        "settings": storage_config.get("settings", {}),
                    }
            except Exception as e:
                logger.debug(f"Error parsing {storage_file}: {e}")
                continue

    # Now get field instance configs
    pattern = "field.field.*.yml"
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

                entity_type_id = config.get("entity_type", "")
                field_name_config = config.get("field_name", "")
                bundle = config.get("bundle", "")

                # Apply filters
                if entity_type and entity_type_id != entity_type:
                    continue

                if field_name and field_name not in field_name_config:
                    continue

                # Get storage info
                storage_key = f"{entity_type_id}.{field_name_config}"
                storage = storage_info.get(storage_key, {})

                # Create or update field entry
                if storage_key not in fields_data:
                    settings = config.get("settings", {})
                    field_entry = {
                        "field_name": field_name_config,
                        "entity_type": entity_type_id,
                        "label": config.get("label", field_name_config),
                        "description": config.get("description", ""),
                        "field_type": storage.get("field_type", "unknown"),
                        "cardinality": storage.get("cardinality", 1),
                        "translatable": config.get("translatable", False),
                        "bundles": [],
                    }

                    # Add type-specific settings
                    if "max_length" in settings:
                        field_entry["max_length"] = settings["max_length"]
                    if "target_type" in settings:
                        field_entry["target_type"] = settings["target_type"]

                    fields_data[storage_key] = field_entry

                # Add bundle info
                fields_data[storage_key]["bundles"].append(
                    {
                        "bundle": bundle,
                        "bundle_label": bundle,
                        "required": config.get("required", False),
                    }
                )

            except Exception as e:
                logger.debug(f"Error parsing {config_file}: {e}")
                continue

    return list(fields_data.values())
