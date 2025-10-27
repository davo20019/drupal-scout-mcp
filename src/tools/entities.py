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


@mcp.tool()
def get_entity_references(
    entity_type: str,
    bundle: Optional[str] = None,
    field_name: Optional[str] = None,
    limit: int = 50,
) -> str:
    """
    Show where entities are referenced by other entities.

    Finds which content types, nodes, or other entities reference specific bundles.
    Perfect for answering "where are these used?" or "which blog posts use this category?"

    Args:
        entity_type: The entity type to analyze (e.g., "node", "taxonomy_term", "media")
        bundle: Optional bundle to filter (e.g., "article", "blog_post", "tags")
        field_name: Optional field name to filter (e.g., "field_category", "field_tags")
        limit: Maximum number of references to show per type (default 50)

    Returns:
        List of parent entities that reference the specified entities

    Examples:
        get_entity_references("taxonomy_term", "tags")  # Where are tags used?
        get_entity_references("node", "article")  # What references articles?
        get_entity_references("media", field_name="field_hero_image")  # What uses this image field?
        get_entity_references("node", "blog_post", "field_category")  # Blog posts with categories
    """
    try:
        from src.core.config import load_config
        from src.core.drush import get_drush_command
        from src.core.database import verify_database_connection
        import subprocess

        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))
        if not drupal_root.exists():
            return "❌ ERROR: Drupal root not found"

        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return f"❌ ERROR: Database required\n{db_msg}"

        drush_cmd = get_drush_command()

        # PHP script to find entity references
        php = f"""
$limit = {limit};
$target_entity_type = "{entity_type}";
$target_bundle = {f'"{bundle}"' if bundle else 'NULL'};
$target_field = {f'"{field_name}"' if field_name else 'NULL'};

// Find all entity reference fields that point to our target entity type
$field_map = \\Drupal::service('entity_field.manager')->getFieldMapByFieldType('entity_reference');
$results = [];

foreach ($field_map as $referencing_entity_type => $fields) {{
  foreach ($fields as $referencing_field_name => $field_info) {{
    // If field filter is set, skip if this isn't the field we want
    if ($target_field && $referencing_field_name !== $target_field) {{
      continue;
    }}

    // Load field storage config to check target type
    $field_storage = \\Drupal::entityTypeManager()
      ->getStorage('field_storage_config')
      ->load($referencing_entity_type . '.' . $referencing_field_name);

    if (!$field_storage) {{
      continue;
    }}

    $storage_settings = $field_storage->getSettings();
    $field_target_type = $storage_settings['target_type'] ?? NULL;

    // Skip if this field doesn't reference our target entity type
    if ($field_target_type !== $target_entity_type) {{
      continue;
    }}

    // Load field configs to check target bundles
    $field_configs = \\Drupal::entityTypeManager()
      ->getStorage('field_config')
      ->loadByProperties(['field_name' => $referencing_field_name]);

    foreach ($field_configs as $field_config) {{
      $settings = $field_config->getSettings();
      $handler_settings = $settings['handler_settings'] ?? [];
      $allowed_bundles = $handler_settings['target_bundles'] ?? [];

      // If bundle filter is set, skip if this field doesn't allow it
      if ($target_bundle && !empty($allowed_bundles) && !in_array($target_bundle, $allowed_bundles)) {{
        continue;
      }}

      // Query entities that use this field
      $query = \\Drupal::entityQuery($referencing_entity_type)
        ->accessCheck(FALSE)
        ->condition($referencing_field_name, NULL, 'IS NOT NULL')
        ->range(0, $limit);

      $entity_ids = $query->execute();

      if (!empty($entity_ids)) {{
        $entities = \\Drupal::entityTypeManager()
          ->getStorage($referencing_entity_type)
          ->loadMultiple($entity_ids);

        foreach ($entities as $entity) {{
          $field_value = $entity->get($referencing_field_name)->getValue();

          foreach ($field_value as $item) {{
            if (isset($item['target_id'])) {{
              // Load the referenced entity to check its bundle
              $referenced_entity = \\Drupal::entityTypeManager()
                ->getStorage($target_entity_type)
                ->load($item['target_id']);

              if ($referenced_entity) {{
                $referenced_bundle = $referenced_entity->bundle();

                // Apply bundle filter
                if ($target_bundle && $referenced_bundle !== $target_bundle) {{
                  continue;
                }}

                $entity_label = $entity->label() ?? 'Untitled';
                $entity_bundle = $entity->bundle();
                $referenced_label = $referenced_entity->label() ?? 'Untitled';

                $key = "$referencing_entity_type|$entity_bundle|$target_entity_type|$referenced_bundle|$referencing_field_name";
                if (!isset($results[$key])) {{
                  $results[$key] = [
                    'referencing_entity_type' => $referencing_entity_type,
                    'referencing_bundle' => $entity_bundle,
                    'target_entity_type' => $target_entity_type,
                    'target_bundle' => $referenced_bundle,
                    'field_name' => $referencing_field_name,
                    'count' => 0,
                    'examples' => []
                  ];
                }}

                $results[$key]['count']++;
                if (count($results[$key]['examples']) < 5) {{
                  $results[$key]['examples'][] = $entity_label . ' (' . $entity->id() . ') → ' . $referenced_label;
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}

// Output results
foreach ($results as $data) {{
  echo $data['referencing_entity_type'] . '|' . $data['referencing_bundle'] . '|' . $data['target_entity_type'] . '|' . $data['target_bundle'] . '|' . $data['field_name'] . '|' . $data['count'] . '|' . implode(';', $data['examples']) . "\\n";
}}
"""

        result = subprocess.run(
            drush_cmd + ["eval", php],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(drupal_root),
        )

        if result.returncode != 0:
            return f"❌ ERROR: {result.stderr}"

        # Parse results
        output = []
        title_parts = [f"📍 ENTITY REFERENCES: {entity_type}"]
        if bundle:
            title_parts.append(f".{bundle}")
        if field_name:
            title_parts.append(f" (field: {field_name})")
        output.append("".join(title_parts))
        output.append("=" * 80)
        output.append("")

        if not result.stdout.strip():
            output.append(f"No references found to {entity_type}")
            if bundle:
                output.append(f"\nℹ️  The '{bundle}' bundle may not be referenced anywhere,")
                output.append("   or it may not exist in the system.")
            return "\n".join(output)

        # Group by target bundle
        by_target = {}
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 7:
                    ref_entity_type = parts[0]
                    ref_bundle = parts[1]
                    # target_entity_type = parts[2]  # Not needed, already known
                    target_bundle = parts[3]
                    field = parts[4]
                    count = parts[5]
                    examples = parts[6].split(";") if parts[6] else []

                    if target_bundle not in by_target:
                        by_target[target_bundle] = []

                    by_target[target_bundle].append(
                        {
                            "ref_entity_type": ref_entity_type,
                            "ref_bundle": ref_bundle,
                            "field_name": field,
                            "count": int(count),
                            "examples": examples,
                        }
                    )

        # Format output
        for target_bundle, references in sorted(by_target.items()):
            output.append(f"TARGET: {entity_type}.{target_bundle}")
            output.append("-" * 80)

            for ref in references:
                output.append(
                    f"\n  📦 Referenced by: {ref['ref_entity_type']}.{ref['ref_bundle']} (field: {ref['field_name']})"
                )
                output.append(f"     {ref['count']} reference(s)")

                if ref["examples"]:
                    output.append("     Examples:")
                    for example in ref["examples"][:5]:
                        output.append(f"       • {example}")

            output.append("")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting entity references")
        return f"❌ ERROR: {str(e)}"


@mcp.tool()
def get_entity_info(entity_type: str, entity_id: int) -> str:
    """
    Get detailed information about a specific entity (node, user, term, etc.).

    Perfect for answering "give me info about node 56" or "what is taxonomy term 12?"

    Args:
        entity_type: The entity type (e.g., "node", "user", "taxonomy_term", "media", "paragraph")
        entity_id: The entity ID

    Returns:
        Comprehensive entity information including:
        - Title/label and basic info
        - Bundle type
        - Created/changed dates
        - Author/owner
        - Published status
        - All field values
        - Referenced entities (with labels)
        - URL/path

    Examples:
        get_entity_info("node", 56)
        get_entity_info("taxonomy_term", 12)
        get_entity_info("user", 1)
        get_entity_info("media", 45)
    """
    try:
        from src.core.config import load_config
        from src.core.drush import get_drush_command
        from src.core.database import verify_database_connection
        import subprocess

        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))
        if not drupal_root.exists():
            return "❌ ERROR: Drupal root not found"

        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return f"❌ ERROR: Database required\n{db_msg}"

        drush_cmd = get_drush_command()

        # PHP script to get entity details
        php = f"""
$entity_type = "{entity_type}";
$entity_id = {entity_id};

try {{
  $entity = \\Drupal::entityTypeManager()->getStorage($entity_type)->load($entity_id);

  if (!$entity) {{
    echo json_encode(['_not_found' => true]);
    exit;
  }}

  $data = [
    'id' => $entity->id(),
    'uuid' => $entity->uuid(),
    'label' => $entity->label() ?? 'Untitled',
    'bundle' => $entity->bundle(),
    'entity_type' => $entity->getEntityTypeId(),
  ];

  // Language
  if ($entity->hasField('langcode')) {{
    $data['language'] = $entity->get('langcode')->value;
  }}

  // Created/changed timestamps
  if (method_exists($entity, 'getCreatedTime')) {{
    $data['created'] = date('Y-m-d H:i:s', $entity->getCreatedTime());
  }}
  if (method_exists($entity, 'getChangedTime')) {{
    $data['changed'] = date('Y-m-d H:i:s', $entity->getChangedTime());
  }}

  // Published status
  if (method_exists($entity, 'isPublished')) {{
    $data['published'] = $entity->isPublished();
  }}

  // Owner/author
  if (method_exists($entity, 'getOwner')) {{
    $owner = $entity->getOwner();
    $data['owner'] = $owner->label() . ' (' . $owner->id() . ')';
  }}

  // URL/path
  if ($entity->hasLinkTemplate('canonical')) {{
    $url = $entity->toUrl('canonical', ['absolute' => false])->toString();
    $data['path'] = $url;
  }}

  // Get all fields
  $fields = [];
  $field_definitions = $entity->getFieldDefinitions();

  foreach ($field_definitions as $field_name => $field_definition) {{
    // Skip base fields that we already covered
    if (in_array($field_name, ['id', 'uuid', 'langcode', 'created', 'changed', 'status', 'uid', 'title', 'name'])) {{
      continue;
    }}

    if (!$entity->hasField($field_name)) {{
      continue;
    }}

    $field = $entity->get($field_name);
    if ($field->isEmpty()) {{
      continue;
    }}

    $field_type = $field_definition->getType();
    $field_label = $field_definition->getLabel();
    $values = [];

    foreach ($field->getValue() as $item) {{
      if (isset($item['target_id'])) {{
        // Entity reference
        $referenced_entity = \\Drupal::entityTypeManager()
          ->getStorage($field->getSetting('target_type'))
          ->load($item['target_id']);
        if ($referenced_entity) {{
          $values[] = $referenced_entity->label() . ' (' . $item['target_id'] . ')';
        }} else {{
          $values[] = 'Deleted (' . $item['target_id'] . ')';
        }}
      }} elseif (isset($item['value'])) {{
        // Simple value
        $value = $item['value'];
        // Truncate long text
        if (is_string($value) && strlen($value) > 200) {{
          $value = substr($value, 0, 200) . '...';
        }}
        $values[] = $value;
      }} elseif (isset($item['uri'])) {{
        // Link/file
        $values[] = $item['uri'];
      }} else {{
        // Complex field - show first key
        $first_key = array_key_first($item);
        if ($first_key) {{
          $values[] = $first_key . ': ' . $item[$first_key];
        }}
      }}
    }}

    if (!empty($values)) {{
      $fields[] = [
        'name' => $field_name,
        'label' => (string)$field_label,
        'type' => $field_type,
        'values' => $values
      ];
    }}
  }}

  $data['fields'] = $fields;

  echo json_encode($data, JSON_PRETTY_PRINT);

}} catch (\\Exception $e) {{
  echo json_encode(['_error' => true, '_message' => $e->getMessage()]);
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

        # Parse JSON result
        import json

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"❌ ERROR: Invalid response from drush\n{result.stdout}"

        # Check if entity not found
        if data.get("_not_found"):
            return f"❌ ERROR: {entity_type} with ID {entity_id} not found"

        # Check for error
        if data.get("_error"):
            return f"❌ ERROR: {data.get('_message', 'Unknown error')}"

        # Format output
        output = []
        output.append(f"📄 {entity_type.upper()}: {data['label']}")
        output.append("=" * 80)
        output.append("")

        # Basic info
        output.append("BASIC INFORMATION:")
        output.append(f"  ID: {data['id']}")
        output.append(f"  UUID: {data['uuid']}")
        output.append(f"  Type: {entity_type}.{data['bundle']}")

        if "language" in data:
            output.append(f"  Language: {data['language']}")

        if "published" in data:
            status = "Published" if data["published"] else "Unpublished"
            output.append(f"  Status: {status}")

        if "created" in data:
            output.append(f"  Created: {data['created']}")

        if "changed" in data:
            output.append(f"  Changed: {data['changed']}")

        if "owner" in data:
            output.append(f"  Author: {data['owner']}")

        if "path" in data:
            output.append(f"  Path: {data['path']}")

        output.append("")

        # Fields
        if data.get("fields"):
            output.append(f"FIELDS ({len(data['fields'])}):")
            for field in data["fields"]:
                output.append(f"\n  {field['label']} ({field['name']})")
                output.append(f"    Type: {field['type']}")

                values = field["values"]
                if len(values) == 1:
                    output.append(f"    Value: {values[0]}")
                else:
                    output.append(f"    Values ({len(values)}):")
                    for idx, value in enumerate(values[:10], 1):
                        output.append(f"      {idx}. {value}")
                    if len(values) > 10:
                        output.append(f"      ... and {len(values) - 10} more")
        else:
            output.append("FIELDS: None")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting entity info")
        return f"❌ ERROR: {str(e)}"
