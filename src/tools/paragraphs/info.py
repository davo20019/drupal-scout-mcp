"""
Paragraph type information tools for Drupal Scout MCP.

Provides paragraph type listing and detailed analysis.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

# Import from core modules
from src.core.config import load_config
from src.core.drush import get_drush_command
from src.core.database import verify_database_connection

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def list_paragraph_types() -> str:
    """
    List all paragraph types with overview information.

    Shows quick overview of all paragraph types including field counts,
    usage statistics, and customization status (templates/hooks).

    Perfect for:
    - Quick paragraph inventory
    - Finding existing paragraph types before creating new ones
    - Identifying unused or rarely used paragraphs
    - Understanding customization status

    Returns:
        List of all paragraph types with summary information

    Examples:
        list_paragraph_types()
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

        # Get paragraph types
        paragraph_types = _get_paragraph_types(drupal_root)

        if not paragraph_types:
            return "No paragraph types found. Is the Paragraphs module enabled?"

        # Build output
        output = []
        output.append("📦 PARAGRAPH TYPES")
        output.append("=" * 80)
        output.append("")
        output.append(f"Total: {len(paragraph_types)} paragraph type(s)")
        output.append("")

        # Sort by usage count (most used first)
        sorted_types = sorted(paragraph_types, key=lambda x: x.get("usage_count", 0), reverse=True)

        for pt in sorted_types:
            bundle = pt["bundle"]
            label = pt["label"]
            field_count = pt["field_count"]
            usage_count = pt.get("usage_count", 0)
            has_template = pt.get("has_template", False)
            has_hook = pt.get("has_hook", False)

            output.append(f"📋 {label} ({bundle})")
            output.append(f"   Fields: {field_count} | Usage: {usage_count} entities")

            customizations = []
            if has_template:
                customizations.append("Custom template")
            if has_hook:
                customizations.append("Preprocess hook")

            if customizations:
                output.append(f"   Customized: {', '.join(customizations)}")

            if usage_count == 0:
                output.append("   ⚠️  UNUSED - No paragraph entities found")

            output.append("")

        output.append("💡 Tips:")
        output.append("   - Use describe_paragraph_type('bundle') for detailed info")
        output.append("   - Use get_paragraph_usage() to see where paragraphs are used")
        output.append("   - Use find_duplicate_paragraphs() to find potential duplicates")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error listing paragraph types")
        return f"❌ ERROR: Failed to list paragraph types: {str(e)}"


@mcp.tool()
def describe_paragraph_type(bundle: str) -> str:
    """
    Get comprehensive information about a specific paragraph type.

    Shows complete details including all fields, usage locations,
    templates, hooks, and potential similar paragraph types.

    Perfect for:
    - Understanding paragraph type structure
    - Finding where a paragraph type is used
    - Checking for custom templates and hooks
    - Identifying potential duplicates

    Args:
        bundle: Machine name of paragraph type (e.g., "hero_banner", "cta", "text_with_image")

    Returns:
        Detailed information about the paragraph type

    Examples:
        describe_paragraph_type("hero_banner")
        describe_paragraph_type("cta")
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

        # Get paragraph type info
        para_info = _get_paragraph_type_details(drupal_root, bundle)

        if not para_info:
            return f"❌ ERROR: Paragraph type '{bundle}' not found"

        # Build output
        output = []
        output.append(f"📋 PARAGRAPH TYPE: {para_info['label']}")
        output.append(f"   Machine name: {bundle}")
        output.append("=" * 80)
        output.append("")

        # Basic info
        if para_info.get("description"):
            output.append(f"Description: {para_info['description']}")
            output.append("")

        output.append(f"Usage: {para_info.get('usage_count', 0)} paragraph entities")
        output.append("")

        # Fields
        fields = para_info.get("fields", [])
        if fields:
            output.append(f"FIELDS ({len(fields)}):")
            for field in fields:
                field_name = field["field_name"]
                field_label = field["label"]
                field_type = field["type"]
                required = " [REQUIRED]" if field.get("required") else ""

                output.append(f"  • {field_label} ({field_name}){required}")
                output.append(f"    Type: {field_type}")

                # Target bundles for entity reference
                if field.get("target_bundles"):
                    bundles = ", ".join(field["target_bundles"])
                    output.append(f"    References: {bundles}")

            output.append("")

        # Used in
        used_in = para_info.get("used_in", [])
        if used_in:
            output.append(f"USED IN ({len(used_in)} location(s)):")
            for location in used_in:
                output.append(f"  • {location}")
            output.append("")

        # Templates
        templates = para_info.get("templates", [])
        if templates:
            output.append("CUSTOM TEMPLATES:")
            for tpl in templates:
                output.append(f"  ✓ {tpl}")
            output.append("")

        # Preprocess hooks
        hooks = para_info.get("hooks", [])
        if hooks:
            output.append("PREPROCESS HOOKS:")
            for hook in hooks:
                output.append(f"  ✓ {hook}")
            output.append("")

        # Similar types
        similar = para_info.get("similar_types", [])
        if similar:
            output.append("SIMILAR PARAGRAPH TYPES (potential duplicates):")
            for sim in similar:
                similarity = sim.get("similarity", 0)
                output.append(f"  ⚠️  {sim['label']} ({sim['bundle']}) - {similarity}% similar")
            output.append("")

        # Tips
        output.append("💡 Tips:")
        output.append(f"   - Templates: find_paragraph_templates('{bundle}')")
        output.append(f"   - Usage details: get_paragraph_usage('{bundle}')")
        output.append("   - Find duplicates: find_duplicate_paragraphs()")

        return "\n".join(output)

    except Exception as e:
        logger.exception(f"Error describing paragraph type '{bundle}'")
        return f"❌ ERROR: Failed to describe paragraph type: {str(e)}"


def _get_paragraph_types(drupal_root: Path) -> list:
    """Get all paragraph types with basic info."""
    drush_cmd = get_drush_command()

    php_script = """
$entity_type_manager = \\Drupal::entityTypeManager();
$bundle_info = \\Drupal::service('entity_type.bundle.info')->getBundleInfo('paragraph');

$result = [];
foreach ($bundle_info as $bundle => $info) {
  // Get field count
  $field_definitions = \\Drupal::service('entity_field.manager')->getFieldDefinitions('paragraph', $bundle);
  $field_count = 0;
  foreach ($field_definitions as $field_name => $field_definition) {
    if (!$field_definition->getFieldStorageDefinition()->isBaseField()) {
      $field_count++;
    }
  }

  // Get usage count
  $query = $entity_type_manager->getStorage('paragraph')->getQuery()
    ->condition('type', $bundle)
    ->accessCheck(FALSE);
  $usage_count = $query->count()->execute();

  $result[] = [
    'bundle' => $bundle,
    'label' => $info['label'],
    'field_count' => $field_count,
    'usage_count' => (int)$usage_count,
  ];
}

echo json_encode($result, JSON_UNESCAPED_SLASHES);
"""

    try:
        cmd = drush_cmd + ["eval", php_script]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=str(drupal_root)
        )

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout.strip())
    except Exception as e:
        logger.error(f"Error getting paragraph types: {e}")

    return []


def _get_paragraph_type_details(drupal_root: Path, bundle: str) -> Optional[dict]:
    """Get detailed information about a specific paragraph type."""
    drush_cmd = get_drush_command()

    php_script = f"""
$bundle = '{bundle}';
$entity_type_manager = \\Drupal::entityTypeManager();
$bundle_info = \\Drupal::service('entity_type.bundle.info')->getBundleInfo('paragraph');

if (!isset($bundle_info[$bundle])) {{
  echo json_encode(['error' => 'Paragraph type not found']);
  exit;
}}

$result = [
  'bundle' => $bundle,
  'label' => $bundle_info[$bundle]['label'],
  'description' => $bundle_info[$bundle]['description'] ?? '',
  'fields' => [],
  'used_in' => [],
];

// Get fields
$field_definitions = \\Drupal::service('entity_field.manager')->getFieldDefinitions('paragraph', $bundle);
foreach ($field_definitions as $field_name => $field_definition) {{
  if ($field_definition->getFieldStorageDefinition()->isBaseField()) {{
    continue;
  }}

  $field_info = [
    'field_name' => $field_name,
    'label' => (string)$field_definition->getLabel(),
    'type' => $field_definition->getType(),
    'required' => $field_definition->isRequired(),
  ];

  // Get target bundles for entity reference fields
  if ($field_definition->getType() === 'entity_reference' || $field_definition->getType() === 'entity_reference_revisions') {{
    $settings = $field_definition->getSettings();
    if (!empty($settings['handler_settings']['target_bundles'])) {{
      $field_info['target_bundles'] = array_values($settings['handler_settings']['target_bundles']);
    }}
  }}

  $result['fields'][] = $field_info;
}}

// Get usage count
$query = $entity_type_manager->getStorage('paragraph')->getQuery()
  ->condition('type', $bundle)
  ->accessCheck(FALSE);
$result['usage_count'] = (int)$query->count()->execute();

// Find where this paragraph type is referenced
$field_map = \\Drupal::service('entity_field.manager')->getFieldMapByFieldType('entity_reference_revisions');
foreach ($field_map as $entity_type => $fields) {{
  foreach ($fields as $field_name => $field_info) {{
    $field_config = \\Drupal::service('entity_field.manager')->getFieldStorageDefinitions($entity_type)[$field_name];
    $settings = $field_config->getSettings();
    if (isset($settings['target_type']) && $settings['target_type'] === 'paragraph') {{
      foreach ($field_info['bundles'] as $host_bundle) {{
        $field_definitions = \\Drupal::service('entity_field.manager')->getFieldDefinitions($entity_type, $host_bundle);
        if (isset($field_definitions[$field_name])) {{
          $field_settings = $field_definitions[$field_name]->getSettings();
          if (isset($field_settings['handler_settings']['target_bundles']) &&
              in_array($bundle, array_keys($field_settings['handler_settings']['target_bundles']))) {{
            $bundle_label = \\Drupal::service('entity_type.bundle.info')->getBundleInfo($entity_type)[$host_bundle]['label'];
            $result['used_in'][] = "$entity_type: $bundle_label ($host_bundle)";
          }}
        }}
      }}
    }}
  }}
}}

echo json_encode($result, JSON_UNESCAPED_SLASHES);
"""

    try:
        cmd = drush_cmd + ["eval", php_script]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=str(drupal_root)
        )

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout.strip())
            if "error" in data:
                return None
            return data
    except Exception as e:
        logger.error(f"Error getting paragraph type details: {e}")

    return None
