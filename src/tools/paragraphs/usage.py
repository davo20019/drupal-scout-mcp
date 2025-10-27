"""Paragraph usage tracking tools."""

import logging
import subprocess
from pathlib import Path
from src.core.config import load_config
from src.core.drush import get_drush_command
from src.core.database import verify_database_connection
from server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def get_paragraph_usage(bundle: str = None) -> str:
    """Get usage statistics for paragraph types."""
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))
        if not drupal_root.exists():
            return "❌ ERROR: Drupal root not found"

        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return f"❌ ERROR: Database required\n{db_msg}"

        # Simple usage query
        drush_cmd = get_drush_command()
        if bundle:
            php = f"echo \\Drupal::entityQuery('paragraph')->condition('type','{bundle}')->accessCheck(FALSE)->count()->execute();"
        else:
            php = "foreach(\\Drupal::service('entity_type.bundle.info')->getBundleInfo('paragraph') as $k=>$v) echo \"$k:\".\\Drupal::entityQuery('paragraph')->condition('type',$k)->accessCheck(FALSE)->count()->execute().\"\\n\";"

        result = subprocess.run(
            drush_cmd + ["eval", php],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(drupal_root),
        )
        return f"📊 PARAGRAPH USAGE\n{'='*80}\n\n{result.stdout if result.returncode==0 else 'Error getting usage'}"
    except Exception as e:
        return f"❌ ERROR: {str(e)}"


@mcp.tool()
def check_paragraph_existence(bundles: list[str]) -> str:
    """
    Check if any paragraphs exist for given paragraph types.

    Quick existence check to see if paragraph types are actually in use.
    Perfect for answering "do we have any paragraphs from these types?"

    Args:
        bundles: List of paragraph bundle machine names to check

    Returns:
        Status showing which types have content and which are empty

    Examples:
        check_paragraph_existence(["hero_banner", "call_to_action"])
        check_paragraph_existence(["text_block"])
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

        # Build PHP to check each bundle
        bundle_checks = []
        for bundle in bundles:
            bundle_checks.append(
                f'$counts["{bundle}"] = \\Drupal::entityQuery("paragraph")->condition("type","{bundle}")->accessCheck(FALSE)->count()->execute();'
            )

        php = (
            "$counts = []; "
            + " ".join(bundle_checks)
            + ' foreach($counts as $type => $count) { echo "$type:$count\\n"; }'
        )

        result = subprocess.run(
            drush_cmd + ["eval", php],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(drupal_root),
        )

        if result.returncode != 0:
            return f"❌ ERROR: {result.stderr}"

        # Parse results
        output = ["🔍 PARAGRAPH EXISTENCE CHECK", "=" * 80, ""]
        has_content = []
        empty = []

        for line in result.stdout.strip().split("\n"):
            if ":" in line:
                bundle, count = line.split(":", 1)
                count = int(count)
                if count > 0:
                    has_content.append(f"  ✓ {bundle}: {count} paragraph(s)")
                else:
                    empty.append(f"  ✗ {bundle}: No content")

        if has_content:
            output.append("HAS CONTENT:")
            output.extend(has_content)
            output.append("")

        if empty:
            output.append("EMPTY (No paragraphs):")
            output.extend(empty)
            output.append("")

        if not has_content and not empty:
            output.append("No results found")

        return "\n".join(output)

    except Exception as e:
        return f"❌ ERROR: {str(e)}"


@mcp.tool()
def get_paragraph_references(bundle: str = None, limit: int = 50) -> str:
    """
    Show where paragraphs are used (parent entities that reference them).

    Finds which content types, nodes, or other entities use specific paragraph types.
    Perfect for answering "where are these paragraphs used?"

    Args:
        bundle: Optional paragraph bundle to filter. If not provided, shows all.
        limit: Maximum number of references to show per type (default 50)

    Returns:
        List of parent entities that reference the paragraphs

    Examples:
        get_paragraph_references("hero_banner")
        get_paragraph_references()  # Show all paragraph references
        get_paragraph_references("call_to_action", limit=10)
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

        # PHP script to find parent entity references
        php = f"""
$limit = {limit};
$bundle_filter = {f'"{bundle}"' if bundle else 'NULL'};

// Find all paragraph reference fields
$field_map = \\Drupal::service('entity_field.manager')->getFieldMapByFieldType('entity_reference_revisions');
$results = [];

foreach ($field_map as $entity_type => $fields) {{
  foreach ($fields as $field_name => $field_info) {{
    // Load field config to check if it references paragraphs
    $field_configs = \\Drupal::entityTypeManager()
      ->getStorage('field_config')
      ->loadByProperties(['field_name' => $field_name]);

    foreach ($field_configs as $field_config) {{
      $settings = $field_config->getSettings();
      if (isset($settings['handler']) && $settings['handler'] === 'default:paragraph') {{
        // This field references paragraphs
        $target_bundles = $settings['handler_settings']['target_bundles'] ?? [];

        // If bundle filter is set, skip if this field doesn't reference it
        if ($bundle_filter && !empty($target_bundles) && !in_array($bundle_filter, $target_bundles)) {{
          continue;
        }}

        // Query entities that use this field
        $query = \\Drupal::entityQuery($entity_type)
          ->accessCheck(FALSE)
          ->exists($field_name)
          ->range(0, $limit);

        $entity_ids = $query->execute();

        if (!empty($entity_ids)) {{
          $entities = \\Drupal::entityTypeManager()->getStorage($entity_type)->loadMultiple($entity_ids);

          foreach ($entities as $entity) {{
            $field_value = $entity->get($field_name)->getValue();

            foreach ($field_value as $item) {{
              if (isset($item['target_id'])) {{
                // Load the paragraph to check its bundle
                $paragraph = \\Drupal::entityTypeManager()->getStorage('paragraph')->load($item['target_id']);

                if ($paragraph) {{
                  $para_bundle = $paragraph->bundle();

                  // Apply bundle filter
                  if ($bundle_filter && $para_bundle !== $bundle_filter) {{
                    continue;
                  }}

                  $entity_label = $entity->label() ?? 'Untitled';
                  $entity_bundle = $entity->bundle();

                  $key = "$entity_type|$entity_bundle|$para_bundle";
                  if (!isset($results[$key])) {{
                    $results[$key] = [
                      'entity_type' => $entity_type,
                      'entity_bundle' => $entity_bundle,
                      'paragraph_bundle' => $para_bundle,
                      'field_name' => $field_name,
                      'count' => 0,
                      'examples' => []
                    ];
                  }}

                  $results[$key]['count']++;
                  if (count($results[$key]['examples']) < 5) {{
                    $results[$key]['examples'][] = $entity_label . ' (' . $entity->id() . ')';
                  }}
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
  echo $data['paragraph_bundle'] . '|' . $data['entity_type'] . '|' . $data['entity_bundle'] . '|' . $data['field_name'] . '|' . $data['count'] . '|' . implode(';', $data['examples']) . "\\n";
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
        if bundle:
            output.append(f"📍 PARAGRAPH REFERENCES: {bundle}")
        else:
            output.append("📍 PARAGRAPH REFERENCES (All)")
        output.append("=" * 80)
        output.append("")

        if not result.stdout.strip():
            output.append("No paragraph references found")
            if bundle:
                output.append(f"\nℹ️  The '{bundle}' paragraph type may not be used anywhere,")
                output.append("   or it may not exist in the system.")
            return "\n".join(output)

        # Group by paragraph bundle
        by_bundle = {}
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 6:
                    para_bundle = parts[0]
                    entity_type = parts[1]
                    entity_bundle = parts[2]
                    field_name = parts[3]
                    count = parts[4]
                    examples = parts[5].split(";") if parts[5] else []

                    if para_bundle not in by_bundle:
                        by_bundle[para_bundle] = []

                    by_bundle[para_bundle].append(
                        {
                            "entity_type": entity_type,
                            "entity_bundle": entity_bundle,
                            "field_name": field_name,
                            "count": int(count),
                            "examples": examples,
                        }
                    )

        # Format output
        for para_bundle, references in sorted(by_bundle.items()):
            output.append(f"PARAGRAPH TYPE: {para_bundle}")
            output.append("-" * 80)

            for ref in references:
                output.append(
                    f"\n  📦 {ref['entity_type']}.{ref['entity_bundle']} (field: {ref['field_name']})"
                )
                output.append(f"     Used in {ref['count']} item(s)")

                if ref["examples"]:
                    output.append("     Examples:")
                    for example in ref["examples"][:5]:
                        output.append(f"       • {example}")

            output.append("")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error getting paragraph references")
        return f"❌ ERROR: {str(e)}"
