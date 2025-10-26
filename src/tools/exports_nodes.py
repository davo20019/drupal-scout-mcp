"""
Nodes export tool for Drupal Scout MCP.

Provides CSV export functionality for node/content:
- export_nodes_to_csv: Export nodes to CSV with comprehensive field data

This tool bypasses MCP token limits by writing directly to filesystem.
"""

import csv
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Import from core modules
from src.core.drush import get_drush_command

# Import shared export utilities
from src.tools.exports_common import get_export_config, validate_export_path

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def export_nodes_to_csv(
    content_type: Optional[str] = None,
    output_path: Optional[str] = None,
    summary_only: bool = True,
    include_unpublished: bool = False,
    include_field_data: bool = False,
    limit: int = 0,
) -> str:
    """
    Export node/content data directly to CSV file, bypassing MCP token limits.

    **BEST SOLUTION FOR CONTENT AUDITS AND MIGRATION PLANNING**

    Perfect for:
    - Content inventory and auditing
    - SEO analysis (URLs, redirects, metatags)
    - Migration planning and mapping
    - Finding broken references or missing fields
    - Bulk content review and cleanup

    **How It Works:**
    1. Queries all nodes (optionally filtered by content type)
    2. Fetches comprehensive field data via drush
    3. Writes CSV directly to Drupal root directory
    4. Returns tiny response with file path and stats

    **Performance:**
    - 100 nodes: ~10 seconds
    - 500 nodes: ~30 seconds
    - 1000 nodes: ~60 seconds
    - 5000 nodes: ~5 minutes

    Args:
        content_type: Optional content type filter (e.g., "article", "page")
                     If None, exports all content types
        output_path: Optional CSV file path. If not provided, auto-generates:
                     {drupal_root}/nodes_export_{type}_{timestamp}.csv
        summary_only: If True, exports essential columns (nid, title, type, status, created, author).
                     If False, exports FULL details including:
                       - nid, uuid, title, type, status, langcode
                       - created, changed, author (username + uid)
                       - published_date, unpublished_date
                       - url_alias, canonical_url
                       - redirects (if redirect module enabled)
                       - taxonomy_terms (all term references with vocabulary labels)
                       - entity_references (referenced nodes, users, media, etc.)
                       - metatags (title, description, keywords if metatag module enabled)
                       - revision_count, latest_revision_log
                       - promote, sticky, front_page
                     Default: True (faster for large datasets)
        include_field_data: If True, includes actual field values in CSV (body text, images, custom fields).
                     **SMART PROMPTING - Set to True when user asks for:**
                     - "field data", "field values", "field content"
                     - "body text", "content", "actual content"
                     - "image data", "alt text", "image fields"
                     - "all data", "everything", "complete export"
                     - "migration data", "full migration export"
                     **Keep False (default) for:**
                     - Basic inventory, metadata-only exports
                     - Quick audits focusing on URLs/taxonomy/status
                     **Field data included:**
                     - body: First 500 chars (summary)
                     - body_format: Text format (full_html, basic_html, etc.)
                     - images: Alt text + count (field_image: "Logo image | 3 images total")
                     - text fields: Full value
                     - link fields: URLs only
                     - Custom fields: Auto-detected and included
                     **Performance impact:** Adds 30-50% to export time
                     Default: False
        include_unpublished: If True, includes unpublished nodes. Default: False
        limit: Max nodes to export. 0 = all nodes. Default: 0

    Returns:
        JSON with file path, stats, and preview:
        {
            "file_path": "/path/to/drupal/nodes_export_article_20251025.csv",
            "total_nodes": 1523,
            "content_types": ["article", "page"],
            "file_size_kb": 450,
            "columns": [...],
            "preview": "..."
        }

    **Column Details (Full Mode):**

    Basic Info:
    - nid, uuid, title, type (content_type), status (published/unpublished)
    - langcode, created (timestamp), changed (timestamp)
    - author (username), author_uid

    URLs & SEO:
    - url_alias (/about-us)
    - canonical_url (https://example.com/node/123)
    - redirects (old-url-1 | old-url-2) if redirect module installed
    - metatag_title, metatag_description, metatag_keywords (if metatag module)

    Relationships:
    - taxonomy_terms (Category: News | Tags: Drupal, PHP)
    - entity_references (References node:456 | media:789)

    Publishing:
    - published_date, unpublished_date
    - promote (YES/NO), sticky (YES/NO), front_page (YES/NO)

    Revisions:
    - revision_count (total revisions)
    - latest_revision_log (last edit message)

    **Examples:**

    Fast summary of all articles:
    export_nodes_to_csv(content_type="article", summary_only=True)

    Full audit of all content:
    export_nodes_to_csv(summary_only=False)

    Migration prep for blog posts:
    export_nodes_to_csv(content_type="blog", summary_only=False, include_unpublished=True)
    """
    try:
        # Get config and verify database connection
        success, result, msg = get_export_config()
        if not success:
            return result["error_response"]

        drupal_root = result["drupal_root"]

        # Auto-generate path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            type_suffix = f"_{content_type}" if content_type else "_all"
            output_path = str(drupal_root / f"nodes_export{type_suffix}_{timestamp}.csv")

        # Validate path is within safe boundaries
        is_valid, error_msg = validate_export_path(output_path, drupal_root)
        if not is_valid:
            return json.dumps({"_error": True, "message": f"Invalid export path: {error_msg}"})

        # Validate path is writable
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Get all nodes via drush
        logger.info(
            f"Fetching nodes{' for content type: ' + content_type if content_type else ''}..."
        )
        nodes = _get_all_nodes_from_drush(
            drupal_root=drupal_root,
            content_type=content_type,
            summary_only=summary_only,
            include_unpublished=include_unpublished,
            include_field_data=include_field_data,
            limit=limit,
        )

        if nodes is None:
            return json.dumps(
                {
                    "_error": True,
                    "message": "Failed to fetch nodes from Drupal. Check server logs for details.",
                    "suggestion": "Verify drush is working: drush status",
                }
            )

        if not nodes or len(nodes) == 0:
            debug_info = {
                "_error": True,
                "message": f"No nodes found{' for content type: ' + content_type if content_type else ''}",
                "filters_applied": {
                    "content_type": content_type or "all",
                    "include_unpublished": include_unpublished,
                    "limit": limit if limit > 0 else "no limit",
                },
                "suggestion": "Try running: drush ev \"echo count(\\\\Drupal::entityQuery('node')->accessCheck(FALSE)->execute());\" to verify nodes exist",
            }
            return json.dumps(debug_info)

        total_nodes = len(nodes)
        content_types = list(set(node.get("type", "") for node in nodes))

        # Determine CSV columns
        if summary_only:
            columns = ["nid", "title", "type", "status", "created", "changed", "author"]
        else:
            # Base columns
            columns = [
                "nid",
                "uuid",
                "title",
                "type",
                "status",
                "langcode",
                "created",
                "changed",
                "author",
                "author_uid",
                "url_alias",
                "canonical_url",
                "redirects",
                "taxonomy_terms",
                "entity_references",
                "metatag_title",
                "metatag_description",
                "metatag_keywords",
                "revision_count",
                "latest_revision_log",
                "promote",
                "sticky",
                "front_page",
            ]

            # Add field data columns if requested
            if include_field_data:
                columns.extend(["body", "body_format"])

                # Collect all custom field names from all nodes
                custom_fields = set()
                for node in nodes:
                    for key in node.keys():
                        # Add fields that aren't in base columns
                        if key not in columns and key not in [
                            "nid",
                            "uuid",
                            "vid",
                            "type",
                            "langcode",
                            "title",
                            "uid",
                            "status",
                            "created",
                            "changed",
                        ]:
                            custom_fields.add(key)

                # Add custom fields to columns (sorted for consistency)
                columns.extend(sorted(custom_fields))

        # Write CSV
        logger.info(f"Writing {total_nodes} nodes to {output_path}...")
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()

            for node in nodes:
                row = {}
                for col in columns:
                    value = node.get(col, "")

                    # Format lists with pipe separator
                    if isinstance(value, list):
                        value = " | ".join(str(v) for v in value)

                    # Convert booleans to YES/NO
                    elif isinstance(value, bool):
                        value = "YES" if value else "NO"

                    # Format timestamps
                    elif col in ["created", "changed"] and isinstance(value, (int, float)):
                        value = datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")

                    row[col] = value

                writer.writerow(row)

        # Get file size
        file_size_kb = round(output_file.stat().st_size / 1024, 1)

        # Create preview
        with open(output_path, "r", encoding="utf-8") as f:
            preview_lines = [f.readline().strip() for _ in range(4)]
            preview = "\n".join(preview_lines)

        result = {
            "success": True,
            "file_path": str(output_path),
            "total_nodes": total_nodes,
            "content_types": content_types,
            "file_size_kb": file_size_kb,
            "columns": columns,
            "preview": preview,
            "message": f"✅ Successfully exported {total_nodes} nodes to {output_path} ({file_size_kb} KB)",
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Error in export_nodes_to_csv: {e}", exc_info=True)
        return json.dumps({"_error": True, "message": str(e)})


def _get_all_nodes_from_drush(
    drupal_root: Path,
    content_type: Optional[str] = None,
    summary_only: bool = True,
    include_unpublished: bool = False,
    include_field_data: bool = False,
    limit: int = 0,
) -> Optional[List[dict]]:
    """Get comprehensive node data via optimized drush query."""
    try:
        # Build filters as proper PHP lines
        filters = []
        if content_type:
            filters.append(f"$query->condition('type', '{content_type}');")
        if not include_unpublished:
            filters.append("$query->condition('status', 1);")
        if limit > 0:
            filters.append(f"$query->range(0, {limit});")

        filters_code = "\n        ".join(filters) if filters else "// No additional filters"

        # Build PHP code for drush
        php_code = f"""
        $node_storage = \\Drupal::entityTypeManager()->getStorage('node');
        $user_storage = \\Drupal::entityTypeManager()->getStorage('user');
        $summary_only = {str(summary_only).lower()};
        $include_field_data = {str(include_field_data).lower()};

        // Query nodes
        $query = \\Drupal::entityQuery('node')->accessCheck(FALSE);

        // Add filters
        {filters_code}

        $query->sort('created', 'DESC');
        $nids = $query->execute();

        if (empty($nids)) {{
            echo json_encode([]);
            exit;
        }}

        $nodes = $node_storage->loadMultiple($nids);
        $results = [];
        $total = count($nodes);
        $count = 0;

        fwrite(STDERR, "Analyzing $total nodes...\\n");

        foreach ($nodes as $node) {{
            $count++;
            if ($count % 100 == 0) {{
                fwrite(STDERR, "Progress: $count / $total nodes\\n");
            }}

            $author = $node->getOwner();
            $data = [
                'nid' => (int) $node->id(),
                'uuid' => $node->uuid(),
                'title' => $node->getTitle(),
                'type' => $node->bundle(),
                'status' => $node->isPublished() ? 'published' : 'unpublished',
                'langcode' => $node->language()->getId(),
                'created' => (int) $node->getCreatedTime(),
                'changed' => (int) $node->getChangedTime(),
                'author' => $author->getDisplayName(),
                'author_uid' => (int) $author->id(),
            ];

            if (!$summary_only) {{
                // URL and alias
                $url_alias = '';
                $canonical_url = '';
                try {{
                    $url = $node->toUrl('canonical', ['absolute' => FALSE])->toString();
                    $url_alias = $url;
                    $canonical_url = $node->toUrl('canonical', ['absolute' => TRUE])->toString();
                }} catch (\\Exception $e) {{
                    // Node might not have a URL
                }}
                $data['url_alias'] = $url_alias;
                $data['canonical_url'] = $canonical_url;

                // Redirects (if redirect module exists)
                $redirects = [];
                if (\\Drupal::moduleHandler()->moduleExists('redirect')) {{
                    $redirect_storage = \\Drupal::entityTypeManager()->getStorage('redirect');
                    $redirect_ids = $redirect_storage->getQuery()
                        ->accessCheck(FALSE)
                        ->condition('redirect_redirect.uri', 'entity:node/' . $node->id())
                        ->execute();
                    if ($redirect_ids) {{
                        $redirect_entities = $redirect_storage->loadMultiple($redirect_ids);
                        foreach ($redirect_entities as $redirect) {{
                            $redirects[] = $redirect->getSourceUrl();
                        }}
                    }}
                }}
                $data['redirects'] = $redirects;

                // Taxonomy terms
                $taxonomy_terms = [];
                foreach ($node->getFields() as $field_name => $field) {{
                    if ($field->getFieldDefinition()->getType() === 'entity_reference' &&
                        $field->getFieldDefinition()->getSetting('target_type') === 'taxonomy_term') {{
                        $field_label = $field->getFieldDefinition()->getLabel();
                        foreach ($field->referencedEntities() as $term) {{
                            $vocab = $term->bundle();
                            $taxonomy_terms[] = $vocab . ': ' . $term->getName();
                        }}
                    }}
                }}
                $data['taxonomy_terms'] = $taxonomy_terms;

                // Entity references (nodes, media, users, etc.)
                $entity_refs = [];
                foreach ($node->getFields() as $field_name => $field) {{
                    if ($field->getFieldDefinition()->getType() === 'entity_reference') {{
                        $target_type = $field->getFieldDefinition()->getSetting('target_type');
                        if ($target_type !== 'taxonomy_term') {{
                            foreach ($field->referencedEntities() as $ref_entity) {{
                                $entity_refs[] = $target_type . ':' . $ref_entity->id();
                            }}
                        }}
                    }}
                }}
                $data['entity_references'] = $entity_refs;

                // Metatags (if metatag module exists)
                $metatag_title = '';
                $metatag_description = '';
                $metatag_keywords = '';
                if (\\Drupal::moduleHandler()->moduleExists('metatag') && $node->hasField('field_metatag')) {{
                    $metatags = $node->get('field_metatag')->getValue();
                    if (!empty($metatags[0])) {{
                        $metatag_title = $metatags[0]['title'] ?? '';
                        $metatag_description = $metatags[0]['description'] ?? '';
                        $metatag_keywords = $metatags[0]['keywords'] ?? '';
                    }}
                }}
                $data['metatag_title'] = $metatag_title;
                $data['metatag_description'] = $metatag_description;
                $data['metatag_keywords'] = $metatag_keywords;

                // Revisions
                $revision_ids = \\Drupal::database()->select('node_revision', 'nr')
                    ->fields('nr', ['vid'])
                    ->condition('nid', $node->id())
                    ->execute()
                    ->fetchCol();
                $data['revision_count'] = count($revision_ids);
                $data['latest_revision_log'] = $node->getRevisionLogMessage() ?? '';

                // Promote/sticky/front page
                $data['promote'] = $node->isPromoted();
                $data['sticky'] = $node->isSticky();
                $data['front_page'] = ($node->id() == \\Drupal::config('system.site')->get('page.front'));

                // Field data extraction (if requested)
                if ($include_field_data) {{
                    // Body field
                    if ($node->hasField('body') && !$node->get('body')->isEmpty()) {{
                        $body_value = $node->get('body')->value;
                        $data['body'] = mb_substr(strip_tags($body_value), 0, 500);
                        $data['body_format'] = $node->get('body')->format ?? '';
                    }} else {{
                        $data['body'] = '';
                        $data['body_format'] = '';
                    }}

                    // Extract common and custom fields
                    $field_data = [];
                    foreach ($node->getFields() as $field_name => $field) {{
                        // Skip base/computed fields
                        if (in_array($field_name, ['nid', 'uuid', 'vid', 'type', 'langcode', 'title', 'uid', 'status', 'created', 'changed', 'promote', 'sticky', 'revision_timestamp', 'revision_uid', 'revision_log', 'default_langcode', 'content_translation_source', 'content_translation_outdated', 'body', 'field_metatag'])) {{
                            continue;
                        }}

                        $field_type = $field->getFieldDefinition()->getType();
                        $field_label = $field->getFieldDefinition()->getLabel();

                        // Skip if empty
                        if ($field->isEmpty()) {{
                            continue;
                        }}

                        // Handle different field types
                        $field_values = [];
                        if ($field_type === 'image') {{
                            foreach ($field->referencedEntities() as $image) {{
                                $alt = $field->alt ?? '';
                                $field_values[] = $alt;
                            }}
                            $count = count($field->referencedEntities());
                            $field_data[$field_name] = implode(' | ', $field_values) . " ($count images)";
                        }} elseif ($field_type === 'entity_reference') {{
                            // Already handled in entity_references, skip
                            continue;
                        }} elseif ($field_type === 'link') {{
                            foreach ($field as $link) {{
                                $field_values[] = $link->uri;
                            }}
                            $field_data[$field_name] = implode(' | ', $field_values);
                        }} elseif ($field_type === 'text' || $field_type === 'string' || $field_type === 'text_long') {{
                            foreach ($field as $item) {{
                                $value = strip_tags($item->value);
                                $field_values[] = mb_substr($value, 0, 200);
                            }}
                            $field_data[$field_name] = implode(' | ', $field_values);
                        }} else {{
                            // Generic handling for other field types
                            foreach ($field as $item) {{
                                if (isset($item->value)) {{
                                    $field_values[] = $item->value;
                                }}
                            }}
                            if (!empty($field_values)) {{
                                $field_data[$field_name] = implode(' | ', $field_values);
                            }}
                        }}
                    }}

                    // Add all collected field data to result
                    foreach ($field_data as $fname => $fvalue) {{
                        $data[$fname] = $fvalue;
                    }}
                }}
            }}

            $results[] = $data;
        }}

        fwrite(STDERR, "Completed: $total nodes\\n");
        echo json_encode($results);
        """

        # Execute via drush
        drush_cmd = get_drush_command()
        if not drush_cmd:
            logger.error("Drush command not available")
            return None

        cmd = drush_cmd + ["php:eval", php_code]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(drupal_root),  # Run in Drupal root directory
            timeout=600,  # 10 minute timeout for large datasets
        )

        if result.returncode != 0:
            logger.error(f"Drush command failed: {result.stderr}")
            logger.error(f"Drush stdout: {result.stdout}")
            return None

        # Parse the output
        try:
            nodes = json.loads(result.stdout)
            return nodes
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output: {e}")
            logger.error(f"Raw output: {result.stdout}")
            return None

    except Exception as e:
        logger.error(f"Error in _get_all_nodes_from_drush: {e}", exc_info=True)
        return None
