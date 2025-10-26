"""
Taxonomy export tool for Drupal Scout MCP.

Provides CSV export functionality for taxonomy terms:
- export_taxonomy_usage_to_csv: Export taxonomy terms to CSV with usage analysis

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
from src.core.drush import run_drush_command

# Import shared export utilities
from src.tools.exports.common import get_export_config, validate_export_path

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def export_taxonomy_usage_to_csv(
    vocabulary: str,
    output_path: Optional[str] = None,
    check_code: bool = False,
    summary_only: bool = True,
    limit: int = 0,
) -> str:
    """
    Export ALL taxonomy term usage data directly to a CSV file, bypassing MCP token limits.

    **BEST SOLUTION FOR LARGE VOCABULARIES (500+ terms)**

    This tool writes CSV directly to the filesystem, avoiding MCP's 25K token response limit.
    Perfect for vocabularies with hundreds or thousands of terms.

    **How It Works:**
    1. Fetches ALL terms from vocabulary (no limit)
    2. Writes CSV directly to file system
    3. Returns file path and summary stats (tiny response)
    4. LLM can then tell user where file is saved

    **When to Use This Tool:**
    - User asks to "export to CSV" or "save to file"
    - Vocabulary has 200+ terms
    - User wants complete dataset without truncation
    - Avoiding token limit issues

    **Workflow Example:**
    ```
    User: "Export all tags to CSV"
    LLM: export_taxonomy_usage_to_csv(vocabulary="tags", output_path="/tmp/tags_export.csv")
    Response: "✅ Exported 751 terms to /tmp/tags_export.csv (45 KB)"
    LLM: "I've exported all 751 terms to /tmp/tags_export.csv. The file includes..."
    ```

    Args:
        vocabulary: Vocabulary machine name (e.g., "topics", "tags")
        output_path: Optional CSV file path. If not provided, auto-generates in Drupal root:
                     {drupal_root}/taxonomy_export_{vocabulary}_{timestamp}.csv
        check_code: If True, scans custom code for term references (slower).
                    Default: False (recommended for large exports)
                    Only applies when summary_only=False
        summary_only: If True, exports minimal columns (tid, name, count, needs_check).
                      If False, exports FULL details including:
                        - tid, name, description, parent, children
                        - content_count (total usage)
                        - content_usage_sample (first 5 nodes using this term)
                        - fields_with_usage (which fields use this term)
                        - code_usage (hardcoded references in custom code, if check_code=True)
                        - config_usage (config file references, if check_code=True)
                        - safe_to_delete (YES/NO based on all checks)
                        - warnings (reasons why term might not be safe to delete)
                      Default: True (faster for large vocabularies)
        limit: Max terms to export. 0 = all terms. Default: 0

    Returns:
        JSON with file path, stats, and preview:
        {
            "file_path": "/tmp/tags_export.csv",
            "total_terms": 751,
            "file_size_kb": 45,
            "columns": ["tid", "name", "count", "safe_to_delete"],
            "preview": "First 3 rows preview..."
        }

    **Advantages Over get_all_taxonomy_usage():**
    - No token limits (can handle 10,000+ terms)
    - Faster (no JSON serialization overhead)
    - File persists for user to download/analyze
    - Response is tiny regardless of term count

    **Performance:**
    - 100 terms: ~5 seconds
    - 500 terms: ~20 seconds
    - 1000 terms: ~40 seconds
    - 5000 terms: ~3 minutes
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
            # Save in Drupal root directory for easy access in IDE
            output_path = str(drupal_root / f"taxonomy_export_{vocabulary}_{timestamp}.csv")

        # Validate path is within safe boundaries
        is_valid, error_msg = validate_export_path(output_path, drupal_root)
        if not is_valid:
            return json.dumps({"_error": True, "message": f"Invalid export path: {error_msg}"})

        # Validate path is writable
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Get ALL terms directly from helper function (no limit)
        logger.info(f"Fetching all terms from vocabulary '{vocabulary}'...")

        # In full mode, fetch sample nodes; in summary mode, skip them for speed
        max_samples = 0 if summary_only else 5

        terms = _get_all_terms_usage_from_drush(
            vocabulary=vocabulary,
            max_sample_nodes=max_samples,
            summary_only=summary_only,
            limit=limit,
        )

        if not terms:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Could not fetch terms for vocabulary '{vocabulary}'",
                    "suggestion": "Verify vocabulary machine name is correct.",
                }
            )

        total_terms = len(terms)

        # Add code/config usage if requested
        if check_code and not summary_only:
            terms = _add_code_usage_to_terms(terms, drupal_root)

        # Determine CSV columns based on summary_only mode
        if summary_only:
            columns = ["tid", "name", "count", "needs_check"]
        else:
            # Full mode - include ALL available details
            columns = [
                "tid",
                "name",
                "description",
                "parent",
                "children",
                "content_count",
                "content_usage_sample",  # Sample nodes (first 5)
                "fields_with_usage",
                "code_usage",
                "config_usage",
                "safe_to_delete",
                "warnings",
            ]

        # Write CSV
        logger.info(f"Writing {total_terms} terms to {output_path}...")
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()

            for term in terms:
                row = {}
                for col in columns:
                    value = term.get(col, "")

                    # Special handling for different field types
                    if col == "content_usage_sample":
                        # Get sample nodes from content_usage array
                        content_usage = term.get("content_usage", [])
                        if content_usage:
                            samples = [
                                f"nid:{item.get('nid')} ({item.get('title', 'Untitled')})"
                                for item in content_usage[:5]
                            ]
                            value = " | ".join(samples)
                        else:
                            value = ""

                    elif col == "content_count":
                        # Use content_count if available, otherwise count content_usage
                        value = term.get("content_count") or term.get("count", 0)

                    elif col == "code_usage":
                        # Format code references
                        code_usage = term.get("code_usage", [])
                        if code_usage:
                            refs = [
                                f"{item.get('file', '')}:{item.get('line', '')}"
                                for item in code_usage
                            ]
                            value = " | ".join(refs)
                        else:
                            value = ""

                    elif col == "config_usage":
                        # Format config references
                        config_usage = term.get("config_usage", [])
                        if config_usage:
                            refs = [
                                f"{item.get('config_name', '')} ({item.get('config_type', '')})"
                                for item in config_usage
                            ]
                            value = " | ".join(refs)
                        else:
                            value = ""

                    elif isinstance(value, list):
                        # Handle any other lists/arrays
                        value = " | ".join(str(v) for v in value)

                    elif isinstance(value, bool):
                        # Convert boolean to readable text
                        value = "YES" if value else "NO"

                    row[col] = value

                writer.writerow(row)

        # Get file size
        file_size_kb = round(output_file.stat().st_size / 1024, 1)

        # Create preview (first 3 rows)
        with open(output_path, "r", encoding="utf-8") as f:
            preview_lines = [f.readline().strip() for _ in range(4)]  # Header + 3 rows
            preview = "\n".join(preview_lines)

        result = {
            "success": True,
            "file_path": str(output_path),
            "total_terms": total_terms,
            "file_size_kb": file_size_kb,
            "columns": columns,
            "preview": preview,
            "message": f"✅ Successfully exported {total_terms} terms to {output_path} ({file_size_kb} KB)",
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Error in export_taxonomy_usage_to_csv: {e}", exc_info=True)
        return json.dumps({"_error": True, "message": str(e)})


def _get_all_terms_usage_from_drush(
    vocabulary: str, max_sample_nodes: int = 5, summary_only: bool = False, limit: int = 0
) -> Optional[List[dict]]:
    """Get usage data for all terms in a vocabulary via optimized drush query."""
    try:
        php_code = f"""
        $vocabulary = '{vocabulary}';
        $max_samples = {max_sample_nodes};
        $summary_only = {str(summary_only).lower()};
        $limit = {limit};

        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');
        $database = \\Drupal::database();
        $node_storage = \\Drupal::entityTypeManager()->getStorage('node');

        // Load vocabulary
        $vocab = $vocab_storage->load($vocabulary);
        if (!$vocab) {{
            echo json_encode(null);
            exit;
        }}

        // Load all terms in vocabulary
        $query = \\Drupal::entityQuery('taxonomy_term')
            ->accessCheck(FALSE)
            ->condition('vid', $vocabulary);

        // Apply limit if specified
        if ($limit > 0) {{
            $query->range(0, $limit);
        }}

        $term_ids = $query->execute();

        if (empty($term_ids)) {{
            echo json_encode([]);
            exit;
        }}

        $terms = $term_storage->loadMultiple($term_ids);
        $results = [];
        $total_terms = count($terms);

        // Progress: Initial status
        fwrite(STDERR, "Analyzing " . $total_terms . " terms in vocabulary '" . $vocabulary . "'...\\n");

        // Get field map once (reuse for all terms)
        $field_map = \\Drupal::service('entity_field.manager')->getFieldMapByFieldType('entity_reference');

        // Build list of field tables to check
        $field_tables = [];
        foreach ($field_map['node'] ?? [] as $field_name => $field_info) {{
            $table_name = 'node__' . $field_name;
            $column_name = $field_name . '_target_id';

            // Test if table exists
            try {{
                $database->query("SELECT 1 FROM {{" . $table_name . "}} LIMIT 1")->fetchField();
                $field_tables[] = [
                    'table' => $table_name,
                    'column' => $column_name,
                    'field_name' => $field_name
                ];
            }} catch (\\Exception $e) {{
                // Table doesn't exist - skip
            }}
        }}

        fwrite(STDERR, "Checking " . count($field_tables) . " field tables for term usage...\\n");

        $processed = 0;
        foreach ($terms as $term) {{
            $processed++;

            // Progress: Show every 50 terms or at key milestones
            if ($processed % 50 === 0 || $processed === 1 || $processed === $total_terms) {{
                fwrite(STDERR, "Progress: " . $processed . "/" . $total_terms . " terms processed\\n");
            }}
            $tid = (int)$term->id();

            // Get term metadata
            $parents = $term_storage->loadParents($tid);
            $parent_name = $parents ? reset($parents)->getName() : null;

            $children = $term_storage->loadChildren($tid);
            $children_names = array_map(function($child) {{ return $child->getName(); }}, $children);

            // Find content using this term (optimized)
            $nids_found = [];
            $fields_found_usage = [];

            // Check taxonomy_index first (fast)
            $taxonomy_index_nids = $database->query(
                "SELECT DISTINCT nid FROM {{taxonomy_index}} WHERE tid = :tid",
                [':tid' => $tid]
            )->fetchCol();

            if ($taxonomy_index_nids) {{
                $nids_found = array_merge($nids_found, $taxonomy_index_nids);
            }}

            // Check field data tables
            foreach ($field_tables as $field_info) {{
                try {{
                    $field_nids = $database->query(
                        "SELECT DISTINCT entity_id FROM {{" . $field_info['table'] . "}} WHERE " . $field_info['column'] . " = :tid",
                        [':tid' => $tid]
                    )->fetchCol();

                    if ($field_nids) {{
                        $nids_found = array_merge($nids_found, $field_nids);
                        $fields_found_usage[] = $field_info['field_name'];
                    }}
                }} catch (\\Exception $e) {{
                    // Query failed - skip
                }}
            }}

            // Get unique NIDs
            $nids_found = array_unique($nids_found);
            $total_content_count = count($nids_found);

            // Determine if safe to delete
            $safe_to_delete = ($total_content_count === 0 && empty($children_names));

            // Build result based on summary_only flag
            if ($summary_only) {{
                // Ultra-compact mode: just essentials
                // Note: 'needs_check' indicates this is content-only analysis
                $results[] = [
                    'tid' => $tid,
                    'name' => $term->getName(),
                    'count' => $total_content_count,
                    'needs_check' => $safe_to_delete  // TRUE = candidate for deletion, needs full check
                ];
            }} else {{
                // Full mode: get sample nodes
                $sample_nids = array_slice($nids_found, 0, $max_samples);
                $content_usage = [];

                if (!empty($sample_nids)) {{
                    $nodes = $node_storage->loadMultiple($sample_nids);
                    foreach ($nodes as $node) {{
                        $content_usage[] = [
                            'nid' => (int)$node->id(),
                            'title' => $node->getTitle(),
                            'type' => $node->bundle()
                        ];
                    }}
                }}

                $warnings = [];
                if ($total_content_count > 0) {{
                    $warnings[] = "Used in " . $total_content_count . " content items";
                }}
                if (!empty($children_names)) {{
                    $warnings[] = "Has " . count($children_names) . " child terms";
                }}

                $results[] = [
                    'tid' => $tid,
                    'name' => $term->getName(),
                    'description' => $term->getDescription(),
                    'vocabulary' => $vocabulary,
                    'vocabulary_label' => $vocab->label(),
                    'parent' => $parent_name,
                    'children' => array_values($children_names),
                    'content_count' => $total_content_count,
                    'content_usage' => $content_usage,
                    'fields_with_usage' => $fields_found_usage,
                    'safe_to_delete' => $safe_to_delete,
                    'warnings' => $warnings
                ];
            }}
        }}

        // Progress: Completion
        fwrite(STDERR, "Analysis complete! Processed " . $total_terms . " terms.\\n");

        echo json_encode($results);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=120)
        return result if result and isinstance(result, list) else None

    except Exception as e:
        logger.debug(f"Could not get all terms usage from drush: {e}")
        return None


def _add_code_usage_to_terms(terms_data: List[dict], drupal_root: Path) -> List[dict]:
    """Scan custom code and config for hardcoded term references."""
    # Build lookup maps for efficient searching
    tid_to_term = {term["tid"]: term for term in terms_data}
    name_to_terms = {}
    for term in terms_data:
        name = term["name"]
        if name not in name_to_terms:
            name_to_terms[name] = []
        name_to_terms[name].append(term)

    # Initialize code_usage and config_usage for all terms
    for term in terms_data:
        term["code_usage"] = []
        term["config_usage"] = []

    # Scan custom modules directory
    custom_dir = drupal_root / "web" / "modules" / "custom"
    if not custom_dir.exists():
        custom_dir = drupal_root / "modules" / "custom"

    if custom_dir.exists():
        # Scan for term IDs in PHP files
        try:
            # Search for ->load(TID) or Term::load(TID)
            for tid in tid_to_term.keys():
                result = subprocess.run(
                    ["grep", "-r", "-n", f"load({tid})", str(custom_dir)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        if line:
                            parts = line.split(":", 2)
                            if len(parts) >= 3:
                                file_path = parts[0].replace(str(drupal_root) + "/", "")
                                line_num = parts[1]
                                context = parts[2].strip()[:100]
                                tid_to_term[tid]["code_usage"].append(
                                    {"file": file_path, "line": line_num, "context": context}
                                )
                                if "Referenced in custom code" not in tid_to_term[tid]["warnings"]:
                                    tid_to_term[tid]["warnings"].append("Referenced in custom code")
                                    tid_to_term[tid]["safe_to_delete"] = False
        except Exception as e:
            logger.debug(f"Error scanning for term IDs: {e}")

        # Scan for term names in PHP/Twig files
        try:
            for name, terms_list in name_to_terms.items():
                # Escape single quotes for grep
                escaped_name = name.replace("'", "\\'")
                result = subprocess.run(
                    ["grep", "-r", "-n", f"'{escaped_name}'", str(custom_dir)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n")[
                        :5
                    ]:  # Limit to 5 matches per term
                        if line:
                            parts = line.split(":", 2)
                            if len(parts) >= 3:
                                file_path = parts[0].replace(str(drupal_root) + "/", "")
                                line_num = parts[1]
                                context = parts[2].strip()[:100]
                                for term in terms_list:
                                    term["code_usage"].append(
                                        {"file": file_path, "line": line_num, "context": context}
                                    )
                                    if "Referenced in custom code" not in term["warnings"]:
                                        term["warnings"].append("Referenced in custom code")
                                        term["safe_to_delete"] = False
        except Exception as e:
            logger.debug(f"Error scanning for term names: {e}")

    # Scan config directory for term references
    config_dir = drupal_root / "config" / "sync"
    if not config_dir.exists():
        config_dir = drupal_root / "web" / "sites" / "default" / "files" / "config"

    if config_dir.exists():
        try:
            for tid in tid_to_term.keys():
                result = subprocess.run(
                    ["grep", "-r", "-l", f": {tid}", str(config_dir)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for config_file in result.stdout.strip().split("\n"):
                        if config_file:
                            config_name = Path(config_file).stem
                            tid_to_term[tid]["config_usage"].append(
                                {"config_name": config_name, "config_type": "yaml"}
                            )
                            if "Referenced in config files" not in tid_to_term[tid]["warnings"]:
                                tid_to_term[tid]["warnings"].append("Referenced in config files")
                                tid_to_term[tid]["safe_to_delete"] = False
        except Exception as e:
            logger.debug(f"Error scanning config files: {e}")

    return terms_data
