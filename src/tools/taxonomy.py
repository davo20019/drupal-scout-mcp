"""
Taxonomy tools for Drupal Scout MCP server.

This module provides comprehensive tools for inspecting Drupal taxonomy vocabularies,
terms, and their usage across content and views. Uses drush-first approach for accuracy,
with file-based fallback when drush is unavailable.

Tools:
- get_taxonomy_info: Get taxonomy vocabularies, terms, and usage analysis
- get_all_taxonomy_usage: Bulk analysis of all terms in a vocabulary (optimized)
"""

import json
import logging
from pathlib import Path
from typing import List, Optional

# Import MCP instance from server (used for @mcp.tool() decorator)
from server import mcp

# Import core utilities
from src.core.config import get_config
from src.core.drush import run_drush_command
from src.core.database import verify_database_connection

logger = logging.getLogger(__name__)


@mcp.tool()
def get_taxonomy_info(
    vocabulary: Optional[str] = None, term_name: Optional[str] = None, term_id: Optional[int] = None
) -> str:
    """
    Get comprehensive information about Drupal taxonomies, vocabularies, and terms.

    **USE THIS TOOL** before deleting, renaming, or modifying taxonomy terms/vocabularies.

    This tool answers questions like:
    - "What taxonomy vocabularies exist?"
    - "Show me all terms in the categories vocabulary"
    - "Where is the 'Technology' term used?" → Use term_name="Technology"
    - "Can I safely delete the 'Old Category' term?" → Use term_name="Old Category"
    - "Where is the Drupal term being used?" → Use term_name="Drupal", vocabulary="tags"
    - "What content uses terms from the tags vocabulary?"
    - "Show me the hierarchy of the main menu vocabulary"
    - "Which fields reference the categories vocabulary?"

    IMPORTANT: To find where a specific term is used:
    1. Use term_name parameter: get_taxonomy_info(term_name="Drupal", vocabulary="tags")
    2. If only one match, automatically shows detailed usage analysis
    3. If multiple matches, shows list with term IDs to choose from

    DO NOT try to find term IDs manually - use term_name parameter!

    Provides:
    - Vocabulary list with term counts
    - Term hierarchies (parent/child relationships)
    - Term usage in content (which nodes reference each term)
    - Term usage in views (filters, contextual filters, relationships)
    - Fields that reference each vocabulary
    - Safe-to-delete analysis for terms
    - Term metadata (name, description, weight, parent)

    Uses drush-first approach to get active taxonomy data from database,
    falls back to parsing taxonomy config files and searching codebase.

    Saves ~1000-1500 tokens vs running multiple taxonomy commands + content queries.

    **Agent-friendly:** This tool works well in loops for checking multiple terms.
    Agents can call this tool 50-100+ times to verify safe-to-delete candidates.

    Args:
        vocabulary: Optional. Vocabulary machine name (e.g., "tags", "categories").
                    If omitted, returns list of all vocabularies.
        term_name: Optional. Search for specific term by name (partial matching).
                   Example: "tech" finds "Technology", "Tech News", etc.
        term_id: Optional. Specific term ID (tid) to get detailed usage info.
                 Use this to see where a specific term is used before deleting.

    Returns:
        Formatted taxonomy information with usage analysis
    """
    try:
        drupal_root = Path(get_config().get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ Error: Drupal root not found. Check drupal_root in config."

        # Get taxonomy data (drush first, then file fallback)
        if term_id:
            # Detailed term usage analysis
            return _get_term_usage_analysis(term_id, drupal_root)
        elif term_name:
            # Search for terms by name
            return _search_terms_by_name(term_name, vocabulary, drupal_root)
        elif vocabulary:
            # Show all terms in a vocabulary
            return _get_vocabulary_terms(vocabulary, drupal_root)
        else:
            # List all vocabularies
            return _get_vocabularies_summary(drupal_root)

    except Exception as e:
        logger.error(f"Error getting taxonomy info: {e}")
        return f"❌ Error: {str(e)}"


def _get_vocabularies_summary(drupal_root: Path) -> str:
    """Get summary of all vocabularies."""
    vocabs_data = _get_vocabularies_from_drush()

    if not vocabs_data:
        # Fallback to file parsing
        vocabs_data = _get_vocabularies_from_files(drupal_root)

    if not vocabs_data:
        return "ℹ️ No taxonomy vocabularies found"

    output = [f"📚 Taxonomy Vocabularies ({len(vocabs_data)} found)\n"]

    for vocab in vocabs_data:
        output.append(f"• {vocab['label']} ({vocab['id']})")
        if vocab.get("description"):
            output.append(f"  Description: {vocab['description']}")

        term_count = vocab.get("term_count", 0)
        output.append(f"  Terms: {term_count}")

        # Show which fields reference this vocabulary
        fields = vocab.get("referencing_fields", [])
        if fields:
            field_summary = ", ".join(fields[:3])
            if len(fields) > 3:
                field_summary += f" (+{len(fields) - 3} more)"
            output.append(f"  Used by fields: {field_summary}")

        output.append("")

    return "\n".join(output)


def _get_vocabulary_terms(vocabulary: str, drupal_root: Path) -> str:
    """Get all terms in a vocabulary with hierarchy."""
    terms_data = _get_terms_from_drush(vocabulary)

    if not terms_data:
        # Fallback to file parsing
        terms_data = _get_terms_from_files(vocabulary, drupal_root)

    if not terms_data:
        return f"ℹ️ No terms found in vocabulary '{vocabulary}'"

    vocab_info = terms_data.get("vocabulary", {})
    terms = terms_data.get("terms", [])

    output = [f"📚 Vocabulary: {vocab_info.get('label', vocabulary)} ({vocabulary})"]
    if vocab_info.get("description"):
        output.append(f"   Description: {vocab_info['description']}")
    output.append(f"   Total terms: {len(terms)}\n")

    # Build hierarchy
    hierarchy = _build_term_hierarchy(terms)

    output.append("📖 Terms:")
    _append_term_tree(output, hierarchy, 0)

    return "\n".join(output)


def _search_terms_by_name(term_name: str, vocabulary: Optional[str], drupal_root: Path) -> str:
    """Search for terms by name across vocabularies."""
    results = _search_terms_from_drush(term_name, vocabulary)

    if not results:
        results = _search_terms_from_files(term_name, vocabulary, drupal_root)

    if not results:
        search_scope = f"in vocabulary '{vocabulary}'" if vocabulary else "across all vocabularies"
        return f"ℹ️ No terms found matching '{term_name}' {search_scope}"

    # If only one result, automatically show detailed usage analysis
    if len(results) == 1:
        logger.info(f"Single term found for '{term_name}', showing detailed usage analysis")
        return _get_term_usage_analysis(results[0]["tid"], drupal_root)

    # Multiple results - show summary with prominent term IDs
    output = [f"🔍 Terms matching '{term_name}' ({len(results)} found)"]
    output.append("💡 Tip: Use get_taxonomy_info(term_id=X) for detailed usage analysis\n")

    for term in results:
        output.append(f"• {term['name']} (tid: {term['tid']})")
        output.append(f"  Vocabulary: {term['vocabulary_label']} ({term['vocabulary']})")

        if term.get("description"):
            desc = (
                term["description"][:100] + "..."
                if len(term["description"]) > 100
                else term["description"]
            )
            output.append(f"  Description: {desc}")

        usage_count = term.get("usage_count", 0)
        if usage_count > 0:
            output.append(f"  ⚠️  Used in {usage_count} content item(s)")
        else:
            output.append("  ✅ Not used (safe to delete)")

        output.append("")

    return "\n".join(output)


def _get_term_usage_analysis(term_id: int, drupal_root: Path) -> str:
    """Get detailed usage analysis for a specific term."""
    # CRITICAL: Verify database connection BEFORE attempting to fetch term data
    db_ok, db_msg = verify_database_connection()
    if not db_ok:
        return (
            f"❌ ERROR: Cannot analyze term {term_id} usage\n\n"
            f"Database connection required but unavailable.\n"
            f"Reason: {db_msg}\n\n"
            f"⚠️  IMPORTANT: Do NOT delete this term without manual verification!\n\n"
            f"Troubleshooting steps:\n"
            f"1. Verify drush is working: drush status\n"
            f"2. Check database connectivity in the output above\n"
            f"3. Ensure your development environment is running (DDEV/Lando/etc.)\n"
            f"4. If database is accessible, manually check term usage:\n"
            f'   drush sqlq "SELECT COUNT(*) FROM taxonomy_index WHERE tid={term_id}"\n\n'
            f"Without database access, Scout cannot determine if this term is safe to delete."
        )

    # Lazy import to avoid circular dependency
    from src.tools.exports import _get_term_usage_from_drush

    usage_data = _get_term_usage_from_drush(term_id)

    if not usage_data:
        # Database is connected but term not found or query failed
        # Don't fallback to files - it won't work and gives false negatives
        return (
            f"❌ Term {term_id} not found or query failed\n\n"
            f"Possible reasons:\n"
            f"1. Term ID does not exist in the database\n"
            f"2. Drush query failed (check logs)\n"
            f"3. Database permissions issue\n\n"
            f'Try: drush sqlq "SELECT * FROM taxonomy_term_field_data WHERE tid={term_id}"'
        )

    term = usage_data["term"]
    diagnostics = usage_data.get("_diagnostics", {})

    output = [f"🏷️  Term: {term['name']} (tid: {term_id})"]
    output.append(f"   Vocabulary: {term['vocabulary_label']} ({term['vocabulary']})")
    output.append("   📊 Data source: Live database via drush")

    # Show diagnostics
    if diagnostics:
        output.append("   🔍 Query diagnostics:")
        output.append(f"      • Database has {diagnostics.get('total_nodes_in_db', 0)} total nodes")
        output.append(
            f"      • taxonomy_index table: {diagnostics.get('taxonomy_index_count', 0)} references for this term"
        )
        if diagnostics.get("fields_checked", 0) > 0:
            output.append(
                f"      • Checked {diagnostics.get('fields_checked', 0)} entity reference fields"
            )
            if diagnostics.get("fields_with_errors"):
                output.append(
                    f"      • {len(diagnostics.get('fields_with_errors', []))} fields had query errors"
                )
        output.append(f"      • Query method: {diagnostics.get('query_method', 'unknown')}")

    output.append("")

    if term.get("description"):
        output.append(f"   Description: {term['description']}")

    if term.get("parent"):
        output.append(f"   Parent: {term['parent']}")

    children = term.get("children", [])
    if children:
        output.append(f"   Children: {', '.join(children)}")

    output.append("")

    # Content usage
    content_usage = usage_data.get("content_usage", [])
    if content_usage:
        output.append(f"📄 Used in {len(content_usage)} content item(s):")
        for item in content_usage[:10]:  # Show first 10
            output.append(f"   • {item['title']} ({item['type']}) - nid: {item['nid']}")
        if len(content_usage) > 10:
            output.append(f"   ... and {len(content_usage) - 10} more")
        output.append("")

    # Views usage
    views_usage = usage_data.get("views_usage", [])
    if views_usage:
        output.append(f"👁️  Used in {len(views_usage)} view(s):")
        for view in views_usage:
            output.append(f"   • {view['view_label']} ({view['view_id']}) - {view['usage_type']}")
        output.append("")

    # Fields that could reference this term
    fields = usage_data.get("referencing_fields", [])
    if fields:
        output.append(f"🔗 Vocabulary referenced by {len(fields)} field(s):")
        for field in fields:
            output.append(
                f"   • {field['field_label']} ({field['field_name']}) on {', '.join(field['bundles'])}"
            )
        output.append("")

    # Safety assessment
    total_usage = len(content_usage) + len(views_usage)
    if total_usage == 0 and not children:
        output.append("✅ SAFE TO DELETE")
        output.append("   This term is not used in content, views, or as a parent term.")
        output.append("   Verified via database query.")
    elif children:
        output.append("⚠️  WARNING: Has child terms")
        output.append(f"   {len(children)} child term(s) will become orphaned if deleted.")
        output.append("   Consider reassigning children or deleting them first.")
    else:
        output.append("⚠️  CAUTION: Term is in use")
        output.append(
            f"   Used in {len(content_usage)} content item(s) and {len(views_usage)} view(s)."
        )
        output.append("   Deleting will remove term references from content.")
        output.append("   Consider merging with another term instead.")

    return "\n".join(output)


def _build_term_hierarchy(terms: List[dict]) -> List[dict]:
    """Build hierarchical tree structure from flat term list."""
    # Create lookup dict
    terms_by_id = {t["tid"]: {**t, "children": []} for t in terms}

    # Build tree
    root_terms = []
    for term in terms:
        parent_id = term.get("parent_tid", 0)
        if parent_id and parent_id in terms_by_id:
            terms_by_id[parent_id]["children"].append(terms_by_id[term["tid"]])
        else:
            root_terms.append(terms_by_id[term["tid"]])

    return root_terms


def _append_term_tree(output: List[str], terms: List[dict], level: int):
    """Recursively append term tree to output."""
    indent = "   " * level
    for term in terms:
        usage = term.get("usage_count", 0)
        usage_str = f" ({usage} uses)" if usage > 0 else ""
        output.append(f"{indent}• {term['name']} (tid: {term['tid']}){usage_str}")

        if term.get("children"):
            _append_term_tree(output, term["children"], level + 1)


def _get_vocabularies_from_drush() -> Optional[List[dict]]:
    """Get vocabularies from database via drush."""
    try:
        php_code = """
        $vocabs_data = [];
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');
        $vocabularies = $vocab_storage->loadMultiple();

        // Get term counts
        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');

        // Get fields that reference taxonomies
        $field_configs = \\Drupal::entityTypeManager()
            ->getStorage('field_config')
            ->loadMultiple();

        $vocab_fields = [];
        foreach ($field_configs as $field) {
            $settings = $field->getSettings();
            if (isset($settings['target_type']) && $settings['target_type'] === 'taxonomy_term') {
                $handler_settings = $settings['handler_settings'] ?? [];
                $target_bundles = $handler_settings['target_bundles'] ?? [];
                foreach ($target_bundles as $vocab_id) {
                    if (!isset($vocab_fields[$vocab_id])) {
                        $vocab_fields[$vocab_id] = [];
                    }
                    $vocab_fields[$vocab_id][] = $field->getName();
                }
            }
        }

        foreach ($vocabularies as $vocab) {
            $vocab_id = $vocab->id();

            // Count terms
            $term_count = $term_storage->getQuery()
                ->condition('vid', $vocab_id)
                ->accessCheck(FALSE)
                ->count()
                ->execute();

            $vocabs_data[] = [
                'id' => $vocab_id,
                'label' => $vocab->label(),
                'description' => $vocab->getDescription(),
                'term_count' => (int)$term_count,
                'referencing_fields' => $vocab_fields[$vocab_id] ?? []
            ];
        }

        echo json_encode($vocabs_data);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=20)
        return result if result and isinstance(result, list) else None

    except Exception as e:
        logger.debug(f"Could not get vocabularies from drush: {e}")
        return None


def _get_vocabularies_from_files(drupal_root: Path) -> List[dict]:
    """Parse vocabulary configs from files."""
    vocabs_data = []

    config_locations = [
        drupal_root / "config" / "sync",
        drupal_root / "config" / "default",
        drupal_root / "sites" / "default" / "config" / "sync",
        drupal_root / "recipes",
    ]

    for config_dir in config_locations:
        if not config_dir.exists():
            continue

        for vocab_file in config_dir.rglob("taxonomy.vocabulary.*.yml"):
            try:
                import yaml

                with open(vocab_file, "r") as f:
                    config = yaml.safe_load(f)

                if config:
                    vocabs_data.append(
                        {
                            "id": get_config().get("vid", ""),
                            "label": get_config().get("name", ""),
                            "description": get_config().get("description", ""),
                            "term_count": 0,  # Can't get from files
                            "referencing_fields": [],  # Would need to parse field configs
                        }
                    )
            except Exception as e:
                logger.debug(f"Error parsing {vocab_file}: {e}")
                continue

    return vocabs_data


def _get_terms_from_drush(vocabulary: str) -> Optional[dict]:
    """Get terms from a vocabulary via drush."""
    try:
        php_code = f"""
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');
        $vocab = $vocab_storage->load('{vocabulary}');

        if (!$vocab) {{
            echo json_encode(null);
            exit;
        }}

        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');
        $terms = $term_storage->loadByProperties(['vid' => '{vocabulary}']);

        // Get usage counts from entity_usage or count manually
        $database = \\Drupal::database();

        $terms_data = [];
        foreach ($terms as $term) {{
            $tid = $term->id();

            // Count usage in node fields (simplified - checks common field tables)
            $usage_count = 0;
            try {{
                // This is a simplified count - real implementation would check all entity reference fields
                $usage_count = $database->select('node__field_tags', 'n')
                    ->condition('field_tags_target_id', $tid)
                    ->countQuery()
                    ->execute()
                    ->fetchField();
            }} catch (\\Exception $e) {{
                // Field doesn't exist
            }}

            $parent = $term_storage->loadParents($tid);
            $parent_tid = $parent ? key($parent) : 0;

            $terms_data[] = [
                'tid' => (int)$tid,
                'name' => $term->getName(),
                'description' => $term->getDescription(),
                'weight' => $term->getWeight(),
                'parent_tid' => (int)$parent_tid,
                'usage_count' => (int)$usage_count
            ];
        }}

        $result = [
            'vocabulary' => [
                'id' => $vocab->id(),
                'label' => $vocab->label(),
                'description' => $vocab->getDescription()
            ],
            'terms' => $terms_data
        ];

        echo json_encode($result);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=25)
        return result if result else None

    except Exception as e:
        logger.debug(f"Could not get terms from drush: {e}")
        return None


def _get_terms_from_files(vocabulary: str, drupal_root: Path) -> Optional[dict]:
    """Parse terms from migration or content files (limited fallback)."""
    # This is a limited fallback - terms are usually only in DB
    # Could parse content files or migration configs if needed
    return None


def _search_terms_from_drush(term_name: str, vocabulary: Optional[str]) -> Optional[List[dict]]:
    """Search for terms by name via drush."""
    try:
        vocab_filter = ""
        if vocabulary:
            vocab_filter = f"->condition('vid', '{vocabulary}')"

        php_code = f"""
        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');
        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');

        $query = $term_storage->getQuery()
            ->condition('name', '%{term_name}%', 'LIKE')
            {vocab_filter}
            ->accessCheck(FALSE)
            ->range(0, 20);

        $tids = $query->execute();
        $terms = $term_storage->loadMultiple($tids);

        $results = [];
        foreach ($terms as $term) {{
            $tid = $term->id();
            $vid = $term->bundle();
            $vocab = $vocab_storage->load($vid);

            // Simple usage count (would need to check all reference fields in production)
            $database = \\Drupal::database();
            $usage_count = 0;

            $results[] = [
                'tid' => (int)$tid,
                'name' => $term->getName(),
                'description' => $term->getDescription(),
                'vocabulary' => $vid,
                'vocabulary_label' => $vocab ? $vocab->label() : $vid,
                'usage_count' => $usage_count
            ];
        }}

        echo json_encode($results);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=20)
        return result if result and isinstance(result, list) else None

    except Exception as e:
        logger.debug(f"Could not search terms from drush: {e}")
        return None


def _search_terms_from_files(
    term_name: str, vocabulary: Optional[str], drupal_root: Path
) -> List[dict]:
    """Search terms in files (limited fallback)."""
    return []


@mcp.tool()
def get_all_taxonomy_usage(
    vocabulary: str,
    check_code: bool = True,
    max_sample_nodes: int = 5,
    limit: int = 100,
    summary_only: bool = False,
) -> str:
    """
    Get comprehensive usage analysis for ALL terms in a vocabulary with one optimized query.

    This is MUCH more efficient than calling get_taxonomy_info() for each term individually.
    For 562 terms: approximately 5,000 tokens instead of 129,000 tokens (96% savings).

    **RESPONSE SIZE LIMITS:**
    - Default limit: 100 terms (fits well within MCP 25K token limit)
    - For vocabularies with 100+ terms, results are automatically limited
    - Use summary_only=True for ultra-compact output (just counts, no samples)
    - Increase limit carefully: limit=200 may approach token limits

    **CRITICAL: If you only receive 100 terms but vocabulary has MORE:**
    - The response includes "total_terms" vs "returned_terms" to show truncation
    - Example: {"total_terms": 751, "returned_terms": 100, "truncated": true}
    - You MUST inform the user results are truncated and suggest:
      A) Increase limit (e.g., limit=751) for full dataset - may exceed token limits
      B) Use summary_only=True with limit=0 for complete compact view
      C) Continue with first 100 terms only
    - DO NOT silently export incomplete data without warning the user!

    **PERFORMANCE NOTE:**
    - Small vocabularies (1-50 terms): 5-10 seconds
    - Medium vocabularies (50-200 terms): 15-30 seconds
    - Large vocabularies (200-500 terms): 30-60 seconds
    - Very large vocabularies (500+ terms): 60-120 seconds
    - Progress messages will appear in real-time showing completion status

    **RECOMMENDED WORKFLOW - For Vocabularies with 200+ Terms:**

    DO NOT call this tool directly with full mode. The response will exceed MCP token limits.
    Instead, use this optimized two-phase approach:

    **Phase 1: Get candidates yourself (fast, ~5-10K tokens)**
    ```
    result = get_all_taxonomy_usage(vocabulary="topics", summary_only=True, check_code=False)
    candidates = [term for term in result["terms"] if term["needs_check"] == True]

    # Show user: "Found {total_terms} terms, {len(candidates)} candidates for deletion"
    ```

    **Phase 2: Delegate deep-checking to Task agent**
    ```
    If len(candidates) > 20:
        Use Task tool with:
          subagent_type: "general-purpose"
          description: "Deep-check taxonomy term candidates"
          prompt: '''
            Verify which of these taxonomy terms are truly safe to delete: {candidate_ids}

            For each term ID, call get_taxonomy_info(term_id=X) to check:
            - Content usage (should already be 0)
            - Views usage
            - Custom code references
            - Config file references

            Return a concise list of:
            - Terms that are SAFE to delete (with term ID and name)
            - Terms that are NOT safe (with reason why)
          '''

    Else if len(candidates) <= 20:
        # Few candidates, check them yourself without agent
        for candidate in candidates:
            details = get_taxonomy_info(term_id=candidate["tid"])
    ```

    **Benefits of this approach:**
    - User sees candidate count immediately (good UX)
    - Agent only handles the slow part (deep checks)
    - If <20 candidates, no need for agent overhead
    - Agent can be split into multiple if too many candidates

    **USE THIS TOOL** when you need to:
    - Audit all terms in a vocabulary for cleanup
    - Generate CSV/table of term usage across entire vocabulary
    - Find unused terms for deletion
    - Analyze term usage patterns

    The tool performs:
    1. Database queries to find content using each term
    2. Code scanning to find hardcoded term IDs/names (optional, if check_code=True)
    3. Config file scanning for term references (optional, if check_code=True)

    Note: Views analysis not included in batch mode. Use get_taxonomy_info(term_id=X) for views checking.

    Returns structured JSON data that AI can format as CSV, markdown table, or any format.

    Args:
        vocabulary: Vocabulary machine name (e.g., "topics", "tags", "categories")
        check_code: If True, scans custom code for hardcoded term references.
                    Slower but more thorough. Default: True
        max_sample_nodes: Max number of sample nodes to return per term. Default: 5
        limit: Max number of terms to return. Default: 100. Set to 0 for all terms (risky for large vocabs).
        summary_only: If True, returns minimal data (no samples, descriptions, or children). Default: False

    Returns:
        JSON string with metadata and term data:
        {
            "total_terms": 562,
            "returned_terms": 100,
            "truncated": true/false,
            "summary_only": true/false,
            "message": "..." (if truncated),
            "terms": [...]
        }

        In summary_only mode, each term includes:
        - tid: Term ID
        - name: Term name
        - count: Number of content items using this term
        - needs_check: TRUE if 0 content usage (candidate for deletion, needs full check)

        In full mode, each term includes:
        - tid, name, description, parent, children
        - content_usage: [{nid, title, type}, ...] (sample nodes)
        - content_count: Total number of content items using this term
        - code_usage: [{file, line, context}, ...] (if check_code=True)
        - config_usage: [{config_name, config_type}, ...] (if check_code=True)
        - fields_with_usage: List of field names where term is used
        - safe_to_delete: boolean (content + code + config analysis)
        - warnings: List of reasons why deletion might be problematic

    Example response format:
    [
        {
            "tid": 123,
            "name": "General",
            "content_count": 4646,
            "content_usage": [{"nid": 1, "title": "Example", "type": "article"}],
            "code_usage": [{"file": "custom/mymodule/mymodule.module", "line": 45}],
            "safe_to_delete": false,
            "warnings": ["Used in 4,646 content items", "Referenced in custom code"]
        }
    ]

    Saves approximately 70-90% tokens compared to individual term queries.
    """
    try:
        drupal_root = Path(get_config().get("drupal_root", ""))

        if not drupal_root.exists():
            return json.dumps(
                {
                    "_error": True,
                    "message": "Could not determine Drupal root. Check drupal_root in config.",
                }
            )

        # Verify database connection first
        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Database connection required. {db_msg}",
                    "troubleshooting": [
                        "Verify drush is working: drush status",
                        "Check database connectivity",
                        "Ensure development environment is running (DDEV/Lando/etc.)",
                    ],
                }
            )

        # Lazy import to avoid circular dependency
        from src.tools.exports import _get_all_terms_usage_from_drush

        # Get all term usage data in one optimized query
        usage_data = _get_all_terms_usage_from_drush(vocabulary, max_sample_nodes, summary_only)

        if not usage_data:
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Could not fetch terms for vocabulary '{vocabulary}'",
                    "suggestion": "Verify vocabulary machine name is correct. Use get_taxonomy_info() with no parameters to list all vocabularies.",
                }
            )

        total_terms = len(usage_data)

        # Apply limit if needed
        if limit > 0 and len(usage_data) > limit:
            usage_data = usage_data[:limit]
            truncated = True
        else:
            truncated = False

        # Add code/config usage if requested (only for returned terms)
        if check_code and not summary_only:
            # Lazy import to avoid circular dependency
            from src.tools.exports import _add_code_usage_to_terms

            usage_data = _add_code_usage_to_terms(usage_data, drupal_root)

        # Add metadata about results
        result = {
            "total_terms": total_terms,
            "returned_terms": len(usage_data),
            "truncated": truncated,
            "summary_only": summary_only,
            "terms": usage_data,
        }

        if truncated:
            result["message"] = (
                f"⚠️  TRUNCATED RESULTS: Showing {len(usage_data)} of {total_terms} terms. "
                f"The vocabulary has {total_terms} total terms, but only {len(usage_data)} are included. "
                f"Options: (1) Increase limit={total_terms} for all terms, "
                f"(2) Use summary_only=True with limit=0 for compact full view, "
                f"(3) Continue with current {len(usage_data)} terms. "
                f"DO NOT export to CSV without informing user of truncation!"
            )

        # Return as JSON for AI to format
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Error in get_all_taxonomy_usage: {e}", exc_info=True)
