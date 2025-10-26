"""
Export tools for Drupal Scout MCP.

Provides CSV export functionality for large datasets:
- export_taxonomy_usage_to_csv: Export taxonomy terms to CSV
- export_nodes_to_csv: Export nodes/content to CSV
- export_users_to_csv: Export user accounts to CSV

These tools bypass MCP token limits by writing directly to filesystem.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional, List

# Import from core modules (no circular dependency)
from src.core.config import load_config
from src.core.drush import get_drush_command, run_drush_command
from src.core.database import verify_database_connection

# Import MCP instance from server (used for @mcp.tool() decorator)
from server import mcp

# Get logger
logger = logging.getLogger(__name__)

# Note: This file contains export tools extracted from server.py
# Import order: server.py creates mcp instance → this file imports it and registers tools


@mcp.tool()
def export_taxonomy_usage_to_csv(
    vocabulary: str,
    output_path: Optional[str] = None,
    check_code: bool = False,
    summary_only: bool = True,
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
    import csv
    from datetime import datetime

    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

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
                }
            )

        # Auto-generate path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Save in Drupal root directory for easy access in IDE
            output_path = str(drupal_root / f"taxonomy_export_{vocabulary}_{timestamp}.csv")

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
    import csv
    from datetime import datetime

    try:
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
                }
            )

        # Auto-generate path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            type_suffix = f"_{content_type}" if content_type else "_all"
            output_path = str(drupal_root / f"nodes_export{type_suffix}_{timestamp}.csv")

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


@mcp.tool()
def export_users_to_csv(
    output_path: Optional[str] = None,
    summary_only: bool = True,
    include_field_data: bool = False,
    include_blocked: bool = False,
    limit: int = 0,
) -> str:
    """
    Export user account data directly to CSV file, bypassing MCP token limits.

    **BEST SOLUTION FOR USER AUDITS AND MIGRATION PLANNING**

    Perfect for:
    - User account auditing and inventory
    - Compliance reporting (GDPR, security audits)
    - Migration planning and user mapping
    - Finding inactive or old accounts
    - User profile analysis and cleanup

    **How It Works:**
    1. Queries all user accounts via drush
    2. Fetches comprehensive user data including roles, activity, and custom fields
    3. Writes CSV directly to Drupal root directory
    4. Returns tiny response with file path and stats

    **Performance:**
    - 100 users: ~5 seconds
    - 500 users: ~15 seconds
    - 1000 users: ~30 seconds
    - 5000 users: ~2 minutes

    Args:
        output_path: Optional CSV file path. If not provided, auto-generates:
                     {drupal_root}/users_export_{timestamp}.csv
        summary_only: If True, exports essential columns (uid, name, email, status, roles, created).
                     If False, exports FULL details including:
                       - uid, uuid, name, email, status, langcode
                       - created, changed, access (last login), login (last access)
                       - roles (comma-separated list)
                       - timezone, preferred_langcode, init (original email)
                       - login_count, access_count (if tracked)
                       - picture (user avatar/profile picture info)
                       - All custom user profile fields
                     Default: True (faster for large user bases)
        include_field_data: If True, includes custom user field values (profile fields).
                     **SMART PROMPTING - Set to True when user asks for:**
                     - "profile data", "profile fields", "user fields"
                     - "custom fields", "field values", "all data"
                     - "migration data", "complete export"
                     **Keep False (default) for:**
                     - Basic inventory, metadata-only exports
                     - Quick audits focusing on roles/activity/status
                     **Performance impact:** Adds 20-30% to export time
                     Default: False
        include_blocked: If True, includes blocked/disabled user accounts. Default: False
        limit: Max users to export. 0 = all users. Default: 0

    Returns:
        JSON with file path, stats, and preview:
        {
            "file_path": "/path/to/drupal/users_export_20251025.csv",
            "total_users": 523,
            "roles": ["authenticated", "administrator", "editor"],
            "file_size_kb": 85,
            "columns": [...],
            "preview": "..."
        }

    **Column Details (Full Mode):**

    Basic Info:
    - uid, uuid, name (username), email, status (active/blocked)
    - langcode, preferred_langcode, timezone, init (original email at registration)

    Activity:
    - created (registration timestamp), changed (last profile update)
    - access (last login timestamp), login (most recent access)
    - login_count (if available), access_count (if available)

    Authorization:
    - roles (administrator | editor | content_creator)

    Profile:
    - picture (profile picture file info)
    - Custom profile fields (if include_field_data=True)

    **Examples:**

    Fast summary of all active users:
    export_users_to_csv(summary_only=True)

    Full audit including blocked users:
    export_users_to_csv(summary_only=False, include_blocked=True)

    Migration prep with all profile data:
    export_users_to_csv(summary_only=False, include_field_data=True, include_blocked=True)
    """
    import csv
    from datetime import datetime

    try:
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
                }
            )

        # Auto-generate path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(drupal_root / f"users_export_{timestamp}.csv")

        # Validate path is writable
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Get all users via drush
        logger.info("Fetching users...")
        users = _get_all_users_from_drush(
            drupal_root=drupal_root,
            summary_only=summary_only,
            include_blocked=include_blocked,
            include_field_data=include_field_data,
            limit=limit,
        )

        if users is None:
            return json.dumps(
                {
                    "_error": True,
                    "message": "Failed to fetch users from Drupal. Check server logs for details.",
                    "suggestion": "Verify drush is working: drush status",
                }
            )

        if not users or len(users) == 0:
            debug_info = {
                "_error": True,
                "message": "No users found",
                "filters_applied": {
                    "include_blocked": include_blocked,
                    "limit": limit if limit > 0 else "no limit",
                },
                "suggestion": "Try running: drush ev \"echo count(\\\\Drupal::entityQuery('user')->accessCheck(FALSE)->execute());\" to verify users exist",
            }
            return json.dumps(debug_info)

        total_users = len(users)

        # Get unique roles
        all_roles = set()
        for user in users:
            if user.get("roles"):
                roles = (
                    user["roles"].split(" | ") if isinstance(user["roles"], str) else user["roles"]
                )
                all_roles.update(roles)
        roles_list = sorted(list(all_roles))

        # Determine CSV columns
        if summary_only:
            columns = ["uid", "name", "email", "status", "roles", "created", "access"]
        else:
            # Base columns
            columns = [
                "uid",
                "uuid",
                "name",
                "email",
                "status",
                "langcode",
                "created",
                "changed",
                "access",
                "login",
                "roles",
                "timezone",
                "preferred_langcode",
                "init",
                "picture",
            ]

            # Add field data columns if requested
            if include_field_data:
                # Collect all custom field names from all users
                custom_fields = set()
                for user in users:
                    for key in user.keys():
                        # Add fields that aren't in base columns
                        if key not in columns and key not in [
                            "uid",
                            "uuid",
                            "name",
                            "mail",
                            "status",
                            "langcode",
                            "created",
                            "changed",
                            "access",
                            "login",
                            "init",
                            "timezone",
                            "preferred_langcode",
                        ]:
                            custom_fields.add(key)

                # Add custom fields to columns (sorted for consistency)
                columns.extend(sorted(custom_fields))

        # Write CSV
        logger.info(f"Writing {total_users} users to {output_path}...")
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()

            for user in users:
                row = {}
                for col in columns:
                    value = user.get(col, "")

                    # Format lists with pipe separator
                    if isinstance(value, list):
                        value = " | ".join(str(v) for v in value)

                    # Convert booleans to YES/NO
                    elif isinstance(value, bool):
                        value = "YES" if value else "NO"

                    # Format timestamps
                    elif col in ["created", "changed", "access", "login"] and isinstance(
                        value, (int, float)
                    ):
                        if value > 0:
                            value = datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            value = "Never" if col in ["access", "login"] else value

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
            "total_users": total_users,
            "roles": roles_list,
            "file_size_kb": file_size_kb,
            "columns": columns,
            "preview": preview,
            "message": f"✅ Successfully exported {total_users} users to {output_path} ({file_size_kb} KB)",
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Error in export_users_to_csv: {e}", exc_info=True)
        return json.dumps({"_error": True, "message": str(e)})


def _get_all_users_from_drush(
    drupal_root: Path,
    summary_only: bool = True,
    include_blocked: bool = False,
    include_field_data: bool = False,
    limit: int = 0,
) -> Optional[List[dict]]:
    """Get comprehensive user data via optimized drush query."""
    try:
        # Build filters as proper PHP lines
        filters = []
        if not include_blocked:
            filters.append("$query->condition('status', 1);")
        if limit > 0:
            filters.append(f"$query->range(0, {limit});")

        filters_code = "\n        ".join(filters) if filters else "// No additional filters"

        # Build PHP code for drush
        php_code = f"""
        $user_storage = \\Drupal::entityTypeManager()->getStorage('user');
        $summary_only = {str(summary_only).lower()};
        $include_field_data = {str(include_field_data).lower()};

        // Query users (exclude anonymous user uid=0)
        $query = \\Drupal::entityQuery('user')->accessCheck(FALSE);
        $query->condition('uid', 0, '>');

        // Add filters
        {filters_code}

        $query->sort('created', 'DESC');
        $uids = $query->execute();

        if (empty($uids)) {{
            echo json_encode([]);
            exit;
        }}

        $users = $user_storage->loadMultiple($uids);
        $results = [];
        $total = count($users);
        $count = 0;

        fwrite(STDERR, "Analyzing $total users...\\n");

        foreach ($users as $user) {{
            $count++;
            if ($count % 100 == 0) {{
                fwrite(STDERR, "Progress: $count / $total users\\n");
            }}

            // Get user roles (exclude 'authenticated' as it's implicit)
            $roles = $user->getRoles(TRUE);  // TRUE excludes 'authenticated'

            $data = [
                'uid' => (int) $user->id(),
                'uuid' => $user->uuid(),
                'name' => $user->getAccountName(),
                'email' => $user->getEmail(),
                'status' => $user->isActive() ? 'active' : 'blocked',
                'langcode' => $user->language()->getId(),
                'created' => (int) $user->getCreatedTime(),
                'changed' => (int) $user->getChangedTime(),
                'access' => (int) $user->getLastAccessedTime(),
                'login' => (int) $user->getLastLoginTime(),
                'roles' => $roles,
            ];

            if (!$summary_only) {{
                // Additional user metadata
                $data['timezone'] = $user->getTimeZone() ?? '';
                $data['preferred_langcode'] = $user->getPreferredLangcode() ?? '';
                $data['init'] = $user->getInitialEmail() ?? '';

                // User picture
                $picture = '';
                if ($user->hasField('user_picture') && !$user->get('user_picture')->isEmpty()) {{
                    $picture_entity = $user->get('user_picture')->entity;
                    if ($picture_entity) {{
                        $picture = $picture_entity->getFileUri();
                    }}
                }}
                $data['picture'] = $picture;

                // Field data extraction (if requested)
                if ($include_field_data) {{
                    // Extract custom fields
                    $field_data = [];
                    foreach ($user->getFields() as $field_name => $field) {{
                        // Skip base/computed fields
                        if (in_array($field_name, ['uid', 'uuid', 'langcode', 'name', 'mail', 'pass', 'status', 'created', 'changed', 'access', 'login', 'init', 'roles', 'default_langcode', 'user_picture', 'timezone', 'preferred_langcode', 'preferred_admin_langcode'])) {{
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
                            $count_imgs = count($field->referencedEntities());
                            $field_data[$field_name] = implode(' | ', $field_values) . " ($count_imgs images)";
                        }} elseif ($field_type === 'entity_reference') {{
                            foreach ($field->referencedEntities() as $ref_entity) {{
                                $target_type = $field->getFieldDefinition()->getSetting('target_type');
                                $field_values[] = $target_type . ':' . $ref_entity->id();
                            }}
                            if (!empty($field_values)) {{
                                $field_data[$field_name] = implode(' | ', $field_values);
                            }}
                        }} elseif ($field_type === 'link') {{
                            foreach ($field as $link) {{
                                if ($link->uri) {{
                                    $field_values[] = $link->uri;
                                }}
                            }}
                            if (!empty($field_values)) {{
                                $field_data[$field_name] = implode(' | ', $field_values);
                            }}
                        }} elseif ($field_type === 'text' || $field_type === 'text_long' || $field_type === 'string') {{
                            $text_value = $field->value;
                            if ($text_value) {{
                                $field_data[$field_name] = mb_substr(strip_tags($text_value), 0, 500);
                            }}
                        }} elseif ($field_type === 'boolean') {{
                            $field_data[$field_name] = $field->value ? 'YES' : 'NO';
                        }} elseif ($field_type === 'datetime' || $field_type === 'timestamp') {{
                            $dt_value = $field->value;
                            if ($dt_value) {{
                                $field_data[$field_name] = $dt_value;
                            }}
                        }} else {{
                            // Generic handling for other field types
                            $generic_value = $field->value ?? $field->getString();
                            if ($generic_value) {{
                                $field_data[$field_name] = $generic_value;
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

        fwrite(STDERR, "Completed: $total users\\n");
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
            users = json.loads(result.stdout)
            return users
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output: {e}")
            logger.error(f"Raw output: {result.stdout}")
            return None

    except Exception as e:
        logger.error(f"Error in _get_all_users_from_drush: {e}", exc_info=True)
        return None


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


def _get_all_terms_usage_from_drush(
    vocabulary: str, max_sample_nodes: int = 5, summary_only: bool = False
) -> Optional[List[dict]]:
    """Get usage data for all terms in a vocabulary via optimized drush query."""
    try:
        php_code = f"""
        $vocabulary = '{vocabulary}';
        $max_samples = {max_sample_nodes};
        $summary_only = {str(summary_only).lower()};

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
        $term_ids = \\Drupal::entityQuery('taxonomy_term')
            ->accessCheck(FALSE)
            ->condition('vid', $vocabulary)
            ->execute();

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


def _get_term_usage_from_drush(term_id: int) -> Optional[dict]:
    """Get detailed usage analysis for a term via drush."""
    try:
        php_code = f"""
        $tid = {term_id};
        $term_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_term');
        $term = $term_storage->load($tid);

        if (!$term) {{
            echo json_encode(null);
            exit;
        }}

        $vocab_storage = \\Drupal::entityTypeManager()->getStorage('taxonomy_vocabulary');
        $vocab = $vocab_storage->load($term->bundle());

        // Get term info
        $parents = $term_storage->loadParents($tid);
        $parent_name = $parents ? reset($parents)->getName() : null;

        $children = $term_storage->loadChildren($tid);
        $children_names = array_map(function($child) {{ return $child->getName(); }}, $children);

        // DIAGNOSTIC: Get database stats
        $database = \\Drupal::database();

        // Check taxonomy_index table (Drupal's optional term tracking)
        $taxonomy_index_count = $database->query(
            "SELECT COUNT(*) FROM {{taxonomy_index}} WHERE tid = :tid",
            [':tid' => $tid]
        )->fetchField();

        // Check total nodes
        $total_nodes = $database->query("SELECT COUNT(*) FROM {{node_field_data}}")->fetchField();

        // Find content using this term
        $node_storage = \\Drupal::entityTypeManager()->getStorage('node');
        $content_usage = [];
        $nids_found = [];

        // METHOD 1: Check taxonomy_index table (if populated)
        if ($taxonomy_index_count > 0) {{
            $nids = $database->query(
                "SELECT DISTINCT nid FROM {{taxonomy_index}} WHERE tid = :tid LIMIT 20",
                [':tid' => $tid]
            )->fetchCol();
            if ($nids) {{
                $nids_found = array_merge($nids_found, $nids);
            }}
        }}

        // METHOD 2: Check field data tables directly (CRITICAL for sites that don't use taxonomy_index)
        // Find all entity_reference fields that target taxonomy_term
        $field_map = \\Drupal::service('entity_field.manager')->getFieldMapByFieldType('entity_reference');
        $fields_checked = 0;
        $fields_found_usage = [];

        foreach ($field_map['node'] ?? [] as $field_name => $field_info) {{
            $fields_checked++;

            // Check if this field's table exists and query it directly
            $table_name = 'node__' . $field_name;
            $column_name = $field_name . '_target_id';

            try {{
                // Direct SQL query to field data table (much more reliable)
                $field_nids = $database->query(
                    "SELECT DISTINCT entity_id FROM {{" . $table_name . "}} WHERE " . $column_name . " = :tid LIMIT 20",
                    [':tid' => $tid]
                )->fetchCol();

                if ($field_nids) {{
                    $nids_found = array_merge($nids_found, $field_nids);
                    $fields_found_usage[] = $field_name;
                }}
            }} catch (\\Exception $e) {{
                // Table doesn't exist or field doesn't reference taxonomy - skip
            }}
        }}

        // Remove duplicates and limit to 20
        $nids_found = array_unique($nids_found);
        $nids_found = array_slice($nids_found, 0, 20);

        // Load the actual nodes
        if (!empty($nids_found)) {{
            $nodes = $node_storage->loadMultiple($nids_found);
            foreach ($nodes as $node) {{
                $content_usage[] = [
                    'nid' => (int)$node->id(),
                    'title' => $node->getTitle(),
                    'type' => $node->bundle()
                ];
            }}
        }}

        // Get fields that reference this vocabulary
        $field_configs = \\Drupal::entityTypeManager()
            ->getStorage('field_config')
            ->loadMultiple();

        $referencing_fields = [];
        foreach ($field_configs as $field) {{
            $settings = $field->getSettings();
            if (isset($settings['target_type']) && $settings['target_type'] === 'taxonomy_term') {{
                $handler_settings = $settings['handler_settings'] ?? [];
                $target_bundles = $handler_settings['target_bundles'] ?? [];
                if (in_array($term->bundle(), $target_bundles)) {{
                    $referencing_fields[] = [
                        'field_name' => $field->getName(),
                        'field_label' => $field->getLabel(),
                        'entity_type' => $field->getTargetEntityTypeId(),
                        'bundles' => [$field->getTargetBundle()]
                    ];
                }}
            }}
        }}

        $result = [
            'term' => [
                'tid' => (int)$tid,
                'name' => $term->getName(),
                'description' => $term->getDescription(),
                'vocabulary' => $term->bundle(),
                'vocabulary_label' => $vocab ? $vocab->label() : $term->bundle(),
                'parent' => $parent_name,
                'children' => array_values($children_names)
            ],
            'content_usage' => array_values($content_usage),
            'views_usage' => [],  // Would need to parse view configs
            'referencing_fields' => $referencing_fields,
            '_diagnostics' => [
                'taxonomy_index_count' => (int)$taxonomy_index_count,
                'total_nodes_in_db' => (int)$total_nodes,
                'fields_checked' => (int)$fields_checked,
                'fields_found_usage' => $fields_found_usage,
                'query_method' => $taxonomy_index_count > 0 ? 'taxonomy_index + field_data' : 'field_data_tables_only',
                'total_nids_found' => count($nids_found)
            ]
        ];

        echo json_encode($result);
        """

        result = run_drush_command(["ev", php_code.strip()], timeout=30)
        return result if result else None

    except Exception as e:
        logger.debug(f"Could not get term usage from drush: {e}")
        return None


def _get_term_usage_from_files(term_id: int, drupal_root: Path) -> Optional[dict]:
    """
    Get term usage from files (NOT IMPLEMENTED - database required).

    This function intentionally returns None because taxonomy term usage
    cannot be reliably determined from config files alone. The taxonomy_index
    table in the database is the only accurate source for term usage.

    IMPORTANT: Returning None here will trigger an error message in the caller,
    preventing false "safe to delete" recommendations.
    """
    logger.warning(
        f"File-based term usage analysis requested for term {term_id} "
        "but this is not implemented. Database access via drush is required."
    )
    return None
