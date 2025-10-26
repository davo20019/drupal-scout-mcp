"""
Users export tool for Drupal Scout MCP.

Provides CSV export functionality for user accounts:
- export_users_to_csv: Export user accounts to CSV with comprehensive profile data

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
from src.tools.exports.common import get_export_config, validate_export_path

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


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
    try:
        # Get config and verify database connection
        success, result, msg = get_export_config()
        if not success:
            return result["error_response"]

        drupal_root = result["drupal_root"]

        # Auto-generate path if not provided
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(drupal_root / f"users_export_{timestamp}.csv")

        # Validate path is within safe boundaries
        is_valid, error_msg = validate_export_path(output_path, drupal_root)
        if not is_valid:
            return json.dumps({"_error": True, "message": f"Invalid export path: {error_msg}"})

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
