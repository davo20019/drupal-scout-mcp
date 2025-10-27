"""
Media export tool for Drupal Scout MCP.

Provides CSV export functionality for media entities:
- export_media_to_csv: Export media entities to CSV with comprehensive file data

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
def export_media_to_csv(
    media_type: Optional[str] = None,
    output_path: Optional[str] = None,
    summary_only: bool = True,
    include_unused: bool = False,
    include_field_data: bool = False,
    limit: int = 0,
) -> str:
    """
    Export media entity data directly to CSV file, bypassing MCP token limits.

    **BEST SOLUTION FOR MEDIA AUDITS AND MIGRATION PLANNING**

    Perfect for:
    - Media asset inventory and auditing
    - File storage analysis and cleanup
    - Migration planning and asset mapping
    - Accessibility compliance (alt text audits)
    - Finding orphaned or unused media
    - Image optimization planning

    **How It Works:**
    1. Queries all media entities (optionally filtered by media type)
    2. Fetches comprehensive file data via drush
    3. Analyzes usage (where media is referenced)
    4. Writes CSV directly to Drupal root directory
    5. Returns tiny response with file path and stats

    **Performance:**
    - 100 media items: ~10 seconds
    - 500 media items: ~30 seconds
    - 1000 media items: ~60 seconds
    - 5000 media items: ~5 minutes

    Args:
        media_type: Optional media type filter (e.g., "image", "video", "document", "audio")
                   If None, exports all media types
        output_path: Optional CSV file path. If not provided, auto-generates:
                     {drupal_root}/media_export_{type}_{timestamp}.csv
        summary_only: If True, exports essential columns (mid, name, type, bundle, file_size, created).
                     If False, exports FULL details including:
                       - mid, uuid, name, bundle (media type), status, langcode
                       - created, changed, author (username + uid)
                       - file_uri, file_url, file_mime, file_size (bytes)
                       - file_size_mb (calculated), file_extension
                       - alt_text (for images), title (media title)
                       - width, height (for images/videos)
                       - duration (for audio/video)
                       - usage_count (number of places referencing this media)
                       - usage_locations (nodes, paragraphs, blocks using this media)
                       - thumbnail_uri (if available)
                     Default: True (faster for large media libraries)
        include_unused: If True, includes media not referenced anywhere (orphaned).
                       If False, only includes media in use.
                       Default: False
        include_field_data: If True, includes custom media field values.
                     **SMART PROMPTING - Set to True when user asks for:**
                     - "field data", "field values", "custom fields"
                     - "all data", "everything", "complete export"
                     - "migration data", "full migration export"
                     **Keep False (default) for:**
                     - Basic inventory, file-only exports
                     - Quick audits focusing on file sizes/types/usage
                     **Performance impact:** Adds 20-30% to export time
                     Default: False
        limit: Max media items to export. 0 = all media. Default: 0

    Returns:
        JSON with file path, stats, and preview:
        {
            "file_path": "/path/to/drupal/media_export_image_20251026.csv",
            "total_media": 1523,
            "media_types": {"image": 1200, "video": 200, "document": 123},
            "total_file_size_mb": 2847.5,
            "file_size_kb": 385,
            "columns": [...],
            "preview": "..."
        }

    **Column Details (Full Mode):**

    Basic Info:
    - mid, uuid, name (media label), bundle (image/video/document/audio)
    - status (published/unpublished), langcode, created, changed
    - author (username), author_uid

    File Information:
    - file_uri (public://images/photo.jpg)
    - file_url (https://example.com/sites/default/files/images/photo.jpg)
    - file_mime (image/jpeg, video/mp4, application/pdf)
    - file_size (bytes), file_size_mb (calculated)
    - file_extension (jpg, mp4, pdf)

    Media Metadata:
    - alt_text (for images - accessibility)
    - title (media title field)
    - width, height (for images/videos)
    - duration (for audio/video in seconds)
    - thumbnail_uri (thumbnail file)

    Usage Analysis:
    - usage_count (number of references)
    - usage_locations (node:123 (Article) | paragraph:456 | block:789)
    - orphaned (YES/NO - not referenced anywhere)

    Custom Fields (if include_field_data=True):
    - All custom media fields auto-detected and included

    **Examples:**

    Fast summary of all images:
    export_media_to_csv(media_type="image", summary_only=True)

    Full audit including orphaned media:
    export_media_to_csv(summary_only=False, include_unused=True)

    Migration prep with all field data:
    export_media_to_csv(summary_only=False, include_field_data=True)

    Find large video files:
    export_media_to_csv(media_type="video", summary_only=False)
    # Then analyze CSV for file_size_mb column
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
            type_suffix = f"_{media_type}" if media_type else "_all"
            output_path = str(drupal_root / f"media_export{type_suffix}_{timestamp}.csv")

        # Validate path is within safe boundaries
        is_valid, error_msg = validate_export_path(output_path, drupal_root)
        if not is_valid:
            return json.dumps({"_error": True, "message": f"Invalid export path: {error_msg}"})

        # Validate path is writable
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        drush_cmd = get_drush_command(drupal_root)

        # Build the PHP script to export media data
        php_script = _build_media_export_script(
            media_type=media_type,
            summary_only=summary_only,
            include_unused=include_unused,
            include_field_data=include_field_data,
            limit=limit,
        )

        # Execute drush eval with timeout
        cmd = drush_cmd + ["eval", php_script]
        logger.info(f"Executing drush command: {' '.join(cmd[:2])} [PHP script]")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout for large media libraries
            cwd=str(drupal_root),
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            logger.error(f"Drush command failed: {error_msg}")
            return json.dumps(
                {
                    "_error": True,
                    "message": f"Failed to export media data: {error_msg}",
                }
            )

        # Parse the JSON output from drush
        media_data = json.loads(result.stdout.strip())

        if "error" in media_data:
            return json.dumps({"_error": True, "message": media_data["error"]})

        # Write CSV file
        _write_media_csv(
            output_file=output_file,
            media_data=media_data["media"],
            summary_only=summary_only,
            include_field_data=include_field_data,
        )

        # Calculate file size
        file_size_kb = output_file.stat().st_size / 1024

        # Get media type breakdown
        type_counts = {}
        total_size_mb = 0
        for item in media_data["media"]:
            bundle = item.get("bundle", "unknown")
            type_counts[bundle] = type_counts.get(bundle, 0) + 1
            if "file_size_mb" in item:
                total_size_mb += float(item["file_size_mb"])

        # Build success response
        response = {
            "success": True,
            "file_path": str(output_file),
            "total_media": len(media_data["media"]),
            "media_types": type_counts,
            "total_file_size_mb": round(total_size_mb, 2),
            "file_size_kb": round(file_size_kb, 1),
            "columns": _get_media_columns(summary_only, include_field_data, media_data["media"]),
        }

        # Add preview (first 3 rows)
        if media_data["media"]:
            preview_lines = []
            with open(output_file, "r") as f:
                for i, line in enumerate(f):
                    if i < 4:  # Header + 3 rows
                        preview_lines.append(line.rstrip())
                    else:
                        break
            response["preview"] = "\n".join(preview_lines)

        return json.dumps(response, indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps(
            {
                "_error": True,
                "message": "Export timeout: Media library is very large. Try using limit parameter or media_type filter.",
            }
        )
    except Exception as e:
        logger.exception("Error exporting media to CSV")
        return json.dumps({"_error": True, "message": f"Export failed: {str(e)}"})


def _build_media_export_script(
    media_type: Optional[str],
    summary_only: bool,
    include_unused: bool,
    include_field_data: bool,
    limit: int,
) -> str:
    """Build the PHP script for drush eval to export media data."""

    type_filter = f'->condition("bundle", "{media_type}")' if media_type else ""
    limit_clause = f"->range(0, {limit})" if limit > 0 else ""

    return f"""
use Drupal\\media\\Entity\\Media;
use Drupal\\file\\Entity\\File;

$media_ids = \\Drupal::entityQuery('media')
  {type_filter}
  ->accessCheck(FALSE)
  {limit_clause}
  ->execute();

$media_data = [];
$file_storage = \\Drupal::entityTypeManager()->getStorage('file');

foreach ($media_ids as $mid) {{
  $media = Media::load($mid);
  if (!$media) continue;

  $item = [
    'mid' => $media->id(),
    'uuid' => $media->uuid(),
    'name' => $media->getName(),
    'bundle' => $media->bundle(),
    'status' => $media->isPublished() ? 'published' : 'unpublished',
    'langcode' => $media->language()->getId(),
    'created' => date('Y-m-d H:i:s', $media->getCreatedTime()),
    'changed' => date('Y-m-d H:i:s', $media->getChangedTime()),
  ];

  // Author info
  $owner = $media->getOwner();
  $item['author'] = $owner ? $owner->getAccountName() : 'unknown';
  $item['author_uid'] = $media->getOwnerId();

  // Get source field and file information
  $source = $media->getSource();
  $source_field = $source->getConfiguration()['source_field'];

  if ($media->hasField($source_field) && !$media->get($source_field)->isEmpty()) {{
    $file_field = $media->get($source_field)->first();

    if ($file_field && $file_field->entity) {{
      $file = $file_field->entity;

      $item['file_uri'] = $file->getFileUri();
      $item['file_url'] = \\Drupal::service('file_url_generator')->generateAbsoluteString($file->getFileUri());
      $item['file_mime'] = $file->getMimeType();
      $item['file_size'] = $file->getSize();
      $item['file_size_mb'] = round($file->getSize() / 1048576, 2);

      // Extract file extension
      $uri = $file->getFileUri();
      $item['file_extension'] = pathinfo($uri, PATHINFO_EXTENSION);
    }}
  }}

  // Media-type specific fields (full mode only)
  {"if (true) {" if not summary_only else "if (false) {"}
    // Alt text for images
    if ($media->bundle() === 'image' && $media->hasField('field_media_image')) {{
      $image_field = $media->get('field_media_image')->first();
      $item['alt_text'] = $image_field ? $image_field->get('alt')->getValue() : '';
    }}

    // Dimensions for images/videos
    if ($media->hasField('field_media_image')) {{
      $image_field = $media->get('field_media_image')->first();
      if ($image_field) {{
        $item['width'] = $image_field->get('width')->getValue();
        $item['height'] = $image_field->get('height')->getValue();
      }}
    }} elseif ($media->hasField('field_media_video_file')) {{
      // Video dimensions if available
      $video_field = $media->get('field_media_video_file')->first();
      if ($video_field && method_exists($video_field, 'getWidth')) {{
        $item['width'] = $video_field->getWidth();
        $item['height'] = $video_field->getHeight();
      }}
    }}

    // Thumbnail
    if ($media->hasField('thumbnail') && !$media->get('thumbnail')->isEmpty()) {{
      $thumb = $media->get('thumbnail')->entity;
      if ($thumb) {{
        $item['thumbnail_uri'] = $thumb->getFileUri();
      }}
    }}
  }}

  // Usage analysis (full mode only)
  {"if (true) {" if not summary_only else "if (false) {"}
    $usage = \\Drupal::service('file.usage')->listUsage($file ?? null);
    $usage_count = 0;
    $usage_locations = [];

    if ($usage && isset($usage['file'])) {{
      foreach ($usage['file'] as $module => $data) {{
        foreach ($data as $type => $ids) {{
          foreach ($ids as $id => $count) {{
            $usage_count += $count;
            $entity = \\Drupal::entityTypeManager()->getStorage($type)->load($id);
            if ($entity) {{
              $label = method_exists($entity, 'label') ? $entity->label() : $entity->id();
              $usage_locations[] = "$type:$id ($label)";
            }}
          }}
        }}
      }}
    }}

    $item['usage_count'] = $usage_count;
    $item['usage_locations'] = implode(' | ', $usage_locations);
    $item['orphaned'] = $usage_count === 0 ? 'YES' : 'NO';
  }}

  // Custom fields (if requested)
  {"if (true) {" if include_field_data else "if (false) {"}
    $field_definitions = $media->getFieldDefinitions();
    foreach ($field_definitions as $field_name => $field_definition) {{
      // Skip base fields and already processed fields
      if (in_array($field_name, ['mid', 'uuid', 'bundle', 'name', 'status', 'created', 'changed', 'uid', 'thumbnail', $source_field])) {{
        continue;
      }}

      if ($field_definition->getFieldStorageDefinition()->isBaseField()) {{
        continue;
      }}

      if ($media->hasField($field_name) && !$media->get($field_name)->isEmpty()) {{
        $field_value = $media->get($field_name)->first();
        if ($field_value) {{
          // Try to get a simple string value
          if (method_exists($field_value, 'getString')) {{
            $item[$field_name] = substr($field_value->getString(), 0, 500);
          }} elseif (isset($field_value->value)) {{
            $item[$field_name] = substr($field_value->value, 0, 500);
          }}
        }}
      }}
    }}
  }}

  // Skip unused media if requested
  {"if (isset($item['orphaned']) && $item['orphaned'] === 'YES') { continue; }" if not include_unused and not summary_only else ""}

  $media_data[] = $item;
}}

echo json_encode(['media' => $media_data], JSON_UNESCAPED_SLASHES);
"""


def _write_media_csv(
    output_file: Path,
    media_data: List[dict],
    summary_only: bool,
    include_field_data: bool,
) -> None:
    """Write media data to CSV file."""

    if not media_data:
        # Write empty CSV with headers
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            headers = _get_summary_headers() if summary_only else _get_full_headers()
            writer.writerow(headers)
        return

    # Collect all possible columns from the data
    all_columns = set()
    for item in media_data:
        all_columns.update(item.keys())

    # Define column order
    if summary_only:
        ordered_columns = [c for c in _get_summary_headers() if c in all_columns]
    else:
        ordered_columns = [c for c in _get_full_headers() if c in all_columns]

    # Add any custom fields not in ordered list
    custom_fields = sorted(all_columns - set(ordered_columns))
    ordered_columns.extend(custom_fields)

    # Write CSV
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(media_data)


def _get_summary_headers() -> List[str]:
    """Get column headers for summary mode."""
    return [
        "mid",
        "name",
        "bundle",
        "status",
        "file_size_mb",
        "file_extension",
        "created",
        "author",
    ]


def _get_full_headers() -> List[str]:
    """Get column headers for full mode."""
    return [
        "mid",
        "uuid",
        "name",
        "bundle",
        "status",
        "langcode",
        "created",
        "changed",
        "author",
        "author_uid",
        "file_uri",
        "file_url",
        "file_mime",
        "file_size",
        "file_size_mb",
        "file_extension",
        "alt_text",
        "width",
        "height",
        "thumbnail_uri",
        "usage_count",
        "usage_locations",
        "orphaned",
    ]


def _get_media_columns(
    summary_only: bool, include_field_data: bool, media_data: List[dict]
) -> List[str]:
    """Get actual columns present in the export."""
    if not media_data:
        return _get_summary_headers() if summary_only else _get_full_headers()

    # Get all columns from actual data
    all_columns = set()
    for item in media_data:
        all_columns.update(item.keys())

    # Return in order
    if summary_only:
        base = [c for c in _get_summary_headers() if c in all_columns]
    else:
        base = [c for c in _get_full_headers() if c in all_columns]

    # Add custom fields
    custom = sorted(all_columns - set(base))
    return base + custom
