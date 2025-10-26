"""
Shared utilities for export tools in Drupal Scout MCP.

This module contains common functions used by all export tools:
- validate_export_path: Security validation for export file paths
- get_export_config: Common configuration loading
"""

import json
import logging
from pathlib import Path

# Import from core modules
from src.core.config import load_config
from src.core.database import verify_database_connection

# Get logger
logger = logging.getLogger(__name__)


def validate_export_path(path: str, drupal_root: Path) -> tuple[bool, str]:
    """
    Validate that export path is within safe boundaries.

    This prevents accidental writes to sensitive system directories.
    Allows writing to:
    - Drupal root and subdirectories
    - /tmp and /var/tmp
    - User's home directory

    Args:
        path: The requested export path
        drupal_root: Drupal installation root

    Returns:
        Tuple of (is_valid: bool, error_message: str)
    """
    try:
        # Resolve to absolute path to catch path traversal attempts
        export_path = Path(path).resolve()

        # Define safe root directories
        safe_roots = [
            drupal_root.resolve(),  # Drupal root
            Path("/tmp"),  # Temporary directory
            Path("/var/tmp"),  # Alternative temp directory
            Path.home(),  # User's home directory
        ]

        # Check if export path is within any safe root
        for safe_root in safe_roots:
            try:
                # Check if export_path is within safe_root
                export_path.relative_to(safe_root)
                return True, ""
            except ValueError:
                # Not within this safe root, try next
                continue

        # Path is not within any safe root
        safe_locations = "\n  - ".join([str(r) for r in safe_roots])
        return (
            False,
            f"Export path must be within safe locations:\n  - {safe_locations}\n\n"
            f"Requested path: {export_path}\n\n"
            f"Use a path within Drupal root or /tmp for security.",
        )

    except Exception as e:
        return False, f"Invalid path: {str(e)}"


def get_export_config() -> tuple[bool, dict, str]:
    """
    Load configuration and verify database connection for export operations.

    Returns:
        Tuple of (success: bool, config_or_error: dict, message: str)
        On success: (True, {"drupal_root": Path, "config": dict}, "")
        On failure: (False, {"error_response": str}, "error message")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            error_response = json.dumps(
                {
                    "_error": True,
                    "message": "Could not determine Drupal root. Check drupal_root in config.",
                }
            )
            return False, {"error_response": error_response}, "Drupal root not found"

        # Verify database connection
        db_ok, db_msg = verify_database_connection()
        if not db_ok:
            # Get config file location for AI to know where to edit
            config_path = Path.home() / ".config" / "drupal-scout" / "config.json"
            local_config = Path("config.json")

            if config_path.exists():
                config_file = str(config_path)
            elif local_config.exists():
                config_file = str(local_config.absolute())
            else:
                config_file = str(config_path)

            error_response = json.dumps(
                {
                    "_error": True,
                    "message": f"Database connection required. {db_msg}",
                    "ai_fix_instructions": {
                        "action": "Open Cursor from Drupal project directory OR edit config file",
                        "config_file": config_file,
                        "recommended_fix": "Open Cursor from your Drupal project directory: cd /path/to/drupal && cursor .",
                        "why": "Opening from the project directory ensures ddev/docker are in PATH",
                        "alternative_fix": "Use absolute paths in config if can't open from project directory",
                        "add_property": "drush_command",
                        "example_values": {
                            "ddev_relative": "ddev drush (only works if opened from project dir)",
                            "ddev_absolute": "/opt/homebrew/bin/ddev drush (works anywhere)",
                            "lando": "lando drush",
                            "docksal": "fin drush",
                        },
                        "example_config": {
                            "drupal_root": "/path/to/drupal",
                            "drush_command": "ddev drush",
                        },
                        "help": "Option 1 (Best): Open Cursor from Drupal project directory. Option 2: Add absolute path to 'drush_command' in config. Then run check_scout_health() to verify.",
                    },
                }
            )
            return False, {"error_response": error_response}, db_msg

        return True, {"drupal_root": drupal_root, "config": config}, ""

    except Exception as e:
        logger.error(f"Error in get_export_config: {e}", exc_info=True)
        error_response = json.dumps({"_error": True, "message": str(e)})
        return False, {"error_response": error_response}, str(e)
