"""Database connectivity and module verification utilities."""

import logging
from typing import Tuple

from src.core.drush import run_drush_command

logger = logging.getLogger(__name__)


def verify_database_connection() -> Tuple[bool, str]:
    """
    Verify that we can connect to the Drupal database via drush.

    Returns:
        Tuple of (success: bool, message: str)
    """
    result = run_drush_command(["status", "--format=json"], timeout=10, return_raw_error=True)

    if not result:
        return False, "Drush status command returned no data"

    if isinstance(result, dict) and result.get("_error"):
        error_type = result.get("_error_type", "unknown")
        error_msg = result.get("_error_message", "Unknown error")
        return False, f"Drush error ({error_type}): {error_msg}"

    # Check database status in drush status output
    db_status = result.get("db-status")
    if db_status == "Connected":
        return True, "Database connected"
    elif db_status:
        return False, f"Database status: {db_status}"
    else:
        # db-status not in output, try a simple query
        test_result = run_drush_command(["ev", "echo 'OK';"], timeout=5)
        if test_result is None:
            return False, "Cannot execute PHP via drush"
        return True, "Database connection assumed (drush working)"


def check_module_enabled(module_name: str) -> bool:
    """
    Check if a specific module is enabled.

    Args:
        module_name: Machine name of the module (e.g., 'dblog', 'views')

    Returns:
        True if module is enabled, False otherwise
    """
    result = run_drush_command(["pm:list", "--format=json", "--status=enabled"])

    if not result or not isinstance(result, dict):
        return False

    # Check if module exists and is enabled
    module_info = result.get(module_name)
    if not module_info:
        return False

    status = module_info.get("status", "").lower()
    return status == "enabled"
