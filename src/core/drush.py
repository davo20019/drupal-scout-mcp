"""Drush command detection and execution utilities."""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Module-level cache for drush command
_drush_command_cache: Optional[List[str]] = None


def get_drush_command() -> Optional[List[str]]:
    """
    Get drush command with caching and smart detection.

    Returns:
        List of command parts (e.g., ["ddev", "drush"]) or None if not found
    """
    global _drush_command_cache

    if _drush_command_cache is not None:
        return _drush_command_cache

    # Try detection
    _drush_command_cache = _detect_drush_command()
    return _drush_command_cache


def _detect_drush_command() -> Optional[List[str]]:
    """
    Detect how to run drush in this environment.

    Priority:
    1. User config (drush_command in config.json)
    2. Auto-detect environment (DDEV, Lando, Docksal)
    3. Composer vendor/bin/drush
    4. Global drush

    Returns:
        List of command parts or None if drush not found
    """
    # Import here to avoid circular dependency
    from src.core.config import ensure_indexed, get_config

    ensure_indexed()  # Make sure config is loaded
    config = get_config()

    drupal_root = Path(config.get("drupal_root"))

    # 1. User explicitly configured drush command
    if config.get("drush_command"):
        cmd = config["drush_command"].split()
        logger.info(f"Using configured drush command: {' '.join(cmd)}")
        return cmd

    # 2. Auto-detect development environment

    # DDEV
    if (drupal_root / ".ddev" / "config.yaml").exists():
        logger.info("Detected DDEV environment")
        return ["ddev", "drush"]

    # Lando
    if (drupal_root / ".lando.yml").exists():
        logger.info("Detected Lando environment")
        return ["lando", "drush"]

    # Docksal
    if (drupal_root / ".docksal").exists():
        logger.info("Detected Docksal environment")
        return ["fin", "drush"]

    # 3. Check for Composer-installed drush in vendor/bin
    vendor_drush = drupal_root / "vendor" / "bin" / "drush"
    if vendor_drush.exists() and vendor_drush.is_file():
        logger.info(f"Using Composer drush: {vendor_drush}")
        return [str(vendor_drush)]

    # 4. Check for global drush
    if shutil.which("drush"):
        logger.info("Using global drush")
        return ["drush"]

    # No drush found
    logger.warning("Drush not found in any expected location")
    return None


def run_drush_command(args: List[str], timeout: int = 30, return_raw_error: bool = False):
    """
    Run a drush command and return JSON output.

    Args:
        args: Drush command arguments (e.g., ["pm:list", "--format=json"])
        timeout: Command timeout in seconds
        return_raw_error: If True, return dict with error info instead of None

    Returns:
        Parsed JSON output (dict or list) or None if command failed
        If return_raw_error=True and error occurs, returns:
        {"_error": True, "_error_type": "...", "_error_message": "..."}
    """
    drush_cmd = get_drush_command()

    if not drush_cmd:
        logger.error("Cannot run drush command: drush not found")
        if return_raw_error:
            return {
                "_error": True,
                "_error_type": "drush_not_found",
                "_error_message": "Drush not found",
            }
        return None

    # Import here to avoid circular dependency
    from src.core.config import get_config

    config = get_config()
    drupal_root = Path(config.get("drupal_root"))
    full_cmd = [*drush_cmd, *args]

    try:
        logger.debug(f"Running: {' '.join(full_cmd)}")
        result = subprocess.run(
            full_cmd,
            cwd=str(drupal_root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.error(f"Drush command failed: {result.stderr}")
            if return_raw_error:
                return {
                    "_error": True,
                    "_error_type": "drush_failed",
                    "_error_message": result.stderr.strip(),
                }
            return None

        if result.stdout.strip():
            return json.loads(result.stdout)

        return None

    except subprocess.TimeoutExpired:
        logger.error(f"Drush command timed out after {timeout}s")
        if return_raw_error:
            return {
                "_error": True,
                "_error_type": "timeout",
                "_error_message": f"Command timed out after {timeout}s",
            }
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse drush JSON output: {e}")
        logger.error(f"Output was: {result.stdout[:200]}")
        if return_raw_error:
            return {
                "_error": True,
                "_error_type": "json_parse",
                "_error_message": str(e),
            }
        return None
    except Exception as e:
        logger.error(f"Error running drush command: {e}")
        if return_raw_error:
            return {"_error": True, "_error_type": "unknown", "_error_message": str(e)}
        return None
