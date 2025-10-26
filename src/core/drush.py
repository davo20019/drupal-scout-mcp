"""Drush command detection and execution utilities."""

import json
import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Module-level cache for drush command
_drush_command_cache: Optional[List[str]] = None


def _setup_drush_environment() -> dict:
    """
    Setup environment with extended PATH for drush execution.

    MCP servers may have limited PATH, missing ddev/docker/lando/fin.
    This function ensures common tool locations are included.

    Returns:
        Environment dict with extended PATH
    """
    env = os.environ.copy()

    # Detect platform for path separator
    is_windows = platform.system() == "Windows"
    path_sep = ";" if is_windows else ":"

    # Add standard system paths if not already present
    # Ordered by likelihood of containing dev tools
    standard_paths = [
        "/usr/local/bin",  # Standard Unix (Intel Mac, Linux, Composer global)
        "/opt/homebrew/bin",  # Homebrew on Apple Silicon Mac
        "/usr/bin",  # System binaries (all Unix-like)
        "/bin",  # Core system binaries (all Unix-like)
        "/opt/local/bin",  # MacPorts on Mac
        "/snap/bin",  # Snap packages on Linux
        "/var/lib/flatpak/exports/bin",  # Flatpak on Linux
        str(Path.home() / ".local" / "bin"),  # User-local binaries (Linux/Mac)
        str(Path.home() / "bin"),  # User bin directory
    ]

    # Add Windows/WSL specific paths
    if is_windows or Path("/mnt/c").exists():  # WSL detected
        standard_paths.extend(
            [
                "C:\\Program Files\\DDEV",
                "C:\\ProgramData\\chocolatey\\bin",
                "/mnt/c/Program Files/DDEV",  # WSL mount
                "/mnt/c/ProgramData/chocolatey/bin",  # WSL mount
            ]
        )

    # Add version manager paths (nvm, asdf, mise, etc.)
    # These have dynamic paths, so we check if the base directories exist
    home = Path.home()

    # Check for nvm (Node Version Manager)
    nvm_current = home / ".nvm" / "current" / "bin"
    if nvm_current.exists():
        standard_paths.append(str(nvm_current))

    # Check for asdf version manager
    asdf_shims = home / ".asdf" / "shims"
    if asdf_shims.exists():
        standard_paths.append(str(asdf_shims))

    # Check for mise (formerly rtx)
    mise_shims = home / ".local" / "share" / "mise" / "shims"
    if mise_shims.exists():
        standard_paths.append(str(mise_shims))

    # Check for rbenv (Ruby version manager)
    rbenv_shims = home / ".rbenv" / "shims"
    if rbenv_shims.exists():
        standard_paths.append(str(rbenv_shims))

    # Check for pyenv (Python version manager)
    pyenv_shims = home / ".pyenv" / "shims"
    if pyenv_shims.exists():
        standard_paths.append(str(pyenv_shims))

    current_path = env.get("PATH", "")
    # Only add paths that exist and aren't already in PATH
    paths_to_add = [p for p in standard_paths if p not in current_path and Path(p).exists()]

    if paths_to_add:
        env["PATH"] = path_sep.join(paths_to_add) + path_sep + current_path

    return env


def test_drush_connectivity() -> Tuple[bool, str, dict]:
    """
    Test if drush is working and can connect to the database.

    Returns:
        Tuple of (success: bool, message: str, details: dict)
    """
    details = {
        "drush_found": False,
        "drush_command": None,
        "drush_version": None,
        "database_connected": False,
        "drupal_version": None,
    }

    # Check if drush command is found
    drush_cmd = get_drush_command()
    if not drush_cmd:
        return False, "Drush command not found", details

    details["drush_found"] = True
    details["drush_command"] = " ".join(drush_cmd)

    # Setup environment with extended PATH for drush
    env = _setup_drush_environment()

    # Try to get drush version
    try:
        from src.core.config import get_config

        config = get_config()
        drupal_root = Path(config.get("drupal_root"))

        result = subprocess.run(
            [*drush_cmd, "version", "--format=json"],
            cwd=str(drupal_root),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )

        if result.returncode == 0 and result.stdout.strip():
            version_data = json.loads(result.stdout)
            details["drush_version"] = version_data.get("drush-version", "unknown")
    except Exception as e:
        logger.debug(f"Could not get drush version: {e}")

    # Try to connect to database
    try:
        result = subprocess.run(
            [*drush_cmd, "status", "--format=json"],
            cwd=str(drupal_root),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )

        if result.returncode == 0 and result.stdout.strip():
            status = json.loads(result.stdout)
            db_status = status.get("db-status")
            details["database_connected"] = db_status == "Connected"
            details["drupal_version"] = status.get("drupal-version")

            if details["database_connected"]:
                return (
                    True,
                    f"✅ Drush working (version {details.get('drush_version', 'unknown')}), database connected",
                    details,
                )
            else:
                return (
                    False,
                    f"Drush found but database not connected (status: {db_status})",
                    details,
                )
        else:
            return (
                False,
                f"Drush command failed: {result.stderr.strip()}",
                details,
            )

    except subprocess.TimeoutExpired:
        return False, "Drush command timed out (database might be slow)", details
    except Exception as e:
        return False, f"Error testing drush: {str(e)}", details


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

    logger.info("🔍 Starting drush detection...")

    ensure_indexed()  # Make sure config is loaded
    config = get_config()

    drupal_root = Path(config.get("drupal_root"))
    logger.info(f"   Drupal root: {drupal_root}")
    logger.info(f"   Root exists: {drupal_root.exists()}")

    # 1. User explicitly configured drush command
    if config.get("drush_command"):
        cmd = config["drush_command"].split()
        logger.info(f"✅ Using configured drush command: {' '.join(cmd)}")
        logger.info("   (from config.json drush_command setting)")
        return cmd
    else:
        logger.info("   No drush_command in config.json, trying auto-detection...")

    # 2. Auto-detect development environment
    logger.info("   Checking for development environments...")

    # DDEV
    ddev_config = drupal_root / ".ddev" / "config.yaml"
    logger.info(f"   DDEV config ({ddev_config}): {ddev_config.exists()}")
    if ddev_config.exists():
        # Verify ddev is actually available
        if shutil.which("ddev"):
            logger.info("✅ Detected DDEV environment (ddev command found)")
            return ["ddev", "drush"]
        else:
            logger.warning("⚠️  Found .ddev/config.yaml but 'ddev' command not in PATH")
            logger.warning("   Install DDEV or add to PATH: https://ddev.readthedocs.io/")

    # Lando
    lando_config = drupal_root / ".lando.yml"
    logger.info(f"   Lando config ({lando_config}): {lando_config.exists()}")
    if lando_config.exists():
        if shutil.which("lando"):
            logger.info("✅ Detected Lando environment (lando command found)")
            return ["lando", "drush"]
        else:
            logger.warning("⚠️  Found .lando.yml but 'lando' command not in PATH")

    # Docksal
    docksal_dir = drupal_root / ".docksal"
    logger.info(f"   Docksal dir ({docksal_dir}): {docksal_dir.exists()}")
    if docksal_dir.exists():
        if shutil.which("fin"):
            logger.info("✅ Detected Docksal environment (fin command found)")
            return ["fin", "drush"]
        else:
            logger.warning("⚠️  Found .docksal directory but 'fin' command not in PATH")

    # 3. Check for Composer-installed drush in vendor/bin
    vendor_drush = drupal_root / "vendor" / "bin" / "drush"
    logger.info(f"   Composer drush ({vendor_drush}): {vendor_drush.exists()}")
    if vendor_drush.exists() and vendor_drush.is_file():
        logger.info(f"✅ Using Composer drush: {vendor_drush}")
        return [str(vendor_drush)]

    # 4. Check for global drush
    global_drush = shutil.which("drush")
    logger.info(f"   Global drush: {global_drush or 'not found'}")
    if global_drush:
        logger.info(f"✅ Using global drush: {global_drush}")
        return ["drush"]

    # No drush found - provide helpful debugging info
    logger.error("❌ Drush not found in any expected location")
    logger.error("")
    logger.error("🔧 TROUBLESHOOTING:")
    logger.error("   1. Add drush_command to config.json:")
    logger.error('      "drush_command": "ddev drush"')
    logger.error("")
    logger.error("   2. Ensure your dev environment is running:")
    logger.error("      - DDEV: ddev start")
    logger.error("      - Lando: lando start")
    logger.error("")
    logger.error("   3. Install drush globally:")
    logger.error("      composer global require drush/drush")
    logger.error("")
    logger.error(f"   4. Verify drupal_root in config.json: {drupal_root}")
    logger.error("")

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

        # Setup environment with extended PATH for drush
        env = _setup_drush_environment()

        result = subprocess.run(
            full_cmd,
            cwd=str(drupal_root),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
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
