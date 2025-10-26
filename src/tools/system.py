"""
System health and logging tools.

Provides tools for system diagnostics and error analysis:
- get_watchdog_logs: Get Drupal watchdog logs for debugging
- check_scout_health: Verify Scout's database connectivity and health

These tools help monitor and troubleshoot the Drupal site.
"""

import logging
from pathlib import Path
from typing import Optional

# Import from core modules
from src.core.config import ensure_indexed, get_config, get_indexer
from src.core.database import check_module_enabled
from src.core.drush import run_drush_command

# Import MCP instance from server
from server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def get_watchdog_logs(
    severity: Optional[str] = None, type: Optional[str] = None, limit: int = 50
) -> str:
    """
    Get recent Drupal watchdog logs (errors, warnings, notices) for debugging.

    IMPORTANT: This tool requires the DBLog (dblog) module to be enabled.
    If you get an error, use list_modules() to check if dblog is enabled first.

    This tool fetches logs from Drupal's database via drush, helping AI assistants:
    - Diagnose errors and exceptions in the application
    - Identify warnings that might indicate issues
    - Understand what's happening in the system
    - Provide context for fixing code issues
    - Suggest next steps for unresolved issues

    Common use cases:
    - "Show me recent errors"
    - "What warnings are in the logs?"
    - "Are there any PHP errors?"
    - "Show me database-related errors"

    Args:
        severity: Optional filter by severity level.
                  Options: emergency, alert, critical, error, warning, notice, info, debug
                  Default: Shows error and warning levels
        type: Optional filter by message type (e.g., "php", "cron", "system", "page not found")
        limit: Number of recent log entries to return (default: 50, max: 200)

    Returns:
        Formatted log entries with severity, type, message, and timestamp.
        Provides actionable insights for debugging.

    Examples:
        get_watchdog_logs()  # Recent errors and warnings
        get_watchdog_logs(severity="error")  # Only errors
        get_watchdog_logs(type="php")  # Only PHP errors
        get_watchdog_logs(severity="warning", limit=100)  # More warnings

    Prerequisites:
        - DBLog (dblog) module must be enabled
        - Use list_modules() to verify dblog status before calling this
        - If dblog not enabled, suggest user runs: drush en dblog -y

    Note: If DBLog is not available, guide user to check DDEV/Lando logs or web server logs instead.
    """
    ensure_indexed()

    # CRITICAL: Check if dblog module is enabled BEFORE trying to fetch logs
    if not check_module_enabled("dblog"):
        return (
            "❌ ERROR: DBLog module is not enabled\n\n"
            "The Database Logging (dblog) module is required to store and retrieve watchdog logs.\n\n"
            "To enable DBLog:\n"
            "  drush en dblog -y\n\n"
            "After enabling, logs will be captured going forward (historical logs won't be available).\n\n"
            "ALTERNATIVE LOGGING OPTIONS:\n"
            "• DDEV users: ddev logs\n"
            "• Lando users: lando logs\n"
            "• Check PHP error log (configured in settings.php)\n"
            "• Check web server error logs (Apache/Nginx)\n"
            "• If syslog module is enabled: Check system logs\n\n"
            "Note: DBLog stores logs in the database. For production sites, consider using\n"
            "syslog module instead to avoid database bloat."
        )

    # Validate and cap limit
    if limit > 200:
        limit = 200
    if limit < 1:
        limit = 1

    # Build drush watchdog:show command (simpler approach)
    valid_severities = [
        "emergency",
        "alert",
        "critical",
        "error",
        "warning",
        "notice",
        "info",
        "debug",
    ]

    # Try to get logs from drush
    # NOTE: Drush watchdog:show doesn't support comma-separated severities
    # If no severity specified, we fetch errors and warnings separately
    if severity:
        severity_lower = severity.lower()
        if severity_lower not in valid_severities:
            return f"❌ Invalid severity level: {severity}\nValid options: {', '.join(valid_severities)}"

        # Single severity - simple case
        args = ["watchdog:show", "--format=json", f"--count={limit}", f"--severity={severity_lower}"]
        if type:
            args.append(f"--type={type}")

        result = run_drush_command(args, timeout=15)
    else:
        # Default to errors and warnings - need to fetch separately and combine
        # Fetch errors first
        error_args = ["watchdog:show", "--format=json", f"--count={limit}", "--severity=error"]
        if type:
            error_args.append(f"--type={type}")

        error_result = run_drush_command(error_args, timeout=15)

        # Fetch warnings
        warning_args = ["watchdog:show", "--format=json", f"--count={limit}", "--severity=warning"]
        if type:
            warning_args.append(f"--type={type}")

        warning_result = run_drush_command(warning_args, timeout=15)

        # Combine results
        result = []
        if error_result:
            if isinstance(error_result, list):
                result.extend(error_result)
            else:
                result.append(error_result)

        if warning_result:
            if isinstance(warning_result, list):
                result.extend(warning_result)
            else:
                result.append(warning_result)

        # If both failed, result will be empty list
        if not result:
            result = None

    if result is None:
        return (
            "❌ ERROR: Could not retrieve watchdog logs from database\n\n"
            "DBLog is enabled but the drush command failed.\n\n"
            "Possible causes:\n"
            "1. Database connection issue\n"
            "2. Drush not working properly\n"
            "3. No logs match the filter criteria\n"
            "4. Permissions issue\n\n"
            "Troubleshooting:\n"
            "• Verify drush works: drush status\n"
            "• Check database connection in drush status output\n"
            "• Try broader filters (remove severity/type filters)\n"
            "• Check if watchdog table exists: drush sqlq \"SHOW TABLES LIKE 'watchdog'\"\n\n"
            "ALTERNATIVE: Check container/server logs:\n"
            "• DDEV: ddev logs\n"
            "• Lando: lando logs\n"
            "• Docker: docker-compose logs web\n"
            "• Server: tail -f /var/log/apache2/error.log (or nginx)"
        )

    # Handle both dict (single entry) and list (multiple entries) responses
    if isinstance(result, dict):
        result = [result]
    elif not isinstance(result, list):
        return "Unexpected response format from drush watchdog:show"

    if len(result) == 0:
        severity_text = severity if severity else "error/warning"
        type_text = f" of type '{type}'" if type else ""
        return f"No {severity_text} log entries{type_text} found in the last {limit} entries."

    # Format the logs for display
    output = []
    output.append(f"DRUPAL WATCHDOG LOGS (most recent {len(result)} entries)\n")

    # Group by severity for better organization
    severity_groups = {}
    for entry in result:
        sev = entry.get("severity", "unknown").upper()
        if sev not in severity_groups:
            severity_groups[sev] = []
        severity_groups[sev].append(entry)

    # Display in severity order (most severe first)
    severity_order = [
        "EMERGENCY",
        "ALERT",
        "CRITICAL",
        "ERROR",
        "WARNING",
        "NOTICE",
        "INFO",
        "DEBUG",
    ]

    for sev_level in severity_order:
        if sev_level not in severity_groups:
            continue

        entries = severity_groups[sev_level]
        output.append(f"\n{sev_level} ({len(entries)} entries)")
        output.append("=" * 80)

        for entry in entries[:20]:  # Limit to 20 per severity to avoid overwhelming
            msg_type = entry.get("type", "unknown")
            message = entry.get("message", "No message")
            timestamp = entry.get("timestamp", "")
            location = entry.get("location", "")

            output.append(f"\n[{timestamp}] {msg_type}")
            output.append(f"Message: {message}")
            if location:
                output.append(f"Location: {location}")
            output.append("-" * 80)

    output.append(f"\n\nSHOWING {len(result)} OF REQUESTED {limit} ENTRIES")

    if severity or type:
        output.append("\nFilters applied:")
        if severity:
            output.append(f"  - Severity: {severity}")
        if type:
            output.append(f"  - Type: {type}")

    output.append("\n\nAI ASSISTANT - SUGGESTED ACTIONS:")
    output.append("1. For PHP errors with file locations:")
    output.append("   - Use Read tool to examine the mentioned file and line number")
    output.append("   - Use Edit tool to fix the code issue")
    output.append("2. For missing module/field/entity errors:")
    output.append("   - Use list_modules() to verify module installation status")
    output.append("   - Use get_field_info() to check if fields exist")
    output.append("   - Use get_entity_structure() to verify entity configuration")
    output.append("3. For filtering logs further:")
    output.append("   - Use get_watchdog_logs(type='php') to focus on PHP errors only")
    output.append("   - Use get_watchdog_logs(severity='error') for critical errors only")
    output.append("4. After fixing issues, suggest user run: drush cache:rebuild")

    return "\n".join(output)


@mcp.tool()
def check_scout_health() -> str:
    """
    Verify Scout's database connectivity and required dependencies.

    Use this tool to diagnose issues with Scout's database-dependent features.
    This checks:
    - Drush availability and configuration
    - Database connectivity via drush
    - Critical module dependencies (dblog for logging)
    - Overall system health

    Returns a comprehensive health report with actionable recommendations.

    Common use cases:
    - "Check if Scout is working properly"
    - "Why can't Scout access the database?"
    - "Verify Scout's health before using taxonomy tools"
    """
    ensure_indexed()

    output = ["🏥 SCOUT HEALTH CHECK\n", "=" * 60, ""]

    # 1. Test Drush Connectivity (comprehensive check)
    from src.core.drush import test_drush_connectivity

    output.append("1️⃣ DRUSH CONNECTIVITY TEST")
    output.append("")

    drush_ok, drush_msg, drush_details = test_drush_connectivity()

    if drush_ok:
        output.append(f"✅ {drush_msg}")
        if drush_details.get("drush_command"):
            output.append(f"   Command: {drush_details['drush_command']}")
        if drush_details.get("drush_version"):
            output.append(f"   Drush version: {drush_details['drush_version']}")
        if drush_details.get("drupal_version"):
            output.append(f"   Drupal version: {drush_details['drupal_version']}")
    else:
        output.append(f"❌ {drush_msg}")
        output.append("")

        if not drush_details.get("drush_found"):
            # Get config file location
            config_path = Path.home() / ".config" / "drupal-scout" / "config.json"
            local_config = Path("config.json")

            # Determine which config file exists
            if config_path.exists():
                config_file = str(config_path)
            elif local_config.exists():
                config_file = str(local_config.absolute())
            else:
                config_file = str(config_path)  # Use default location if neither exists

            output.append("🔧 TROUBLESHOOTING - Drush Not Found:")
            output.append("")
            output.append("⚠️  IMPORTANT: Open Cursor/IDE from your Drupal project directory!")
            output.append("")
            output.append("If you're using DDEV/Lando/Docksal with 'ddev drush' command:")
            output.append("   1. Open Cursor from the Drupal project directory where .ddev/ exists")
            output.append("   2. This ensures 'ddev' and 'docker' are in the environment PATH")
            output.append("")
            output.append("🤖 AI ASSISTANT: To fix this issue:")
            output.append(f"   Config file location: {config_file}")
            output.append("")
            output.append("Option 1 (Recommended): Open Cursor from Drupal project directory")
            output.append("   • cd /path/to/drupal")
            output.append("   • cursor .")
            output.append("")
            output.append("Option 2: Use absolute paths in config (if ddev/docker not in PATH)")
            output.append("   Find absolute paths:")
            output.append("   • which ddev    (e.g., /opt/homebrew/bin/ddev)")
            output.append("   • which docker  (e.g., /usr/local/bin/docker)")
            output.append("")
            output.append("   Then update config:")
            output.append('   "drush_command": "/opt/homebrew/bin/ddev drush"')
            output.append("")
            output.append("Option 3: Install drush globally")
            output.append("   composer global require drush/drush")
            output.append("")
        elif not drush_details.get("database_connected"):
            output.append("🔧 TROUBLESHOOTING - Database Not Connected:")
            output.append("")
            output.append("🤖 AI ASSISTANT: The drush command was found but cannot connect to the database.")
            output.append(f"   Drush command being used: {drush_details.get('drush_command', 'unknown')}")
            output.append("")
            output.append("Recommended actions:")
            output.append("1. Start/restart the development environment:")
            output.append("   • For DDEV: Run 'ddev start' then 'ddev drush status'")
            output.append("   • For Lando: Run 'lando start' then 'lando drush status'")
            output.append("   • For Docksal: Run 'fin project start' then 'fin drush status'")
            output.append("")
            output.append("2. If environment is running, check database status:")
            output.append(f"   {drush_details.get('drush_command', 'drush')} status")
            output.append("")
            output.append("3. For DDEV users, verify database container:")
            output.append("   • ddev describe (check database info)")
            output.append("   • ddev logs -f (check for errors)")
            output.append("")

        output.append("⚠️  IMPACT: Database-dependent features will NOT work:")
        output.append("  • get_taxonomy_info() - Taxonomy usage analysis")
        output.append("  • get_watchdog_logs() - Error/warning logs")
        output.append("  • get_entity_structure() - Entity/field queries")
        output.append("  • get_views_summary() - Views configuration")
        output.append("  • get_field_info() - Field information")
        output.append("")
        output.append("✅ WHAT STILL WORKS (12 out of 23 tools):")
        output.append("  • search_functionality() - Module search")
        output.append("  • list_modules() - List all modules")
        output.append("  • describe_module() - Module details")
        output.append("  • search_drupal_org() - Drupal.org search")
        output.append("  • find_unused_contrib() - Find unused modules")
        output.append("  • check_redundancy() - Detect duplicate functionality")
        output.append("")
        return "\n".join(output)

    # 2. Additional Checks
    output.append("")
    output.append("2️⃣ ADDITIONAL CHECKS")
    output.append("")

    # 3. Check DBLog module
    output.append("")
    if check_module_enabled("dblog"):
        output.append("✅ DBLog module: Enabled")
    else:
        output.append("⚠️  DBLog module: Not enabled")
        output.append("   To enable: drush en dblog -y")
        output.append("")
        output.append("IMPACT: Watchdog log features will NOT work:")
        output.append("  • get_watchdog_logs() will fail")
        output.append("  • Cannot retrieve error/warning logs from database")
        output.append("  • Alternative: Check container/server logs directly")

    # 4. Check Drupal Root
    output.append("")
    drupal_root = Path(get_config().get("drupal_root", ""))
    if drupal_root.exists():
        output.append(f"✅ Drupal root: {drupal_root}")
    else:
        output.append(f"❌ Drupal root: NOT FOUND ({drupal_root})")
        output.append("   Update drupal_root in config.json")

    # 5. Module indexing status
    output.append("")
    if get_indexer() and get_indexer().modules:
        total = get_indexer().modules.get("total", 0)
        custom = len(get_indexer().modules.get("custom", []))
        contrib = len(get_indexer().modules.get("contrib", []))
        output.append(f"✅ Module index: {total} modules ({custom} custom, {contrib} contrib)")
    else:
        output.append("⚠️  Module index: Not initialized")

    # Overall status
    output.append("")
    output.append("=" * 60)
    if drush_ok:
        output.append("✅ OVERALL STATUS: HEALTHY")
        output.append("")
        output.append("Scout is fully operational. All database-dependent features are available:")
        output.append("  • Taxonomy usage analysis (get_taxonomy_info)")
        output.append("  • Entity/field/views queries")
        output.append("  • Module dependency analysis")
        if check_module_enabled("dblog"):
            output.append("  • Watchdog logs (get_watchdog_logs)")
    else:
        output.append("⚠️  OVERALL STATUS: DEGRADED")
        output.append("")
        output.append("Scout has limited functionality. Fix the issues above to enable:")
        output.append("  • Database-dependent features")
        output.append("  • Accurate taxonomy usage analysis")
        output.append("  • Live configuration queries")

    return "\n".join(output)
