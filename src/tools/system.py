"""
System health and logging tools.

Provides tools for system diagnostics and error analysis:
- get_watchdog_logs: Get Drupal watchdog logs for debugging
- check_scout_health: Verify Scout's database connectivity and health
- get_available_updates: Get report of available updates for Drupal core and contrib modules
- get_status_report: Get Drupal status report with errors, warnings, and recommendations

These tools help monitor and troubleshoot the Drupal site.
"""

import logging
import subprocess
from pathlib import Path
from typing import Optional

# Import from core modules
from src.core.config import ensure_indexed, get_config, get_indexer
from src.core.database import check_module_enabled
from src.core.drush import run_drush_command, get_drush_command, _setup_drush_environment

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

    # Build drush watchdog:show command
    # NOTE: Drush requires capitalized severity levels (Error, Warning, etc.)
    valid_severities = {
        "emergency": "Emergency",
        "alert": "Alert",
        "critical": "Critical",
        "error": "Error",
        "warning": "Warning",
        "notice": "Notice",
        "info": "Info",
        "debug": "Debug",
    }

    # Try to get logs from drush
    # NOTE: Drush watchdog:show doesn't support comma-separated severities
    # If no severity specified, we fetch errors and warnings separately
    if severity:
        severity_lower = severity.lower()
        if severity_lower not in valid_severities:
            return f"❌ Invalid severity level: {severity}\nValid options: {', '.join(valid_severities.keys())}"

        # Get the properly capitalized severity for drush
        drush_severity = valid_severities[severity_lower]

        # Single severity - simple case
        args = [
            "watchdog:show",
            "--format=json",
            f"--count={limit}",
            f"--severity={drush_severity}",
        ]
        if type:
            args.append(f"--type={type}")

        result = run_drush_command(args, timeout=15)
    else:
        # Default to errors and warnings - need to fetch separately and combine
        # Fetch errors first
        error_args = ["watchdog:show", "--format=json", f"--count={limit}", "--severity=Error"]
        if type:
            error_args.append(f"--type={type}")

        error_result = run_drush_command(error_args, timeout=15)

        # Fetch warnings
        warning_args = ["watchdog:show", "--format=json", f"--count={limit}", "--severity=Warning"]
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
            output.append(
                "🤖 AI ASSISTANT: The drush command was found but cannot connect to the database."
            )
            output.append(
                f"   Drush command being used: {drush_details.get('drush_command', 'unknown')}"
            )
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


@mcp.tool()
def get_available_updates(include_dev: bool = False, security_only: bool = False) -> str:
    """
    Get comprehensive report of available updates for Drupal core and contrib modules.

    This tool helps identify outdated packages without requiring login to the site.
    Perfect for:
    - Proactive maintenance and security monitoring
    - Planning update sprints
    - Identifying security vulnerabilities
    - Understanding technical debt

    The tool uses composer to check for available updates, providing:
    - Current version vs available version
    - Update type (security, minor, major)
    - Package descriptions
    - Update recommendations

    Common use cases:
    - "What updates are available?"
    - "Are there any security updates?"
    - "Show me all outdated packages"
    - "What's the status of Drupal core updates?"

    Args:
        include_dev: Include dev dependencies in the report (default: False)
        security_only: Only show packages with security updates (default: False)

    Returns:
        Formatted report of available updates with recommendations

    Examples:
        get_available_updates()  # All production updates
        get_available_updates(security_only=True)  # Security updates only
        get_available_updates(include_dev=True)  # Include dev dependencies

    Note: This tool runs 'composer outdated' which checks drupal.org and packagist
          for available updates. Requires composer and network connectivity.
    """
    ensure_indexed()

    output = []
    output.append("🔄 DRUPAL UPDATES REPORT\n")
    output.append("=" * 80)
    output.append("")

    # Get Drupal root from config
    config = get_config()
    drupal_root = Path(config.get("drupal_root"))

    if not drupal_root.exists():
        return (
            "❌ ERROR: Drupal root not found\n\n"
            f"The configured drupal_root does not exist: {drupal_root}\n"
            "Please update drupal_root in config.json"
        )

    # Check if composer.json exists
    composer_json = drupal_root / "composer.json"
    if not composer_json.exists():
        return (
            "❌ ERROR: composer.json not found\n\n"
            f"No composer.json found in: {drupal_root}\n"
            "This tool requires a Composer-managed Drupal site."
        )

    # Determine the composer command to use
    # For DDEV/Lando, use the wrapper; otherwise use system composer
    drush_cmd = get_drush_command()
    if drush_cmd and len(drush_cmd) > 1:
        # Extract the environment wrapper (ddev, lando, fin)
        wrapper = drush_cmd[0]
        if wrapper in ["ddev", "lando", "fin"]:
            composer_cmd = [wrapper, "composer"]
        else:
            composer_cmd = ["composer"]
    else:
        composer_cmd = ["composer"]

    # Build the composer outdated command
    cmd_args = ["outdated", "--format=json", "--direct"]

    if not include_dev:
        cmd_args.append("--no-dev")

    # Run composer outdated
    try:
        env = _setup_drush_environment()
        result = subprocess.run(
            [*composer_cmd, *cmd_args],
            cwd=str(drupal_root),
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )

        # Composer outdated returns exit code 0 if no updates, non-zero if updates available
        # So we don't check returncode, just parse the output
        if not result.stdout.strip():
            output.append("✅ ALL PACKAGES UP TO DATE")
            output.append("")
            output.append("No updates are currently available for your installed packages.")
            return "\n".join(output)

        import json

        data = json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        return (
            "❌ ERROR: Composer command timed out\n\n"
            "The composer outdated command took too long to complete.\n"
            "This might indicate network issues or a very large project.\n\n"
            "Try running manually:\n"
            f"  cd {drupal_root}\n"
            f"  {' '.join(composer_cmd)} outdated --direct"
        )
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse composer JSON: {e}")
        logger.error(f"Output was: {result.stdout[:500]}")
        return (
            "❌ ERROR: Failed to parse composer output\n\n"
            f"Composer command: {' '.join(composer_cmd + cmd_args)}\n"
            f"Error: {str(e)}\n\n"
            "The output format may have changed. Try running manually:\n"
            f"  cd {drupal_root}\n"
            f"  {' '.join(composer_cmd)} outdated --direct"
        )
    except Exception as e:
        logger.error(f"Error running composer outdated: {e}")
        return (
            f"❌ ERROR: Failed to run composer outdated\n\n"
            f"Error: {str(e)}\n\n"
            "Ensure composer is installed and accessible.\n"
            f"Command attempted: {' '.join(composer_cmd + cmd_args)}\n\n"
            "For DDEV users: Ensure DDEV is running (ddev start)\n"
            "For Lando users: Ensure Lando is running (lando start)"
        )

    # Parse the outdated packages
    # Composer outdated JSON format:
    # {
    #   "installed": [
    #     {
    #       "name": "drupal/core",
    #       "version": "11.2.4",
    #       "latest": "11.2.5",
    #       "latest-status": "semver-safe-update",
    #       "description": "Drupal is an open source content management platform..."
    #     }
    #   ]
    # }

    if "installed" not in data or not data["installed"]:
        output.append("✅ ALL PACKAGES UP TO DATE")
        output.append("")
        output.append("No updates are currently available for your installed packages.")
        return "\n".join(output)

    packages = data["installed"]

    # Filter for security updates if requested
    if security_only:
        # Composer doesn't directly mark security updates in outdated command
        # We would need to run 'composer audit' for that
        # For now, show a message and run audit instead
        output.append("🔒 SECURITY UPDATES CHECK\n")
        output.append("Checking for security advisories...\n")

        try:
            audit_result = subprocess.run(
                [*composer_cmd, "audit", "--format=json"],
                cwd=str(drupal_root),
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )

            if audit_result.returncode == 0:
                output.append("✅ NO KNOWN SECURITY VULNERABILITIES")
                output.append("")
                output.append(
                    "All installed packages are free from known security advisories."
                )
                return "\n".join(output)
            else:
                # Parse audit output
                audit_data = json.loads(audit_result.stdout)
                if "advisories" in audit_data and audit_data["advisories"]:
                    output.append(
                        f"⚠️  FOUND {len(audit_data['advisories'])} SECURITY ADVISORIES\n"
                    )

                    for pkg_name, advisories in audit_data["advisories"].items():
                        output.append(f"📦 {pkg_name}")
                        for adv in advisories:
                            output.append(f"   • {adv.get('title', 'Security issue')}")
                            output.append(
                                f"     Affected: {adv.get('affectedVersions', 'unknown')}"
                            )
                            output.append(f"     CVE: {adv.get('cve', 'N/A')}")
                            if adv.get("link"):
                                output.append(f"     More info: {adv['link']}")
                        output.append("")

                    output.append("\n🔧 RECOMMENDED ACTIONS:")
                    output.append("1. Review the security advisories above")
                    output.append("2. Update affected packages: composer update <package-name>")
                    output.append("3. Test thoroughly after updates")
                    output.append("4. Deploy to production ASAP for security fixes")

                    return "\n".join(output)

        except Exception as e:
            logger.error(f"Error running composer audit: {e}")
            output.append(f"⚠️  Could not run security audit: {str(e)}\n")
            output.append("Falling back to standard outdated report...\n")

    # Categorize packages
    core_updates = []
    contrib_updates = []
    other_updates = []

    for pkg in packages:
        name = pkg.get("name", "")
        if name.startswith("drupal/core"):
            core_updates.append(pkg)
        elif name.startswith("drupal/"):
            contrib_updates.append(pkg)
        else:
            other_updates.append(pkg)

    # Display summary
    total_updates = len(packages)
    output.append(f"📊 SUMMARY: {total_updates} packages have updates available\n")
    output.append(f"   • Drupal Core: {len(core_updates)} packages")
    output.append(f"   • Contributed Modules: {len(contrib_updates)} packages")
    output.append(f"   • Other Dependencies: {len(other_updates)} packages")
    output.append("")

    # Helper function to format update info
    def format_update(pkg):
        name = pkg.get("name", "unknown")
        current = pkg.get("version", "unknown")
        latest = pkg.get("latest", "unknown")
        status = pkg.get("latest-status", "unknown")
        desc = pkg.get("description", "")

        # Interpret status
        if status == "semver-safe-update":
            update_type = "✅ SAFE (minor/patch)"
        elif status == "update-possible":
            update_type = "⚠️  MAJOR (breaking changes possible)"
        elif status == "up-to-date":
            update_type = "✅ UP TO DATE"
        else:
            update_type = f"❓ {status}"

        lines = []
        lines.append(f"📦 {name}")
        lines.append(f"   Current: {current} → Latest: {latest}")
        lines.append(f"   Type: {update_type}")
        if desc:
            # Truncate long descriptions
            desc_short = desc[:80] + "..." if len(desc) > 80 else desc
            lines.append(f"   {desc_short}")
        lines.append("")
        return lines

    # Display Drupal Core updates
    if core_updates:
        output.append("=" * 80)
        output.append("🌟 DRUPAL CORE UPDATES")
        output.append("=" * 80)
        output.append("")
        for pkg in core_updates:
            output.extend(format_update(pkg))

    # Display contrib module updates
    if contrib_updates:
        output.append("=" * 80)
        output.append("🔌 CONTRIBUTED MODULE UPDATES")
        output.append("=" * 80)
        output.append("")
        for pkg in contrib_updates:
            output.extend(format_update(pkg))

    # Display other dependency updates
    if other_updates and include_dev:
        output.append("=" * 80)
        output.append("📚 OTHER DEPENDENCIES")
        output.append("=" * 80)
        output.append("")
        for pkg in other_updates:
            output.extend(format_update(pkg))

    # Recommendations
    output.append("=" * 80)
    output.append("🔧 RECOMMENDED ACTIONS")
    output.append("=" * 80)
    output.append("")

    if core_updates:
        output.append("1. DRUPAL CORE UPDATES:")
        output.append("   • Review the Drupal core release notes")
        output.append("   • Backup your database before updating")
        output.append("   • Update core: composer update drupal/core-* --with-dependencies")
        output.append("   • Run database updates: drush updatedb")
        output.append("   • Clear caches: drush cache:rebuild")
        output.append("")

    if contrib_updates:
        output.append("2. CONTRIB MODULE UPDATES:")
        output.append("   • Review each module's release notes")
        output.append("   • Update individually: composer update drupal/<module-name>")
        output.append("   • Or update all: composer update drupal/*")
        output.append("   • Check for breaking changes in major updates")
        output.append("")

    output.append("3. SECURITY UPDATES:")
    output.append("   • Run: composer audit")
    output.append("   • Or use: get_available_updates(security_only=True)")
    output.append("   • Prioritize security updates over feature updates")
    output.append("")

    output.append("4. TESTING:")
    output.append("   • Test updates in development environment first")
    output.append("   • Verify all functionality still works")
    output.append("   • Check watchdog logs for errors: get_watchdog_logs()")
    output.append("   • Run automated tests if available")
    output.append("")

    # Note about manual update
    output.append("=" * 80)
    output.append("ℹ️  NOTE")
    output.append("=" * 80)
    output.append("")
    output.append("This is a READ-ONLY report. Updates are NOT automatically applied.")
    output.append("To apply updates, use the composer commands shown above or ask the AI")
    output.append("assistant to help update specific packages.")
    output.append("")

    return "\n".join(output)


@mcp.tool()
def get_status_report(
    severity_filter: Optional[str] = None, include_ok: bool = False
) -> str:
    """
    Get Drupal status report showing system health, errors, warnings, and recommendations.

    This tool fetches the same information shown on /admin/reports/status page,
    helping AI assistants diagnose and fix site issues without requiring login.

    Perfect for:
    - Identifying configuration issues
    - Security vulnerability detection
    - Performance and optimization recommendations
    - Module-specific setup problems
    - File permission issues
    - Database and PHP configuration checks

    The tool uses drush core:requirements to fetch:
    - Errors (severity 2) - Critical issues requiring immediate attention
    - Warnings (severity 1) - Important issues that should be addressed
    - Info (severity -1) - Informational messages
    - OK (severity 0) - Everything working correctly

    Common use cases:
    - "What errors are on the status report?"
    - "Check the site health"
    - "Why is the status report showing warnings?"
    - "Diagnose configuration issues"
    - "What security issues exist?"

    Args:
        severity_filter: Optional filter by severity level.
                        Options: "error", "warning", "info", "ok"
                        Default: Shows errors and warnings only
        include_ok: Include successful checks in report (default: False)
                   When True, shows all checks including those that passed

    Returns:
        Formatted status report with issues categorized by severity,
        including descriptions and recommended actions

    Examples:
        get_status_report()  # Errors and warnings only
        get_status_report(severity_filter="error")  # Only errors
        get_status_report(include_ok=True)  # All checks including successful ones
        get_status_report(severity_filter="warning")  # Only warnings

    Note: Requires drush connectivity. This is equivalent to visiting
          /admin/reports/status but accessible via AI without login.
    """
    ensure_indexed()

    output = []
    output.append("🏥 DRUPAL STATUS REPORT\n")
    output.append("=" * 80)
    output.append("")

    # Run drush core:requirements
    result = run_drush_command(["core:requirements", "--format=json"], timeout=30)

    if result is None:
        return (
            "❌ ERROR: Could not retrieve status report\n\n"
            "Drush command 'core:requirements' failed.\n\n"
            "Possible causes:\n"
            "1. Drush not configured properly\n"
            "2. Database connection issue\n"
            "3. Drupal site not bootstrapped correctly\n\n"
            "Troubleshooting:\n"
            "• Verify drush works: drush status\n"
            "• Check database connection\n"
            "• Use check_scout_health() to diagnose connectivity issues\n\n"
            "Alternative: Visit /admin/reports/status in your browser"
        )

    if not isinstance(result, dict):
        return (
            "❌ ERROR: Unexpected response format from drush core:requirements\n\n"
            "Expected a dictionary but got a different type.\n"
            "This might indicate a drush version compatibility issue."
        )

    # Severity mapping
    # Drupal uses: 2=Error, 1=Warning, 0=OK, -1=Info
    # The JSON output has both 'severity' (string) and 'sid' (int)
    severity_map = {"error": 2, "warning": 1, "ok": 0, "info": -1}
    severity_string_map = {"Error": 2, "Warning": 1, "OK": 0, "Info": -1}

    # Filter requirements by severity
    filtered_requirements = {}

    for key, requirement in result.items():
        # Try to get severity as integer from 'sid' field first
        severity_int = requirement.get("sid")

        # If sid is not available or not an int, try parsing 'severity' field
        if severity_int is None or not isinstance(severity_int, int):
            severity_str = requirement.get("severity", "")

            # Try to convert string severity to int
            if isinstance(severity_str, str):
                # Check if it's a severity name (Error, Warning, etc.)
                severity_int = severity_string_map.get(severity_str)

                # If not found, try parsing as number
                if severity_int is None:
                    try:
                        severity_int = int(severity_str)
                    except (ValueError, TypeError):
                        # Default to OK if we can't determine
                        severity_int = 0
            else:
                # Default to OK if we can't determine
                severity_int = 0

        requirement["severity_int"] = severity_int

        # Apply filters
        if severity_filter:
            filter_level = severity_map.get(severity_filter.lower())
            if filter_level is not None and severity != filter_level:
                continue

        # Skip OK checks unless explicitly included
        if not include_ok and severity == 0:
            continue

        filtered_requirements[key] = requirement

    if not filtered_requirements:
        if severity_filter:
            return f"No status report items found with severity: {severity_filter}"
        else:
            return "✅ No errors or warnings found in status report. Site is healthy!"

    # Categorize by severity
    errors = {k: v for k, v in filtered_requirements.items() if v["severity_int"] == 2}
    warnings = {k: v for k, v in filtered_requirements.items() if v["severity_int"] == 1}
    info = {k: v for k, v in filtered_requirements.items() if v["severity_int"] == -1}
    ok_checks = {k: v for k, v in filtered_requirements.items() if v["severity_int"] == 0}

    # Summary
    output.append("📊 SUMMARY\n")
    output.append(f"   ❌ Errors: {len(errors)}")
    output.append(f"   ⚠️  Warnings: {len(warnings)}")
    output.append(f"   ℹ️  Info: {len(info)}")
    if include_ok:
        output.append(f"   ✅ OK: {len(ok_checks)}")
    output.append("")

    # Helper function to format requirement
    def format_requirement(key, req):
        lines = []
        title = req.get("title", key)
        value = req.get("value", "").strip()
        description = req.get("description", "").strip()

        lines.append(f"• {title}")
        if value:
            # Clean up value - remove excessive newlines
            value_clean = " ".join(value.split())
            lines.append(f"  Status: {value_clean}")
        if description:
            # Clean up description and wrap long lines
            desc_clean = description.replace("\n\n", " | ")
            desc_clean = " ".join(desc_clean.split())
            # Wrap at 76 chars (accounting for 2 char indent)
            if len(desc_clean) > 76:
                words = desc_clean.split()
                current_line = "  "
                for word in words:
                    if len(current_line + word) > 78:
                        lines.append(current_line.rstrip())
                        current_line = "  " + word + " "
                    else:
                        current_line += word + " "
                if current_line.strip():
                    lines.append(current_line.rstrip())
            else:
                lines.append(f"  {desc_clean}")
        lines.append("")
        return lines

    # Display errors
    if errors:
        output.append("=" * 80)
        output.append("❌ ERRORS (Critical Issues)")
        output.append("=" * 80)
        output.append("")
        for key, req in errors.items():
            output.extend(format_requirement(key, req))

    # Display warnings
    if warnings:
        output.append("=" * 80)
        output.append("⚠️  WARNINGS (Important Issues)")
        output.append("=" * 80)
        output.append("")
        for key, req in warnings.items():
            output.extend(format_requirement(key, req))

    # Display info
    if info and (include_ok or not severity_filter):
        output.append("=" * 80)
        output.append("ℹ️  INFORMATION")
        output.append("=" * 80)
        output.append("")
        for key, req in info.items():
            output.extend(format_requirement(key, req))

    # Display OK checks if requested
    if ok_checks and include_ok:
        output.append("=" * 80)
        output.append("✅ SUCCESSFUL CHECKS")
        output.append("=" * 80)
        output.append("")
        for key, req in ok_checks.items():
            output.extend(format_requirement(key, req))

    # AI Assistant recommendations
    output.append("=" * 80)
    output.append("🤖 AI ASSISTANT - RECOMMENDED ACTIONS")
    output.append("=" * 80)
    output.append("")

    if errors:
        output.append("CRITICAL ERRORS - Address these immediately:")
        output.append("")
        for key, req in errors.items():
            title = req.get("title", key)
            output.append(f"• {title}")

            # Provide specific guidance based on common error types
            if "permission" in title.lower() or "writable" in req.get("value", "").lower():
                output.append("  → Fix file permissions with: chmod or chown commands")
                output.append("  → For settings.php: chmod 444 sites/default/settings.php")
            elif "ai" in title.lower() and "provider" in title.lower():
                output.append("  → Configure AI provider at /admin/config/ai/settings")
                output.append("  → Or disable the AI module if not needed")
            elif "database" in title.lower():
                output.append("  → Check database connection in settings.php")
                output.append("  → Verify database server is running")
            elif "update" in title.lower() or "readiness" in title.lower():
                output.append("  → Review automatic updates configuration")
                output.append("  → May require manual intervention or module updates")

        output.append("")

    if warnings:
        output.append("WARNINGS - Should be addressed soon:")
        output.append("")
        for key, req in warnings.items():
            title = req.get("title", key)
            output.append(f"• {title}")

            # Provide specific guidance
            if "settings.php" in req.get("description", "").lower():
                output.append("  → Make settings.php read-only: chmod 444 sites/default/settings.php")
            elif "trusted host" in title.lower():
                output.append("  → Configure trusted_host_patterns in settings.php")
            elif "cron" in title.lower():
                output.append("  → Run cron: drush cron")
                output.append("  → Configure automated cron or external cron job")

        output.append("")

    output.append("GENERAL TROUBLESHOOTING:")
    output.append("1. Read the descriptions carefully - they often contain direct links to fix issues")
    output.append("2. Use other Scout tools for deeper analysis:")
    output.append("   • get_watchdog_logs() - Check recent errors")
    output.append("   • get_available_updates() - Check for security updates")
    output.append("   • list_modules() - Verify module installation")
    output.append("3. Visit /admin/reports/status in browser for clickable links")
    output.append("4. After fixing issues, clear caches: drush cache:rebuild")
    output.append("")

    output.append("=" * 80)
    output.append("ℹ️  NOTE")
    output.append("=" * 80)
    output.append("")
    output.append("This report is equivalent to /admin/reports/status page.")
    output.append("Some issues may require manual configuration or code changes.")
    output.append("Always test changes in a development environment first.")
    output.append("")

    return "\n".join(output)
