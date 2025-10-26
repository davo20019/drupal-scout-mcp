# Drupal Scout MCP - Troubleshooting Guide

This guide helps you diagnose and fix common issues with Drupal Scout, especially database connectivity problems when using it via MCP (Model Context Protocol) in tools like Cursor.

## Quick Diagnostic

Run the health check tool first:
```
check_scout_health()
```

This will tell you exactly what's working and what's not.

## AI-Assisted Troubleshooting (NEW!)

Scout now provides **AI-friendly error messages** that include:

- 🤖 Exact config file location to edit
- 📝 Ready-to-use JSON snippets
- 🔧 Step-by-step fix instructions
- 💡 Context-aware suggestions

**When you encounter a database error, Scout will:**
1. Show you the exact config file path
2. Provide the exact JSON to add
3. Give you examples for your specific environment (DDEV, Lando, etc.)

**For AI assistants (Cursor, Claude):** The error responses include `ai_fix_instructions` that you can use to automatically suggest or apply the fix. Look for the `config_file` path and `example_config` in error messages.

---

## Common Issue: "Database-dependent tools not working"

### Symptoms:
- `get_taxonomy_info()` returns empty or errors
- `get_watchdog_logs()` says DBLog not enabled (but it is)
- `get_entity_structure()` returns "database connection issue"
- `get_field_info()` returns unformatted data
- `get_views_summary()` returns views but no details

### Root Cause:
Scout can't execute drush commands to access your Drupal database.

### Why This Happens:
When Scout runs via MCP (in Cursor/Claude Desktop), it runs in a different environment than your terminal:
- Different working directory
- Different PATH environment variables
- Can't find `ddev`, `lando`, or other dev tools
- May not be able to execute drush commands

---

## Solution 1: Configure drush_command (Recommended)

Tell Scout exactly how to run drush by adding `drush_command` to your config.json:

### For DDEV users:
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "ddev drush"
}
```

### For Lando users:
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "lando drush"
}
```

### For Docksal users:
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "fin drush"
}
```

### For Composer/global drush:
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "/full/path/to/vendor/bin/drush"
}
```

**After editing config.json:**
1. Save the file
2. Restart the MCP server (in Cursor: reload window or restart MCP server)
3. Run `check_scout_health()` to verify

---

## Solution 2: Ensure Dev Environment is Running

Scout auto-detects DDEV/Lando/Docksal, but your dev environment must be running:

### For DDEV:
```bash
# Check if DDEV is running
ddev describe

# If not running, start it
ddev start

# Test drush works
ddev drush status
```

### For Lando:
```bash
# Check if Lando is running
lando info

# If not running, start it
lando start

# Test drush works
lando drush status
```

### For Docksal:
```bash
# Check if Docksal is running
fin project status

# If not running, start it
fin project start

# Test drush works
fin drush status
```

---

## Solution 3: Verify Drupal Root Path

Scout needs the correct path to your Drupal installation:

```json
{
  "drupal_root": "/Users/yourname/projects/mysite"
}
```

**How to find it:**
```bash
# Go to your Drupal directory
cd /path/to/drupal

# Run pwd to get full path
pwd
```

The drupal_root should be the directory containing:
- `web/` or `docroot/` (Drupal files)
- `composer.json`
- `vendor/`
- `.ddev/` or `.lando.yml` (if using dev environment)

---

## Debugging Steps

### Step 1: Check Drush Detection
Look at the Scout server logs when it starts. You should see:

**✅ Good (drush found):**
```
🔍 Starting drush detection...
   Drupal root: /Users/you/projects/drupalsite
   Root exists: True
   DDEV config (.ddev/config.yaml): True
✅ Detected DDEV environment (ddev command found)
```

**❌ Bad (drush not found):**
```
🔍 Starting drush detection...
   Drupal root: /Users/you/projects/drupalsite
   Root exists: True
   DDEV config (.ddev/config.yaml): True
⚠️  Found .ddev/config.yaml but 'ddev' command not in PATH
   Composer drush (/path/to/vendor/bin/drush): False
   Global drush: not found
❌ Drush not found in any expected location
```

### Step 2: Test Drush Manually
In your terminal, try running the exact command Scout would use:

```bash
# For DDEV
cd /path/to/drupal
ddev drush status

# For Lando
cd /path/to/drupal
lando drush status

# For Composer drush
cd /path/to/drupal
vendor/bin/drush status
```

If any of these fail, fix that first before using Scout.

### Step 3: Check Database Connection
```bash
# Test database connectivity
ddev drush sqlq "SELECT 1"

# Should output: 1

# If it fails, check:
ddev describe  # Verify database is running
ddev logs      # Check for errors
```

---

## What Works Without Database?

Even if database connectivity is broken, these **12 tools still work** because they only read local files:

### ✅ File-based Tools (Always Work)
1. `search_functionality()` - Search modules by functionality
2. `list_modules()` - List all modules
3. `describe_module()` - Get module details
4. `find_unused_contrib()` - Find unused contrib modules
5. `check_redundancy()` - Check for duplicate functionality
6. `reindex_modules()` - Re-index module files
7. `search_drupal_org()` - Search drupal.org
8. `get_module_recommendation()` - Get module suggestions
9. `get_drupal_org_module_details()` - Module info from drupal.org
10. `get_popular_drupal_modules()` - Popular modules list
11. `search_module_issues()` - Search issue queues
12. `analyze_module_dependencies()` - Dependency analysis (partial)

### ⚠️ Database-dependent Tools (Need Drush)
1. `get_taxonomy_info()` - Taxonomy usage (requires DB)
2. `get_all_taxonomy_usage()` - Batch taxonomy export (requires DB)
3. `get_entity_structure()` - Entity/bundle info (requires DB)
4. `get_field_info()` - Field configurations (requires DB)
5. `get_views_summary()` - Views details (requires DB)
6. `get_watchdog_logs()` - Error logs (requires DB + dblog module)
7. `export_taxonomy_usage_to_csv()` - CSV export (requires DB)
8. `export_nodes_to_csv()` - CSV export (requires DB)
9. `export_users_to_csv()` - CSV export (requires DB)
10. `find_hook_implementations()` - Hook usage (requires DB for accuracy)
11. `check_scout_health()` - Health check (always works, but shows DB status)

---

## Advanced Debugging

### Enable Debug Logging
Scout uses Python's logging module. To see more detailed logs:

1. Check your MCP server logs (in Cursor: View → Output → Select "MCP" from dropdown)
2. Look for drush detection messages
3. Look for database connection attempts

### Test Drush Command Directly
Create a test script:

```python
# test_drush.py
from pathlib import Path
import subprocess

drupal_root = Path("/path/to/your/drupal")
cmd = ["ddev", "drush", "status", "--format=json"]

result = subprocess.run(
    cmd,
    cwd=str(drupal_root),
    capture_output=True,
    text=True,
    timeout=10
)

print(f"Return code: {result.returncode}")
print(f"Output: {result.stdout}")
print(f"Error: {result.stderr}")
```

Run it:
```bash
python test_drush.py
```

If this fails, the problem is with drush/DDEV, not Scout.

---

## Still Not Working?

### Check the Logs
Look for these specific error messages in the MCP server logs:

**"Drush not found in any expected location"**
→ Solution 1: Add drush_command to config.json

**"Found .ddev/config.yaml but 'ddev' command not in PATH"**
→ DDEV is installed but not in PATH when MCP runs
→ Solution: Use absolute path in config.json: `"drush_command": "/usr/local/bin/ddev drush"`

**"Database status: Not connected"**
→ Drush works but can't connect to database
→ Check: `ddev drush status` manually
→ Verify database credentials in settings.php

**"DBLog module: Not enabled" (but it IS enabled)**
→ Scout can't query the database to check module status
→ This is a symptom of the main drush connectivity issue

### Get Help
If you're still stuck:

1. Run `check_scout_health()` and save the output
2. Check the MCP server logs (all of them)
3. Run `ddev drush status` manually and save output
4. Create a GitHub issue with all three outputs

---

## Prevention: Test Before Using

When setting up Scout, always run `check_scout_health()` first:

```
check_scout_health()
```

This will tell you:
- ✅ What's working
- ❌ What's broken
- 🔧 How to fix it

If the health check shows "HEALTHY", all 23 tools will work.
If it shows "DEGRADED", you'll know exactly which tools won't work and why.

---

## Configuration Examples

### Minimal Config (DDEV auto-detect):
```json
{
  "drupal_root": "/Users/davidloor/projects/drupalcms"
}
```
Scout will auto-detect DDEV if `.ddev/config.yaml` exists and `ddev` is in PATH.

### Explicit Config (Recommended for MCP):
```json
{
  "drupal_root": "/Users/davidloor/projects/drupalcms",
  "drush_command": "ddev drush"
}
```
Explicitly tells Scout how to run drush, avoiding auto-detection issues.

### Full Config with All Options:
```json
{
  "drupal_root": "/Users/davidloor/projects/drupalcms",
  "modules_path": "modules",
  "drush_command": "ddev drush",
  "drupal_version": "10"
}
```

---

## Summary

**Most common fix:** Add this to config.json:
```json
{
  "drupal_root": "/your/path",
  "drush_command": "ddev drush"
}
```

Then restart the MCP server and run `check_scout_health()`.
