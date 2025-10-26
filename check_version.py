#!/usr/bin/env python3
"""
Diagnostic script to verify which version of server.py is being loaded.
Run this to see if the __main__ fix is present.
"""

import sys
import subprocess

print("=" * 70)
print("DRUPAL SCOUT VERSION CHECK")
print("=" * 70)
print()

# Check git commit
try:
    result = subprocess.run(
        ["git", "log", "--oneline", "-1"],
        capture_output=True,
        text=True,
        cwd="/Users/davidloor/projects/drupal-scout-mcp"
    )
    print(f"Git commit: {result.stdout.strip()}")
except Exception as e:
    print(f"Could not check git: {e}")

print()

# Check if fix is in server.py
server_path = "/Users/davidloor/projects/drupal-scout-mcp/server.py"
with open(server_path) as f:
    content = f.read()

has_fix = 'sys.modules["server"] = sys.modules["__main__"]' in content
print(f"Fix present in server.py: {'✅ YES' if has_fix else '❌ NO'}")

if not has_fix:
    print("\n⚠️  WARNING: The __main__ fix is NOT in server.py!")
    print("   This means the refactored modules won't load.")
    print("   Run: git pull")
    sys.exit(1)

print()

# Import and check tools
sys.path.insert(0, '/Users/davidloor/projects/drupal-scout-mcp')
import server

total_tools = len(server.mcp._tool_manager._tools)
print(f"Total tools registered: {total_tools}")

if total_tools < 23:
    print(f"\n❌ PROBLEM: Only {total_tools}/23 tools loaded!")
    print("\nDebugging info:")
    print(f"  - mcp instance ID: {id(server.mcp)}")
    print(f"  - __name__: {server.__name__}")

    # Check if modules imported
    print("\nChecking module imports:")
    try:
        import src.tools.exports
        print("  ✓ src.tools.exports imported")
        print(f"    - exports.mcp ID: {id(src.tools.exports.mcp)}")
        print(f"    - Same as server.mcp? {src.tools.exports.mcp is server.mcp}")
    except Exception as e:
        print(f"  ✗ src.tools.exports failed: {e}")

    try:
        import src.tools.drupal_org
        print("  ✓ src.tools.drupal_org imported")
        print(f"    - drupal_org.mcp ID: {id(src.tools.drupal_org.mcp)}")
        print(f"    - Same as server.mcp? {src.tools.drupal_org.mcp is server.mcp}")
    except Exception as e:
        print(f"  ✗ src.tools.drupal_org failed: {e}")

    try:
        import src.tools.system
        print("  ✓ src.tools.system imported")
        print(f"    - system.mcp ID: {id(src.tools.system.mcp)}")
        print(f"    - Same as server.mcp? {src.tools.system.mcp is server.mcp}")
    except Exception as e:
        print(f"  ✗ src.tools.system failed: {e}")

    try:
        import src.tools.entities
        print("  ✓ src.tools.entities imported")
        print(f"    - entities.mcp ID: {id(src.tools.entities.mcp)}")
        print(f"    - Same as server.mcp? {src.tools.entities.mcp is server.mcp}")
    except Exception as e:
        print(f"  ✗ src.tools.entities failed: {e}")
else:
    print("✅ All 23 tools loaded successfully!")

print()
print("=" * 70)
print("Tool breakdown:")
print("=" * 70)

# Categorize tools
drupal_org_tools = ['search_drupal_org', 'get_popular_drupal_modules', 'get_module_recommendation', 'get_drupal_org_module_details', 'search_module_issues']
system_tools = ['get_watchdog_logs', 'check_scout_health']
export_tools = ['export_taxonomy_usage_to_csv', 'export_nodes_to_csv', 'export_users_to_csv']
entity_tools = ['get_entity_structure', 'get_field_info']

tools = sorted(server.mcp._tool_manager._tools.keys())

drupal_org_count = sum(1 for t in tools if t in drupal_org_tools)
system_count = sum(1 for t in tools if t in system_tools)
export_count = sum(1 for t in tools if t in export_tools)
entity_count = sum(1 for t in tools if t in entity_tools)
server_count = total_tools - drupal_org_count - system_count - export_count - entity_count

print(f"  server.py: {server_count}/11 tools")
print(f"  drupal_org.py: {drupal_org_count}/5 tools")
print(f"  system.py: {system_count}/2 tools")
print(f"  exports.py: {export_count}/3 tools")
print(f"  entities.py: {entity_count}/2 tools")

if drupal_org_count < 5:
    print("\n❌ Missing drupal_org tools:")
    for t in drupal_org_tools:
        if t not in tools:
            print(f"  - {t}")

if system_count < 2:
    print("\n❌ Missing system tools:")
    for t in system_tools:
        if t not in tools:
            print(f"  - {t}")

if export_count < 3:
    print("\n❌ Missing export tools:")
    for t in export_tools:
        if t not in tools:
            print(f"  - {t}")

if entity_count < 2:
    print("\n❌ Missing entity tools:")
    for t in entity_tools:
        if t not in tools:
            print(f"  - {t}")

print()
print("=" * 70)
