#!/usr/bin/env python3
"""Script to refactor server.py to use core modules."""

import re

# Read the current server.py
with open("server.py", "r") as f:
    content = f.read()

# Step 1: Remove old function definitions (lines 51-285 approximately)
# We'll remove from "def load_config():" to just before "@mcp.tool()"
pattern_to_remove = r'\ndef load_config\(\).*?(?=\n@mcp\.tool\(\))'
content = re.sub(pattern_to_remove, '\n', content, flags=re.DOTALL)

# Step 2: Remove global state variables
old_globals = """# Global state
indexer: Optional[ModuleIndexer] = None
searcher: Optional[ModuleSearch] = None
prioritizer = ResultPrioritizer()
drupal_org_api = DrupalOrgAPI()
config = {}
_drush_command_cache: Optional[List[str]] = None"""

new_comment = """# Note: Global state (config, indexer, searcher, etc.) now managed in src/core/config.py
# Access via get_config(), get_indexer(), get_searcher(), get_prioritizer(), get_drupal_org_api()"""

content = content.replace(old_globals, new_comment)

# Step 3: Replace global variable usages with getter functions
replacements = [
    (r'\bconfig\b(?!\))', 'get_config()'),  # config -> get_config() (but not if already in function call)
    (r'\bindexer\b(?!:)', 'get_indexer()'),  # indexer -> get_indexer()
    (r'\bsearcher\b(?!:)', 'get_searcher()'),  # searcher -> get_searcher()
    (r'\bprior itizer\b(?!:|\s*=\s*ResultPrioritizer)', 'get_prioritizer()'),  # prioritizer -> get_prioritizer()
    (r'\bdrupal_org_api\b(?!:)', 'get_drupal_org_api()'),  # drupal_org_api -> get_drupal_org_api()
]

for pattern, replacement in replacements:
    content = re.sub(pattern, replacement, content)

# Write the refactored content
with open("server.py", "w") as f:
    f.write(content)

print("Refactoring complete!")
print("Check server.py and compare with server.py.backup")
