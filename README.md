# Drupal Scout MCP

A Model Context Protocol server providing comprehensive Drupal analysis through intelligent data gathering and drush integration. Gives AI assistants deep knowledge of your Drupal site's structure, configuration, and the drupal.org ecosystem.

**Why use Drupal Scout?**
- **Saves tokens**: Single MCP calls replace multiple drush commands + greps, significantly reducing token usage
- **Faster responses**: Pre-processed data returns instantly vs chaining multiple commands
- **Better context**: Combines file configs + database state + usage analysis in one response
- **Smarter decisions**: Cross-references data (e.g., shows what depends on a module before uninstall)

**What it does:**
- **Analyzes** your Drupal installation with Drush-powered live database queries
- **Combines** static file analysis with active configuration data
- **Searches** drupal.org for modules, issues, and solutions
- **Provides** actionable insights for safe decision-making

**What it doesn't do:**
- Execute drush/composer commands (your AI handles that based on MCP data)
- Modify your site directly (read-only analysis)

## Features

**Deep Drupal Analysis (Drush-Powered)**

Drush integration enables live database queries for accurate, up-to-date analysis:

- **Entity & Content Type Structure**: Complete field configs, displays, bundles from active database
- **Views Discovery**: Filter by entity type, see displays/filters/relationships from live config
- **Field Usage Analysis**: Track fields across bundles, find duplicates in active configuration
- **Taxonomy Management**: Term hierarchies, usage analysis, safe-to-delete warnings with actual content checks
- **Error & Warning Logs**: Fetch recent watchdog logs to diagnose issues and fix code problems
- **Hook Implementation Finder**: Locate all hook implementations with line numbers via static analysis
- **Module Dependencies**: Reverse deps, circular detection, uninstall safety checks
- **Installation Status**: Check which modules are actually installed vs just present in codebase

**Local Module Analysis**

Static file analysis for fast, offline insights:

- Index and search your Drupal installation
- Find functionality across custom and contrib modules
- Detect unused modules (checks both code usage AND installation status via drush)
- Analyze service dependencies and routing
- Parse .info.yml, .services.yml, .routing.yml files

**Drupal.org Integration**

Access the entire Drupal ecosystem:

- Search 50,000+ modules on drupal.org
- Get detailed module information with compatibility data
- Search issue queues for solutions to specific problems
- Automatic Drupal version filtering for relevant results

**Intelligent Recommendations**

Make informed decisions:

- Compare modules side-by-side
- Get recommendations based on your needs
- See migration patterns from issue discussions
- Identify maintainer activity and community health

## Installation

### PyPI Installation (Recommended)

```bash
pip install drupal-scout-mcp
```

### Quick Install Script

```bash
curl -sSL https://raw.githubusercontent.com/davo20019/drupal-scout-mcp/main/install.sh | bash
```

### Manual Installation

1. **Clone the repository**
```bash
git clone https://github.com/davo20019/drupal-scout-mcp.git
cd drupal-scout-mcp
```

2. **Install dependencies**
```bash
pip3 install -r requirements.txt
```

3. **Configure Drupal path**
```bash
mkdir -p ~/.config/drupal-scout
cp config.example.json ~/.config/drupal-scout/config.json
```

Edit `~/.config/drupal-scout/config.json`:
```json
{
  "drupal_root": "/path/to/your/drupal",
  "modules_path": "modules"
}
```

4. **Add to MCP client**

For Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "drupal-scout": {
      "command": "python3",
      "args": ["/path/to/drupal-scout-mcp/server.py"]
    }
  }
}
```

For Cursor, add to MCP settings.

5. **Restart your MCP client**

## Available Tools

### Local Module Tools

**search_functionality** - Search for functionality across modules
```
Example: "Do we have email functionality?"
```

**list_modules** - List all installed modules with details
```
Example: "List all contrib modules"
```

**describe_module** - Get detailed information about a specific module
```
Example: "Describe the webform module"
```

**find_unused_contrib** - Find contrib modules that aren't used by custom code
```
Example: "Find unused contrib modules"
Enhanced: Now checks both code usage AND installation status via drush
Shows: Installed vs not installed, actionable uninstall commands
Helps: Safely identify modules that can be removed without breaking functionality
```

**check_redundancy** - Check if functionality exists before building
```
Example: "Should I build a PDF export feature?"
```

**reindex_modules** - Force re-indexing when modules change
```
Example: "Reindex modules"
```

**analyze_module_dependencies** - Analyze module dependency relationships
```
Example: "Can I safely uninstall the token module?"
Shows: Reverse dependencies, circular deps, uninstall safety
Unique: Unlike drush, shows what DEPENDS ON a module
```

**find_hook_implementations** - Find all implementations of a Drupal hook
```
Example: "Which modules implement hook_form_alter?"
Shows: All implementations with file locations and line numbers
Use case: Debugging hook execution order, finding conflicts
No drush needed: Pure file-based search using cached index
```

**get_entity_structure** - Get comprehensive entity type information
```
Example: "What fields does the node entity have?"
Shows: Bundles, fields, view displays, form displays
Combines: Config files + drush (if available)
Replaces: Multiple drush and grep commands in a single call
```

**get_views_summary** - Get summary of Views configurations with filtering
```
Example: "What views exist in the site?"
Example: "Do we have any user views?" (filters by entity_type="users")
Example: "Are there views showing articles?" (filters by entity_type="node")
Shows: View names, display types (page/block/feed), paths, filters, fields, relationships
Combines: Database active config via drush + config file parsing
Replaces: drush views:list + multiple greps
Use case: Understanding existing data displays before creating duplicates
Supports filtering by entity type (node, users, taxonomy_term, media, etc.)
```

**get_field_info** - Get comprehensive field information with usage analysis
```
Example: "What fields exist on the article content type?"
Example: "Where is field_image used?"
Example: "Do we have a field for storing phone numbers?"
Example: "Show me all email fields" (partial matching)
Shows: Field types, labels, cardinality, where used (bundles), settings, requirements
Combines: Field storage + field instance configs from database/files
Replaces: Multiple field:list + config:get commands
Use case: Understanding data structure before adding fields, avoiding duplicates
Supports: Partial field name matching, entity type filtering, bundle usage tracking
```

**get_taxonomy_info** - Get taxonomy vocabularies, terms, and usage analysis
```
Example: "What taxonomy vocabularies exist?"
Example: "Show me all terms in the categories vocabulary"
Example: "Where is the 'Drupal' term used?" → Automatically shows usage (single match)
Example: "Can I safely delete the 'Old News' term?" → Auto-analyzes safety
Example: "Search for terms named 'tech'" → Shows matches with term IDs
Shows: Vocabularies, term counts, hierarchies, usage in content/views/fields, safety analysis
Combines: Taxonomy configs + content queries + field references
Replaces: Multiple taxonomy commands + node queries + field reference checks
Use case: Before deleting/renaming terms, understanding taxonomy structure, finding orphans
Unique: Auto-detects single term match and shows full usage analysis in ONE call
Smart: Shows parent/child relationships, which content uses each term, safe-to-delete warnings
```

**get_watchdog_logs** - Get recent Drupal error and warning logs for debugging
```
Example: "Show me recent errors"
Example: "What warnings are in the logs?"
Example: "Are there any PHP errors?"
Example: "Show me database-related errors"
Shows: Error messages, warnings, timestamps, log types, severity levels
Filters: By severity (error, warning, notice, etc.) and type (php, cron, system, etc.)
Helps: Diagnose issues, fix code problems, understand system behavior
AI benefits: Can analyze errors and suggest fixes or next steps
Default: Shows last 50 error/warning entries
Use case: Debugging production issues, understanding why something broke
```

### Drupal.org Tools

**search_drupal_org** - Search for modules on drupal.org
```
Example: "Search drupal.org for SAML authentication"
```

**get_drupal_org_module_details** - Get comprehensive module information
```
Example: "Get details about samlauth from drupal.org"
Options: include_issues=True for deeper analysis
```

**get_popular_drupal_modules** - Get most popular modules by category
```
Example: "Show popular commerce modules"
```

**get_module_recommendation** - Get recommendations for specific needs
```
Example: "Recommend a module for user authentication with OAuth"
```

**search_module_issues** - Find solutions to specific problems in issue queues
```
Example: "Search samlauth issues for Azure AD authentication error"
Features: Automatic Drupal version filtering
```

## Usage Examples

### Finding Existing Functionality
```
User: "Do we have HTML email functionality?"
Result: Shows symfony_mailer module with email templating features
```

### Discovering New Modules
```
User: "Search drupal.org for SAML authentication"
Result: Lists samlauth, simplesamlphp_auth, and other options with stats
```

### Troubleshooting Issues
```
User: "I'm getting an AttributeConsumingService error with samlauth"
Result: Finds matching issues with solutions and patches
```

### Making Decisions
```
User: "Should I use samlauth or simplesamlphp_auth for Drupal 11?"
Result: Compares modules, shows migration patterns, provides recommendation
```

### Complete Workflow: Discovery to Installation
```
User: "I need SAML authentication for Azure AD"
MCP: search_drupal_org("SAML authentication")
MCP: get_drupal_org_module_details("samlauth", include_issues=True)
MCP: search_module_issues("samlauth", "Azure AD")
Result: MCP provides comprehensive module data, issues, and recommendations

User: "Install samlauth"
AI: Uses Bash to run: ddev composer require drupal/samlauth && ddev drush en samlauth
AI: Calls reindex_modules() to update MCP's index
Result: Module installed with AI executing commands based on your environment
```

### Cleanup Workflow (Enhanced with Drush)
```
User: "Clean up unused modules"
MCP: find_unused_contrib()
Result: "UNUSED CONTRIB MODULES:

         Found 5 modules not referenced by custom code

         3 INSTALLED but unused (can be uninstalled):
         - Devel (devel)
           Development tools
           Package: Development

         - Kint (kint)
           Debugging tool
           Package: Development

         - Admin Toolbar Tools (admin_toolbar_tools)
           Extra admin toolbar features
           Package: Administration

         2 NOT INSTALLED (can be removed from codebase):
         - Examples (examples)
           Code examples
           Package: Development

         - Devel Generate (devel_generate)
           Generate test content
           Package: Development

         RECOMMENDATIONS:
         - Uninstall 3 unused modules: drush pmu devel kint admin_toolbar_tools
         - Then remove from composer: composer remove drupal/MODULE_NAME
         - Remove 2 uninstalled modules from composer
         - This will reduce site complexity and improve performance"

User: "Uninstall the installed ones"
AI: Uses Bash to run: ddev drush pmu devel kint admin_toolbar_tools
AI: Then removes from composer: ddev composer remove drupal/devel drupal/kint drupal/admin_toolbar_tools
AI: Calls reindex_modules() to update MCP's index
Result: Safely removed 3 installed modules, avoiding any that are actually in use
        MCP's drush check prevented breaking the site
```

### Troubleshooting Workflow
```
User: "Getting errors with webform"
MCP: search_module_issues("webform", "error description")
Result: MCP finds relevant issues from drupal.org with solutions

AI: Uses Bash to check logs, run updates, clear caches as needed
Result: AI executes fixes based on MCP's data
```

### Dependency Analysis Workflow
```
User: "Can I safely uninstall the token module?"
MCP: analyze_module_dependencies("token")
Result: "CANNOT SAFELY UNINSTALL
         - 27 modules depend on token
         - Including: pathauto, metatag, my_custom_module
         - Must remove dependents first"

User: "What are my most critical modules?"
MCP: analyze_module_dependencies()  # System-wide analysis
Result: Shows modules with most dependents, circular dependencies,
        custom module coupling, and safe-to-remove candidates
```

### Taxonomy Management Workflow
```
User: "I want to clean up old taxonomy terms"
MCP: get_taxonomy_info()
Result: "Taxonomy Vocabularies (4 found)

         - Categories (categories)
           Description: Content categories
           Terms: 28
           Used by fields: field_category, field_article_category

         - Tags (tags)
           Terms: 156
           Used by fields: field_tags

         - Departments (departments)
           Terms: 12
           Used by fields: field_department"

User: "Show me all terms in the tags vocabulary"
MCP: get_taxonomy_info(vocabulary="tags")
Result: "Vocabulary: Tags (tags)
         Total terms: 156

         Terms:
         - Technology (tid: 42) (87 uses)
           - AI/ML (tid: 43) (12 uses)
           - Web Development (tid: 44) (23 uses)
         - Business (tid: 50) (45 uses)
         - Sports (tid: 60) (0 uses)
         - Old Category (tid: 75) (0 uses)"

User: "Can I safely delete 'Old Category'?"
MCP: get_taxonomy_info(term_id=75)
Result: "Term: Old Category (tid: 75)
         Vocabulary: Tags (tags)
         Description: Deprecated - do not use

         SAFE TO DELETE
         This term is not used in content, views, or as a parent term."

User: "What about the 'Technology' term?"
MCP: get_taxonomy_info(term_id=42)
Result: "Term: Technology (tid: 42)
         Vocabulary: Tags (tags)
         Children: AI/ML, Web Development

         Used in 87 content item(s):
         - How AI is Changing Development (article) - nid: 123
         - Tech Trends 2024 (blog) - nid: 156
         - Future of Web (article) - nid: 189
         ... and 84 more

         Vocabulary referenced by 2 field(s):
         - Tags (field_tags) on article, blog
         - Category (field_category) on article

         WARNING: Has child terms
         2 child term(s) will become orphaned if deleted.
         Consider reassigning children or deleting them first.

         CAUTION: Term is in use
         Used in 87 content item(s) and 0 view(s).
         Deleting will remove term references from content.
         Consider merging with another term instead."

User: "I'll keep Technology and just delete 'Old Category'"
AI: Uses Bash to run: ddev drush taxonomy:term:delete 75
Result: Term safely deleted with MCP's confirmation it was unused
        Avoided accidentally breaking 87 articles by checking first
```

### Field Analysis Workflow
```
User: "I need to add a phone number field to the staff content type"
MCP: get_field_info(field_name="phone")
Result: "Fields Summary (2 fields found) - Matching: phone
         NODE:
         - Phone Number (field_phone_number)
           Type: telephone | Bundles: contact, vendor
         - Mobile Phone (field_mobile_phone)
           Type: telephone | Bundles: employee"

User: "Show me details about field_phone_number"
MCP: get_field_info(field_name="field_phone_number")
Result: "Field: Phone Number (field_phone_number)
         Type: telephone
         Entity Type: node
         Storage: Single value
         Settings: Max length: 255

         Used in 2 bundle(s):
         - Contact (required)
         - Vendor"

User: "What fields does the article content type have?"
MCP: get_field_info(entity_type="node")
Result: "Fields Summary (15 fields found) - Entity type: node
         NODE:
         - Title (title)
           Type: string | Bundles: article, page, blog
         - Body (body)
           Type: text_with_summary | Bundles: article, blog
         - Image (field_image)
           Type: image | Bundles: article, blog, school
         - Category (field_category)
           Type: entity_reference | Bundles: article, blog
         ..."

User: "Perfect! I can reuse field_phone_number on the staff content type"
Result: Discovered existing field with same purpose in a single query
        Avoided creating duplicate field with different name
        Showed exactly where fields are used for informed decisions
```

### Debugging Workflow (with Watchdog Logs)
```
User: "The site is showing errors, can you check what's wrong?"
MCP: get_watchdog_logs()
Result: "DRUPAL WATCHDOG LOGS (most recent 15 entries)

         ERROR (12 entries)
         ================================================================================

         [2024-01-15 14:32:21] php
         Message: Undefined array key 'field_category' in custom_module_preprocess_node()
         Location: /modules/custom/custom_module/custom_module.module:line 45
         --------------------------------------------------------------------------------

         [2024-01-15 14:30:15] php
         Message: Call to undefined method Drupal\node\Entity\Node::getCategory()
         Location: /modules/custom/custom_module/src/Service/CategoryService.php:line 78
         --------------------------------------------------------------------------------

         WARNING (3 entries)
         ================================================================================

         [2024-01-15 14:25:10] cron
         Message: Cron run exceeded the time limit and was aborted
         --------------------------------------------------------------------------------

         NEXT STEPS:
         1. Review the error messages above to identify issues
         2. For PHP errors: Check the file and line number mentioned
         3. For missing modules/dependencies: Use drush pm:list to verify
         4. For database errors: Check database connectivity and permissions
         5. Use get_watchdog_logs(type='php') to focus on PHP errors"

AI: "I can see two related PHP errors in your custom_module. The issue is:

     1. Line 45 in custom_module.module is trying to access 'field_category' which doesn't exist
     2. Line 78 in CategoryService.php is calling a method that doesn't exist on Node entities

     Let me check the module code to fix these issues."

AI: Uses Read tool to examine /modules/custom/custom_module/custom_module.module
AI: Uses Read tool to examine /modules/custom/custom_module/src/Service/CategoryService.php
AI: Identifies the bugs and proposes fixes
AI: Uses Edit tool to fix both issues
AI: "I've fixed both errors. The problems were:
     1. Missing field existence check before accessing field_category
     2. Using non-existent getCategory() instead of get('field_category')

     Run 'drush cache:rebuild' to clear the cache and test."

User: "Thanks! Any other issues I should know about?"
MCP: get_watchdog_logs(severity="warning")
Result: Shows the cron timeout warning

AI: "There's also a cron timeout issue. This usually means a cron task is taking too long.
     You might want to review your cron hooks or increase the time limit."
```

### Views Discovery Workflow
```
User: "Do we have any views that display user data?"
MCP: get_views_summary(entity_type="users")
Result: "Views Summary (2 views found) - Showing 'users' views only
         User List (user_list)
            Displays: master, page_1
            Base: users_field_data
         Staff Directory (staff_directory)
            Displays: master, page_1, block_1
            Base: users_field_data"

User: "What about school content?"
MCP: get_views_summary(entity_type="node")  # Schools are a content type
Result: "Views Summary (5 views found) - Showing 'node' views only
         Content (content)
            Displays: master, page_1, block_1
            Base: node
         Schools Directory (schools_directory)
            Displays: master, page_1
            Base: node_field_data
         Blog Posts (blog)
            Displays: master, page_1
            Base: node_field_data"

User: "Show me details about the schools_directory view"
MCP: get_views_summary("schools_directory")
Result: "View: Schools Directory (schools_directory)
         Status: Enabled
         Base Table: node_field_data

         Displays (2):
         - Master [master]
           Filters: status, type
           Fields: title, field_address, field_principal...

         - Page [page]
           Path: /schools
           Filters: status, type, field_district"

User: "Perfect! The schools view already exists with the filters I need"
Result: Found existing view with needed filters in a single query
        Entity type filtering prevented showing irrelevant views
        Helped avoid creating duplicate functionality
```

## How It Works

### Division of Labor

**MCP Server (Data Provider) - What Drupal Scout Does:**
- Indexes your local Drupal codebase
- Executes Drush commands to query live database configuration
- Provides fast searching across modules
- Fetches data from drupal.org (modules, issues, stats)
- Caches drupal.org responses (1 hour TTL)
- Analyzes dependencies and redundancies
- Recommends modules based on your needs

**AI Assistant (Action Executor) - What Your AI Does:**
- Executes drush/composer/git commands for modifications
- Detects your environment (DDEV, Lando, Docker, etc.)
- Runs commands appropriate for your setup
- Chains operations efficiently
- Handles errors and edge cases
- Calls reindex_modules() after changes

### Technical Details

**Drush Integration**
- Auto-detects drush command (DDEV, Lando, Docksal, global, etc.)
- Executes read-only drush commands for live data
- Queries active configuration from database
- Checks module installation status
- Retrieves entity structures, views, fields, and taxonomy data
- Combines static file analysis with runtime data for complete picture

**Local Indexing**
- Parses .info.yml, .services.yml, .routing.yml, and PHP files
- Indexes services, routes, dependencies, and keywords
- Builds searchable database of functionality
- Call reindex_modules() after installing/removing modules

**Drupal.org Integration**
- Uses drupal.org REST API for module data
- Scrapes project pages for accurate compatibility
- Fetches issue queues for troubleshooting
- Automatic Drupal version filtering

**Why This Architecture?**
- MCP focuses on Drupal domain knowledge and read-only analysis
- MCP executes drush queries internally for efficiency
- AI handles environment-specific execution for modifications
- Simpler, more maintainable code
- Works with any dev environment (DDEV, Lando, etc.)
- AI can adapt to errors better than hardcoded commands

## Requirements

- Python 3.10 or higher
- Drupal 9, 10, or 11 installation
- MCP-compatible client (Claude Desktop, Cursor, etc.)
- Internet connection (for drupal.org features)

## Configuration

### Basic Configuration
```json
{
  "drupal_root": "/var/www/drupal",
  "modules_path": "modules"
}
```

### Advanced Options
```json
{
  "drupal_root": "/var/www/drupal",
  "modules_path": "modules",
  "exclude_patterns": ["node_modules", "vendor"],
  "drush_command": "drush"
}
```

### Drush Configuration

Some tools require drush (e.g., `get_entity_structure`). The MCP auto-detects drush in common environments:

**Auto-detected environments:**
- DDEV: `ddev drush`
- Lando: `lando drush`
- Docksal: `fin drush`
- Composer: `vendor/bin/drush`
- Global: `drush`

**Manual override (if auto-detection fails):**
```json
{
  "drush_command": "ddev drush"
}
```

**Examples:**
- DDEV: `"drush_command": "ddev drush"`
- Lando: `"drush_command": "lando drush"`
- Custom Docker: `"drush_command": "docker-compose exec php drush"`
- SSH remote: `"drush_command": "ssh user@host drush"`

## Performance

**Token Efficiency**

Drupal Scout's primary value is reducing token consumption in AI conversations by replacing multiple commands with single MCP calls:

| Without Drupal Scout | With Drupal Scout |
|---------------------|-------------------|
| Multiple field:list + config:get commands | get_field_info() (single call) |
| views:list + multiple greps | get_views_summary() (single call) |
| Multiple taxonomy + node queries | get_taxonomy_info() (single call) |
| Multiple config:get calls | get_entity_structure() (single call) |

**Benefits:**
- Faster AI responses (less back-and-forth)
- Lower token usage and API costs
- More room for complex conversations
- Better context retention
- Pre-analyzed, cross-referenced data

**Speed**

**Local Search**
- Initial indexing: 2-5 seconds (typical site)
- Search queries: < 100ms
- Re-indexing: Only when needed

**Drupal.org API**
- Module search: ~500ms
- Module details: ~700ms (basic) or ~1000ms (with issues)
- Issue search: ~1 second
- All results cached for 1 hour

## Troubleshooting

### Module not found
- Check drupal_root path in config.json
- Run "Reindex modules"
- Verify module is enabled

### Drupal.org search empty
- Check internet connection
- Try broader search terms
- Module might not exist on drupal.org

### No issue results
- Issue might be very old (searches recent 100)
- Try broader keywords
- Check module name spelling

## Development

### Running Tests
```bash
python3 -m pytest tests/
```

### Code Structure
```
src/
  indexer.py      - Module indexing logic
  search.py       - Local search functionality
  drupal_org.py   - Drupal.org API integration
  parsers/        - File parsers (.yml, .php)
  prioritizer.py  - Result formatting
server.py         - MCP server entry point
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- Issues: https://github.com/davo20019/drupal-scout-mcp/issues
- Discussions: https://github.com/davo20019/drupal-scout-mcp/discussions

## Changelog

See individual commits for detailed changes.

## Related Projects

- Model Context Protocol: https://modelcontextprotocol.io
- Drupal: https://www.drupal.org
- FastMCP: https://github.com/jlowin/fastmcp
