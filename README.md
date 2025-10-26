# Drupal Scout MCP

A Model Context Protocol server for local Drupal development. Combines local file indexing with drush-powered database queries to give AI assistants knowledge of your site's structure, content, and the drupal.org ecosystem.

**Designed for local development environments** (DDEV, Lando, Docker, etc.)

**Why use Drupal Scout?**
- **Reduces AI back-and-forth**: One MCP call instead of multiple drush + grep commands
- **Bypasses token limits**: Export thousands of nodes/users/terms to CSV files
- **Combines multiple data sources**: File analysis + database queries + drupal.org API in single responses
- **Safe decision-making**: Shows dependencies and usage before changes

**What it does:**
- **Local indexing**: Searches your codebase for modules, services, routes, hooks
- **Database queries**: Runs drush php:eval to fetch entities, fields, views, taxonomy, logs
- **Security analysis**: Pattern-based scanning for XSS, SQL injection, access control issues
- **CSV exports**: Writes large datasets (nodes, users, taxonomy) directly to files
- **Drupal.org search**: Finds modules, issues, and compatibility info
- **Read-only**: Only queries data, never modifies your site

**What it doesn't do:**
- Modify files or database (AI executes drush/composer commands for changes)
- Real-time updates (call reindex_modules after installing/removing modules)

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

**get_all_taxonomy_usage** - Batch analysis of ALL terms in a vocabulary
```
Example: "Analyze all terms in the tags vocabulary for cleanup"
Example: "Show me usage statistics for all category terms"
Shows: Complete usage analysis for every term in a vocabulary (optimized single query)
Performance: 96% token savings vs calling get_taxonomy_info() per term
Default limit: 100 terms (configurable with limit parameter)
Smart truncation: Warns when vocabulary has more terms than returned
Modes: summary_only=True (fast, counts only) or False (detailed with samples)
Use case: Bulk cleanup planning, vocabulary auditing, finding unused terms
Replaces: Hundreds of individual term queries with one efficient batch operation
```

**export_taxonomy_usage_to_csv** - Export taxonomy analysis directly to CSV file
```
Example: "Export all tags to CSV with full details"
Example: "Export categories vocabulary to CSV for cleanup planning"
Bypasses: MCP token limits entirely by writing directly to filesystem
Speed: Much faster than AI-formatted output for large vocabularies
Output: Saves to Drupal root directory as taxonomy_export_{vocab}_{timestamp}.csv
Modes:
  - summary_only=True: tid, name, count, needs_check (4 columns, fast)
  - summary_only=False: 12 columns including content samples, code refs, safety analysis
Handles: Unlimited terms (no 100-term limit like get_all_taxonomy_usage)
Use case: Exporting 500+ terms, spreadsheet analysis, team reporting
Perfect for: Large vocabularies where token limits prevent full display
```

**export_nodes_to_csv** - Export content/nodes directly to CSV for audits and migrations
```
Example: "Export all articles to CSV with full details"
Example: "Export all content for migration planning"
Example: "Export blog posts with field data for migration"
Example: "Export articles including body text and custom fields"
Bypasses: MCP token limits by writing directly to filesystem
Perfect for: Content audits, SEO analysis, migration planning, bulk reviews
Output: Saves to Drupal root directory as nodes_export_{type}_{timestamp}.csv
Filters: content_type (article, page, etc.), include_unpublished, limit
Modes:
  - summary_only=True: nid, title, type, status, created, author (7 columns, fast)
  - summary_only=False: 21+ columns including:
    * Basic: nid, uuid, title, type, status, langcode, timestamps, author
    * URLs/SEO: url_alias, canonical_url, redirects, metatags (title/desc/keywords)
    * Relationships: taxonomy_terms, entity_references (nodes/media/users)
    * Publishing: promote, sticky, front_page flags
    * Revisions: revision_count, latest_revision_log
  - include_field_data=True: Adds actual field content (use with summary_only=False)
    **WHY USE THIS:**
    - Migration planning: Map old field values to new structure
    - Content quality audit: Find empty fields, missing alt text
    - Data cleanup: Identify fields that need updating
    - SEO review: Check body text length, image descriptions
    - Translation prep: Export content for translation services
    **WHAT YOU GET:**
    * body: First 500 characters of body text (HTML stripped)
    * body_format: Text format (full_html, basic_html, etc.)
    * Images: Alt text + image count (field_image: "Logo image | 3 images total")
    * Text/Link fields: Full values (perfect for link audits)
    * Custom fields: Auto-detected and included (field_subtitle, field_author_bio, etc.)
    * Performance: Adds 30-50% to export time but essential for migrations
Performance: 100 nodes ~10s, 1000 nodes ~60s, 5000 nodes ~5min
Use case: Migration planning, SEO audits, content inventory, finding broken refs
Smart detection: Auto-detects redirect and metatag modules for enhanced data
AI knows: Automatically sets include_field_data=True when user asks for "body text", "field data", "complete export", or "migration data"
```

**export_users_to_csv** - Export user accounts directly to CSV for audits and migrations
```
Example: "Export all users to CSV"
Example: "Export users with full profile data for migration"
Example: "Export all users including blocked accounts"
Bypasses: MCP token limits by writing directly to filesystem
Perfect for: User audits, compliance reporting (GDPR), migration planning, inactive account cleanup
Output: Saves to Drupal root directory as users_export_{timestamp}.csv
Filters: include_blocked (default: False), limit
Modes:
  - summary_only=True: uid, name, email, status, roles, created, access (7 columns, fast)
  - summary_only=False: 15+ columns including:
    * Basic: uid, uuid, name, email, status, langcode
    * Activity: created, changed, access (last login), login (last access)
    * Authorization: roles (pipe-separated list, e.g., "administrator | editor")
    * Profile: timezone, preferred_langcode, init (original email), picture
  - include_field_data=True: Adds custom user profile fields (use with summary_only=False)
    **WHY USE THIS:**
    - Migration planning: Map profile fields to new system
    - User data export: GDPR compliance, data portability
    - Profile analysis: Find incomplete profiles, missing fields
    - Custom field audit: See what profile data exists
    **WHAT YOU GET:**
    * All custom user fields auto-detected and included
    * Profile pictures/avatars (file paths)
    * Text fields, links, entity references
    * Boolean fields (YES/NO format)
    * Performance: Adds 20-30% to export time
Performance: 100 users ~5s, 1000 users ~30s, 5000 users ~2min
Use case: User migration, GDPR exports, security audits, cleanup planning
Smart detection: Automatically sets include_field_data=True when user asks for "profile data", "user fields", or "complete export"
Activity tracking: Shows last login, last access, account age for inactive user identification
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

### Security Analysis Tools

**security_audit** - Comprehensive security scan with multiple modes
```
Example: "Run security audit on my_custom_module"
Example: "Security audit on webform module, show HIGH issues only"
Example: "Audit the commerce module in summary mode"

Scans for:
- XSS vulnerabilities (unescaped output, unsafe render arrays)
- SQL injection (db_query concatenation, unsafe queries)
- Access control issues (missing permission checks)
- CSRF protection (custom POST handlers, state-changing operations)
- Command injection (exec, shell_exec, system with variables)
- Path traversal (file operations with user input, ../ patterns)
- Hardcoded secrets (API keys, passwords, credentials)
- Deprecated/unsafe API usage (eval, extract, Drupal 7 functions)

Modes:
- summary (default): Fast overview with counts, perfect for large modules
- high_only: Shows only HIGH severity findings with details
- findings: Detailed report with code snippets (respects max_findings limit)

Parameters:
- mode: "summary", "high_only", or "findings" (default: "summary")
- severity_filter: Filter by "high", "medium", or "low"
- max_findings: Limit results (default: 50, prevents token overflow)

Smart token management: Automatically handles large modules without hitting limits
Pattern-based: All findings are concrete code patterns, no AI guessing
```

**scan_anonymous_exploits** - 🎯 CRITICAL: Identify remotely exploitable vulnerabilities
```
Example: "Scan my_api_module for anonymous exploits"
Example: "Check chatbot for vulnerabilities accessible to anonymous users"
Example: "What vulnerabilities in custom_api can be exploited remotely?"

This is the HIGHEST PRIORITY security scan - identifies vulnerabilities that can
be exploited remotely without authentication.

How it works:
1. Runs security scans (XSS, SQL injection, command injection, path traversal)
2. Parses routing.yml files to identify anonymous-accessible routes
3. Maps HIGH severity vulnerabilities to routes
4. Reports ONLY vulnerabilities in anonymous routes

Reports:
- Routes accessible to anonymous users
- Vulnerabilities that can be exploited remotely
- Prioritized by exploitability (anonymous = critical)

Why this matters:
- Anonymous exploits = Remote exploitation without credentials
- Highest priority for security fixes
- Critical for public-facing modules (APIs, chatbots, forms)

Parameters: max_findings (default: 50)

Use cases:
- Pre-deployment security validation
- API security assessment
- Public module vulnerability analysis
- Penetration testing preparation

Combines: Pattern-based vulnerability detection + Routing access analysis
Output: Prioritized list of remotely exploitable security issues
```

**scan_xss** - Detect Cross-Site Scripting vulnerabilities
```
Example: "Scan my_module for XSS issues"
Example: "Check custom_auth module for XSS, limit to 20 findings"

Detects:
- Unescaped print/echo statements
- Unsafe render arrays
- Direct superglobal output ($_GET, $_POST, etc.)
- JavaScript innerHTML usage
- drupal_set_message with variables

Parameters: max_findings (default: 50)
```

**scan_sql_injection** - Detect SQL injection vulnerabilities
```
Example: "Scan my_module for SQL injection"

Detects:
- db_query with string concatenation
- SQL queries with concatenation
- mysqli/PDO without prepared statements
- EntityQuery with unsanitized user input

Parameters: max_findings (default: 50)
```

**scan_access_control** - Find missing access control checks
```
Example: "Check my_module for access control issues"

Detects:
- Routes without _permission requirements
- Forms without access checks
- Entity modifications without access verification
- User data access without permission checks

Parameters: max_findings (default: 50)
```

**scan_deprecated_api** - Identify deprecated or unsafe API usage
```
Example: "Scan my_module for deprecated APIs"

Detects:
- Drupal 7 functions in D8+ code (drupal_set_message, variable_get, etc.)
- eval() usage
- unserialize() with user input
- Deprecated PHP functions (create_function, extract, assert)

Parameters: max_findings (default: 50)
Use case: Preparing modules for Drupal upgrades, security hardening
```

**scan_csrf** - Check CSRF (Cross-Site Request Forgery) protection
```
Example: "Check my_module for CSRF protection"
Example: "Scan custom_api module for CSRF issues"

Detects:
- Custom POST handlers outside Form API (may need CSRF token)
- State-changing operations (save/delete/update)
- Potential GET routes with state changes (CSRF risk)

How it works:
- Scans PHP code for custom request handling
- Guides AI to verify routing files (*.routing.yml)
- Checks for Form API usage (auto CSRF protection)

Note: Advisory scan - AI should investigate routing files to confirm CSRF handling
Drupal Form API provides automatic CSRF protection

Parameters: max_findings (default: 50)
Use case: Custom route handlers, REST APIs, AJAX endpoints
```

**scan_command_injection** - Detect command injection vulnerabilities
```
Example: "Scan my_module for command injection"
Example: "Check system_integration for shell command issues"

Detects:
- exec(), shell_exec(), system(), passthru() with variables
- Backtick shell execution operator with variables
- Drush shell commands with user input
- PHP mail() with user input (header injection)

Parameters: max_findings (default: 50)
Use case: Modules that execute shell commands, system integration modules
```

**scan_path_traversal** - Detect path traversal vulnerabilities
```
Example: "Scan my_module for path traversal issues"
Example: "Check file_manager for path traversal vulnerabilities"

Detects:
- File includes with user input (include, require)
- File read operations with unsanitized input
- Directory traversal patterns (../ sequences)
- Drupal file operations without validation
- File deletion with user input

Understands Drupal stream wrappers (public://, private://)

Parameters: max_findings (default: 50)
Use case: File management modules, import/export functionality
```

**scan_hardcoded_secrets** - Find hardcoded credentials and secrets
```
Example: "Scan my_module for hardcoded secrets"
Example: "Check api_integration for hardcoded API keys"

Detects:
- API keys hardcoded in code
- Passwords in variables
- Database credentials
- Private/secret keys
- OAuth tokens
- AWS credentials

Excludes: Test files, examples, placeholders, comments

Parameters: max_findings (default: 50)
Use case: Pre-deployment security checks, code review, API integrations

Best practices:
- Use Drupal Key module for secret management
- Store secrets in settings.php (excluded from version control)
- Use environment variables
```

**verify_vulnerability** - 🎓 Explain how to manually verify security vulnerabilities
```
Example: "How do I verify the XSS vulnerability found in MyController.php?"
Example: "Show me how to test the SQL injection in my_custom_module"
Example: "Explain how to verify this command injection vulnerability"

INFORMATIONAL TOOL - Does NOT automatically execute exploits.
Provides detailed educational content on how vulnerabilities work and how
developers can manually test them on their OWN sites.

Provides:
- Code context showing the vulnerable line
- Explanation of why the code is vulnerable
- Attack flow diagrams
- Step-by-step manual testing instructions
- Expected results for vulnerable vs. fixed code
- Specific remediation guidance
- Before/after verification workflow

Input (from scan results):
- Module name, file path, line number
- Vulnerability type (xss, sql_injection, etc.)
- Optional route path

Output:
- Detailed explanation of the vulnerability
- Safe, manual testing commands (NOT executed automatically)
- Browser console testing steps
- DDEV/Lando curl examples
- Remediation code with examples
- Legal and ethical warnings

Use cases:
- Understand how a vulnerability works (educational)
- Manually verify scan findings before filing bugs
- Learn manual penetration testing techniques
- Verify patch effectiveness after remediation
- Security training for development teams

Example workflow:
1. scan_xss("my_module") → Finds XSS at MyController.php:45
2. verify_vulnerability("my_module", "xss", "MyController.php", 45, "/api/endpoint")
3. Read the detailed explanation and testing instructions
4. Manually run the commands in your local DDEV environment
5. Apply the recommended fix
6. Re-run the manual tests to confirm the fix works
7. Run scan_xss("my_module") again to verify

⚠️  For AUTHORIZED testing of YOUR OWN sites only
⚠️  Includes legal warnings about unauthorized testing
⚠️  Educational purpose - teaches secure coding practices
```

**Security Scanning Limitations & Best Practices**

Scout's pattern-based security analysis is excellent for:
- ✅ Quick security screening and first-pass vulnerability detection
- ✅ Finding obvious issues (direct echo/print, SQL concatenation)
- ✅ Eliminating false positives with Drupal-aware filtering
- ✅ Identifying deprecated/unsafe API usage

Pattern-based analysis may miss:
- Multi-line code patterns and complex data flow
- Variables passed through functions or indirect calls
- Conditional logic spanning multiple functions
- Custom security wrappers

**For comprehensive security audits:**
1. Use Scout for initial screening (fast, catches obvious issues)
2. Review all HIGH severity findings with manual code inspection
3. Use additional static analysis tools:
   - PHPStan (static analysis)
   - Psalm (type checking & security)
   - Semgrep (custom security rules)
4. Manual penetration testing for runtime validation
5. Professional security audit for production/compliance requirements

Scout should NOT be the sole tool for:
- Production security certification
- Compliance audits (PCI-DSS, SOC 2, HIPAA)
- Complete vulnerability coverage

**All findings include**: file location, line number, code snippet, severity level (HIGH/MEDIUM/LOW), and specific remediation recommendations with Drupal documentation links.

**Enhanced Accuracy with AST Analysis**

Scout uses tree-sitter-php for AST-based security analysis (installed automatically with `pip install drupal-scout-mcp`):
- Reduces false positives by understanding PHP syntax structure
- Catches multi-line code patterns (e.g., SQL concatenation across lines)
- Provides Drupal-aware validation (distinguishes EntityQuery from SQL queries)
- Verifies actual code structure vs simple pattern matching
- Graceful fallback to pattern-based analysis if tree-sitter unavailable

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

### Content Audit and SEO Analysis Workflow (Node CSV Export)
```
User: "I need to do a content audit for our migration to the new site"
AI: "I'll export all your content to CSV with full details for analysis."
MCP: export_nodes_to_csv(summary_only=False, include_unpublished=True)
Result: "✅ Successfully exported 3,247 nodes to /path/to/drupal/nodes_export_all_20251025_153000.csv (2.1 MB)

         Content types found: article (1,523), page (892), blog (654), event (178)

         Columns included (21 total):
         - Basic: nid, uuid, title, type, status, langcode, created, changed, author
         - URLs/SEO: url_alias, canonical_url, redirects, metatag_title, metatag_description
         - Relationships: taxonomy_terms, entity_references
         - Publishing: promote, sticky, front_page
         - Revisions: revision_count, latest_revision_log

         Preview:
         nid,uuid,title,type,status,langcode,created,changed,author,url_alias,canonical_url,redirects,taxonomy_terms,metatag_title...
         1,abc-123,Home,page,published,en,2023-01-15 10:30:00,2024-10-20 14:22:00,admin,/home,https://example.com/home,,Category: News | Tags: Drupal,Welcome to Our Site...
         2,def-456,About Us,page,published,en,2023-01-16 09:15:00,2024-09-12 11:05:00,editor,/about,https://example.com/about,/about-us | /company,,About Our Company..."

AI: "Perfect! I've exported all 3,247 nodes. The CSV includes:
     - SEO data: All URL aliases, redirects, and metatags
     - Taxonomy relationships for each node
     - Entity references (media, related content)
     - Revision history
     - Publishing status and flags

     You can now open this in Excel/Google Sheets to:
     - Audit SEO metatags (sort by empty metatag_title)
     - Find broken redirects
     - Map content for migration
     - Identify content without taxonomy terms
     - Review publishing workflow

     Would you like me to analyze specific patterns?"

User: "Show me articles without metatag descriptions"
AI: [Reads CSV file and filters]
    "Found 234 articles missing metatag descriptions:
     - Article nid:45 'How to Use Drupal' (published 2023-03-12)
     - Article nid:67 'PHP Best Practices' (published 2023-04-08)
     ... [continues listing]

     These should be updated before migration for better SEO."

User: "What about redirect analysis?"
AI: [Analyzes redirects column]
    "Redirect analysis from CSV:
     - 456 nodes have redirects (good for SEO continuity)
     - 128 nodes have multiple redirects (shows URL history)
     - Top 10 nodes by redirect count:
       * nid:123 'Company History' - 8 redirects
       * nid:456 'Product Launch' - 6 redirects

     All redirect data is preserved in the CSV for migration planning."
```

### Migration Planning with Field Data Export
```
User: "I need to export all blog posts with their field content for our migration to the new CMS"
AI: "I'll export all blog posts including field data (body text, images, custom fields)."
MCP: export_nodes_to_csv(content_type="blog", summary_only=False, include_field_data=True, include_unpublished=True)
Result: "✅ Successfully exported 654 blog nodes to /path/to/drupal/nodes_export_blog_20251025_160000.csv (892 KB)

         Columns included (32 total):
         - Basic: nid, uuid, title, type, status, author...
         - URLs/SEO: url_alias, canonical_url, metatags...
         - Field Data:
           * body (first 500 chars)
           * body_format
           * field_featured_image (alt text + count)
           * field_author_bio
           * field_publish_date
           * field_related_links
           * field_tags (auto-detected custom field)
           * field_subtitle (auto-detected)

         Preview:
         nid,title,body,body_format,field_featured_image,field_author_bio,field_subtitle...
         123,How to Migrate,"This comprehensive guide covers...(500 chars),full_html,"Migration guide banner | 3 images",John Doe is a...,The Ultimate Guide..."

AI: "Perfect! I've exported all 654 blog posts with complete field data. The CSV includes:

     **Content Data:**
     - Body text (first 500 chars) - ready for content analysis
     - Body format - shows which posts use full_html vs basic_html
     - Image alt text - identify missing accessibility data
     - Custom fields - all detected and exported

     **What you can do now:**
     1. Content Quality Audit:
        - Sort by empty 'body' to find placeholder content
        - Find posts missing field_featured_image
        - Check for missing alt text descriptions

     2. Migration Mapping:
        - Map field_subtitle → new_cms_field_intro
        - Map field_author_bio → author.biography
        - Identify which body_format to convert

     3. Translation Preparation:
        - Export body text for translation services
        - See which fields need localization

     4. SEO/Content Review:
        - Check body text length (too short?)
        - Find posts without field_subtitle
        - Identify missing metadata"

User: "Show me posts with short body text that need more content"
AI: [Analyzes CSV body column]
    "Found 47 blog posts with body text under 100 characters:
     - nid:234 'Quick Update' - 45 chars ('Just a quick note about...')
     - nid:567 'Announcement' - 78 chars ('We're excited to share that...')

     These posts might be placeholders or need expansion before migration."

User: "What about missing image alt text?"
AI: [Checks field_featured_image column]
    "Image analysis:
     - 589 posts have featured images
     - 123 posts missing alt text (empty field_featured_image)
     - Posts to fix:
       * nid:89 'Product Launch' - 2 images, no alt text
       * nid:145 'Case Study' - 1 image, no alt text

     You should add alt text to these before migration for accessibility."
```

### Large Vocabulary Cleanup Workflow (CSV Export)
```
User: "I need to clean up our tags vocabulary - we have hundreds of old terms"
MCP: get_all_taxonomy_usage(vocabulary="tags", summary_only=True)
Result: "⚠️  TRUNCATED RESULTS: Showing 100 of 751 terms.
         Options: (1) Increase limit, (2) Use CSV export, (3) Continue with 100"

User: "Export all 751 terms to CSV with full details"
MCP: export_taxonomy_usage_to_csv(vocabulary="tags", summary_only=False)
Result: "✅ Successfully exported 751 terms to /path/to/drupal/taxonomy_export_tags_20251025_143500.csv (125 KB)

         Columns included:
         - tid, name, description, parent, children
         - content_count, content_usage_sample (first 5 nodes)
         - fields_with_usage, code_usage, config_usage
         - safe_to_delete, warnings

         Preview:
         tid,name,description,parent,children,content_count,content_usage_sample,...
         1,Technology,,,,87,nid:123 (AI Article) | nid:156 (Tech Blog)...
         2,Old News,Deprecated,,,0,,...,YES,
         3,Music,,,,23,nid:45 (Concert Review) | nid:67 (Album Review)...
         ..."

AI: "I've exported all 751 terms to a CSV file in your Drupal root. The file includes:
     - Full usage analysis for every term
     - Sample content using each term
     - Safety recommendations
     - 234 terms marked as safe to delete (0 content usage)

     You can open it in Excel/Google Sheets to filter and plan your cleanup."

User: "Great! Show me just the safe-to-delete terms"
AI: "Based on the CSV, here are the 234 terms safe to delete (0 content usage):
     - Old News (tid: 2)
     - Deprecated Category (tid: 15)
     - Test Tag (tid: 47)
     ... [reads from CSV file]

     Would you like me to generate a drush command to delete all of them?"

User: "Yes, delete all unused terms"
AI: Uses Bash to run: ddev drush taxonomy:term:delete 2,15,47,... [all safe term IDs]
Result: Cleaned up 234 unused terms in one operation
        CSV export enabled analysis of 751 terms without hitting token limits
        Much faster than AI formatting - took 30 seconds vs several minutes
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

### User Audit and Migration Workflow (User CSV Export)
```
User: "I need to audit our user accounts and prepare for migration to the new authentication system"
AI: "I'll export all your user accounts with full details for analysis."
MCP: export_users_to_csv(summary_only=False, include_blocked=True)
Result: "✅ Successfully exported 523 users to /path/to/drupal/users_export_20251025_143000.csv (85 KB)

         Roles found: administrator (3), editor (12), content_creator (45), authenticated (463)

         Columns included (15 total):
         - Basic: uid, uuid, name, email, status, langcode
         - Activity: created, changed, access (last login), login (last access)
         - Authorization: roles
         - Profile: timezone, preferred_langcode, init, picture

         Preview:
         uid,uuid,name,email,status,langcode,created,changed,access,login,roles,timezone,preferred_langcode,init,picture
         1,abc-123,admin,admin@example.com,active,en,2020-01-15 10:30:00,2024-10-25 09:15:00,2024-10-25 14:30:00,2024-10-25 09:15:00,administrator,America/New_York,en,admin@example.com,public://pictures/picture-1.jpg
         2,def-456,editor1,editor@example.com,active,en,2021-03-20 14:22:00,2024-10-20 11:05:00,2024-10-24 16:45:00,2024-10-20 11:05:00,editor,America/Los_Angeles,en,editor@example.com,"

AI: "Perfect! I've exported all 523 user accounts including blocked users. The CSV includes:
     - User activity data: Last login, last access times
     - Authorization: All role assignments
     - Account status: Active vs blocked
     - Original registration info: Creation date, initial email
     - Profile settings: Timezone, language preferences

     You can now open this in Excel/Google Sheets to:
     - Identify inactive users (sort by 'access' column)
     - Audit role assignments (filter by 'roles' column)
     - Find accounts to cleanup (blocked status, never logged in)
     - Plan migration mapping (email → new auth system)
     - GDPR compliance (export user data on request)

     Would you like me to analyze specific patterns?"

User: "Show me users who haven't logged in for over a year"
AI: [Reads CSV file and filters by access date]
    "Found 87 users who haven't logged in since October 2023:

     INACTIVE ADMINISTRATORS (2):
     - uid:45 'old_admin' - Last login: 2022-08-15 (2+ years ago)
     - uid:67 'backup_admin' - Last login: 2023-03-20 (1.5 years ago)

     INACTIVE EDITORS (12):
     - uid:89 'john.smith' - Last login: 2023-05-10
     - uid:134 'jane.doe' - Last login: 2023-02-28
     ... [continues listing]

     INACTIVE REGULAR USERS (73):
     - Many accounts created but never logged in (access: Never)

     RECOMMENDATIONS:
     - Review administrator accounts - should backup_admin still have admin rights?
     - Consider blocking or deleting accounts with 'Never' login status
     - Send re-activation emails to editors before blocking"

User: "What about blocked accounts?"
AI: [Filters CSV by status column]
    "Blocked accounts analysis:
     - 23 blocked user accounts total
     - 15 were spam accounts (registered but never verified)
     - 5 were former employees (blocked after leaving)
     - 3 were security-related blocks

     Safe to delete: The 15 spam accounts (uids: 234, 267, 289...)"

User: "Export users with their profile fields for the migration"
AI: "I'll export with full profile data for migration planning."
MCP: export_users_to_csv(summary_only=False, include_field_data=True, include_blocked=True)
Result: "✅ Successfully exported 523 users with profile fields (142 KB)

         Additional custom fields detected and included:
         - field_department (entity reference to taxonomy)
         - field_bio (text field)
         - field_phone_number (telephone)
         - field_office_location (text)

         You can now map these fields to your new authentication system."

AI: "Perfect! The export now includes all custom profile fields. You can use this to:
     1. Map field_department → new_system.department
     2. Map field_bio → new_system.profile.about_me
     3. Map field_phone_number → new_system.contact.phone
     4. Identify which users have incomplete profiles (empty fields)"
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

## Security Considerations

Drupal Scout is designed as a **development tool for trusted local environments**. Please review these security considerations:

### Trusted Drupal Installations Only

**Drush PHP Execution:**
- Drupal Scout executes PHP code via `drush eval` to query the database
- This has the same permissions as your Drupal database user
- Can read any data accessible to your Drupal installation

**Recommendation:**
- ✅ Use with Drupal sites you control and trust
- ✅ Perfect for local development environments (DDEV, Lando, Docker)
- ❌ Not intended for untrusted or compromised Drupal installations

### Configuration Security

**Config File Location:**
- Config stored at `~/.config/drupal-scout/config.json`
- May contain sensitive paths and settings
- File permissions should restrict to your user account

**Recommendations:**
- ✅ Keep config.json in your home directory (default location)
- ❌ Do not commit config.json to version control
- ✅ Add `config.json` to `.gitignore` if creating project-specific configs
- ✅ Use environment-specific paths (don't share configs between developers)

### Export File Security

**CSV Export Paths:**
- Export tools write CSV files to the filesystem
- Paths are validated to prevent writing to system directories
- Allowed locations:
  - Drupal root and subdirectories
  - `/tmp` and `/var/tmp`
  - User's home directory

**What This Prevents:**
- ❌ Writing to `/etc/` or other system directories
- ❌ Path traversal attacks (`../../../etc/passwd`)
- ❌ Accidental overwrites of critical system files

**Recommendations:**
- ✅ Use default paths (Drupal root) for easy access in IDE
- ✅ Use `/tmp` for temporary exports
- ⚠️  Be mindful of exported data (may contain user emails, content)

### Development Tool Context

**Important:**
- Drupal Scout is a **development tool**, not a production service
- Assumes a trusted local environment
- No authentication/authorization layer (by design)
- Should not be exposed to untrusted networks
- Uses MCP protocol (STDIO) - typically local use only

**Recommendations:**
- ✅ Use for local development and staging environments
- ✅ Use with your own Drupal installations
- ❌ Do not expose to public networks
- ❌ Do not use with untrusted Drupal installations

### What Drupal Scout Does NOT Do

**Read-Only by Design:**
- Does not modify database content
- Does not change files in your codebase
- Does not execute user-provided PHP/SQL directly
- Does not install/uninstall modules (AI does this via separate commands)

**Secure Subprocess Usage:**
- All drush commands use safe subprocess.run() (no shell=True)
- Commands passed as lists, not strings
- Timeouts on all subprocess calls
- No user input passed directly to shell

## Requirements

- Python 3.10 or higher
- Drupal 9, 10, or 11 installation
- MCP-compatible client (Claude Desktop, Cursor, etc.)
- Internet connection (for drupal.org features)

## Configuration

### Quick Start (Recommended for MCP)

**For DDEV users:**
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "ddev drush"
}
```

**For Lando users:**
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "lando drush"
}
```

**For Docksal users:**
```json
{
  "drupal_root": "/path/to/your/drupal",
  "drush_command": "fin drush"
}
```

> **💡 TIP:** When using Scout via MCP (Cursor, Claude Desktop), explicitly setting `drush_command` is **highly recommended** to avoid auto-detection issues. MCP runs in a different environment than your terminal and may not find development tools in PATH.

### Basic Configuration (Minimal)
```json
{
  "drupal_root": "/var/www/drupal",
  "modules_path": "modules"
}
```

Scout will attempt to auto-detect drush, but this may fail in MCP environments.

### Advanced Options
```json
{
  "drupal_root": "/var/www/drupal",
  "modules_path": "modules",
  "exclude_patterns": ["node_modules", "vendor"],
  "drush_command": "ddev drush"
}
```

### Drush Configuration (Important!)

**11 out of 47 tools require drush** to access the Drupal database:
- `get_taxonomy_info()` - Taxonomy usage analysis
- `get_entity_structure()` - Entity/bundle information
- `get_field_info()` - Field configurations
- `get_views_summary()` - Views details
- `get_watchdog_logs()` - Error/warning logs
- `export_taxonomy_usage_to_csv()` - CSV exports
- `export_nodes_to_csv()` - CSV exports
- `export_users_to_csv()` - CSV exports
- And more...

**Auto-detection (may fail in MCP):**

Scout attempts to auto-detect drush in this order:
1. User config (`drush_command` in config.json) ← **Use this for MCP!**
2. DDEV: `ddev drush` (if `.ddev/config.yaml` exists and `ddev` in PATH)
3. Lando: `lando drush` (if `.lando.yml` exists and `lando` in PATH)
4. Docksal: `fin drush` (if `.docksal/` exists and `fin` in PATH)
5. Composer: `vendor/bin/drush` (if file exists)
6. Global: `drush` (if in PATH)

**Manual override (recommended for MCP):**

```json
{
  "drush_command": "ddev drush"
}
```

**Common examples:**
- DDEV: `"drush_command": "ddev drush"`
- Lando: `"drush_command": "lando drush"`
- Docksal: `"drush_command": "fin drush"`
- Custom Docker: `"drush_command": "docker-compose exec php drush"`
- SSH remote: `"drush_command": "ssh user@host drush"`
- Absolute path: `"drush_command": "/path/to/vendor/bin/drush"`

### Troubleshooting Database Connectivity

If database-dependent tools aren't working, run:
```
check_scout_health()
```

This will show exactly what's wrong and how to fix it.

**Common issues:**
- ❌ `[Errno 2] No such file or directory: 'ddev'`
  → Add `"drush_command": "ddev drush"` to config.json

- ❌ `Drush found but database not connected`
  → Ensure dev environment is running: `ddev start`

- ⚠️ `Drush not found in any expected location`
  → Add explicit `drush_command` to config.json

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for comprehensive solutions.

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
