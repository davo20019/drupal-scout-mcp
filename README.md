# Drupal Scout MCP

A Model Context Protocol **data provider** for Drupal module discovery and troubleshooting. This MCP server gives AI assistants (Claude, Cursor, etc.) deep knowledge of your Drupal codebase and drupal.org's module ecosystem.

**What it does:** Provides data about modules, not execution
**What it doesn't do:** Execute drush/composer commands (your AI handles that)

## Features

**Local Module Analysis**
- Index and search your Drupal installation
- Find functionality across custom and contrib modules
- Detect unused modules and redundant functionality
- Analyze service dependencies and routing
- **Enhanced dependency analysis** (reverse deps, circular detection, uninstall safety)

**Drupal.org Integration**
- Search 50,000+ modules on drupal.org
- Get detailed module information with compatibility data
- Search issue queues for solutions to specific problems
- Automatic Drupal version filtering for relevant results

**Intelligent Recommendations**
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

### Cleanup Workflow
```
User: "Clean up unused modules"
MCP: find_unused_contrib()
Result: MCP identifies devel, kint, admin_toolbar_tools as unused (based on indexed data)

User: "Remove them"
AI: Uses Bash to uninstall and remove from composer
AI: Calls reindex_modules() to update MCP's index
Result: Modules removed, MCP index updated
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
Result: "⚠️ CANNOT SAFELY UNINSTALL
         - 27 modules depend on token
         - Including: pathauto, metatag, my_custom_module
         - Must remove dependents first"

User: "What are my most critical modules?"
MCP: analyze_module_dependencies()  # System-wide analysis
Result: Shows modules with most dependents, circular dependencies,
        custom module coupling, and safe-to-remove candidates
```

## How It Works

### Division of Labor

**MCP Server (Data Provider) - What Drupal Scout Does:**
- 📊 Indexes your local Drupal codebase
- 🔍 Provides fast searching across modules
- 🌐 Fetches data from drupal.org (modules, issues, stats)
- 💾 Caches drupal.org responses (1 hour TTL)
- 🧠 Analyzes dependencies and redundancies
- 📈 Recommends modules based on your needs

**AI Assistant (Action Executor) - What Your AI Does:**
- 🔧 Executes drush/composer/git commands
- 🐳 Detects your environment (DDEV, Lando, Docker, etc.)
- ⚡ Runs commands appropriate for your setup
- 🔄 Chains operations efficiently
- 🛠️ Handles errors and edge cases
- 📝 Calls reindex_modules() after changes

### Technical Details

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
- ✅ MCP focuses on Drupal domain knowledge
- ✅ AI handles environment-specific execution
- ✅ Simpler, more maintainable code
- ✅ Works with any dev environment (DDEV, Lando, etc.)
- ✅ AI can adapt to errors better than hardcoded commands

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
  "cache_ttl": 3600
}
```

## Performance

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
