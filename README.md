# Drupal Scout MCP

A Model Context Protocol server for Drupal module discovery and troubleshooting. Search local modules, find drupal.org solutions, and get intelligent recommendations - all from your IDE.

## Features

**Local Module Analysis**
- Index and search your Drupal installation
- Find functionality across custom and contrib modules
- Detect unused modules and redundant functionality
- Analyze service dependencies and routing

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

### Quick Install

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

## How It Works

**Local Indexing**
- Parses .info.yml, .services.yml, .routing.yml, and PHP files
- Indexes services, routes, dependencies, and keywords
- Builds searchable database of functionality
- Updates automatically when modules change

**Drupal.org Integration**
- Uses drupal.org REST API for module data
- Scrapes project pages for accurate compatibility
- Fetches issue queues for troubleshooting
- Caches results for performance (1 hour TTL)

**Version Filtering**
- Detects your Drupal version automatically
- Filters issue results for compatibility
- Understands D7 vs D8/9/10/11 differences
- Shows only relevant results

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
