# Changelog

All notable changes to Drupal Scout MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2025-01-26

### Changed
- **Refactored export tools for better maintainability**
  - Split large `exports.py` (1,952 lines) into focused modules:
    - `exports_common.py` - Shared utilities (path validation, config loading)
    - `exports_taxonomy.py` - Taxonomy term CSV export (~550 lines)
    - `exports_nodes.py` - Node/content CSV export (~600 lines)
    - `exports_users.py` - User account CSV export (~500 lines)
  - Each module now has single responsibility and clear purpose
  - Improved code organization and navigation
  - No breaking changes - pure refactoring

### Fixed
- Added missing `limit` parameter to `export_taxonomy_usage_to_csv` for API consistency
- Fixed "unexpected keyword argument 'limit'" error in taxonomy export tool

### Added
- Drupal.org API integration for module discovery
- Four new MCP tools: `search_drupal_org`, `get_popular_drupal_modules`, `get_module_recommendation`, `get_drupal_org_module_details`
- Automatic fallback to drupal.org when local modules not found
- AI-powered recommendations combining local + drupal.org data
- Multi-strategy search: machine name, title, and keyword-based
- **Enhanced module details from drupal.org API:**
  - ✅ **Accurate Drupal version compatibility** - Scraped from project page ("Works with Drupal: ^9.5 || ^10 || ^11")
  - Security coverage badges (🛡️ for security-covered modules)
  - Star count showing community trust (⭐)
  - Total installation count across all versions
  - Breakdown by Drupal version (top 3 most-used versions)
  - Project timeline (created and last updated dates)
  - Supporting organizations count
  - Direct links to issue queue
  - Direct links to documentation
  - Issue queue availability indicator
  - 🆕 **Optional issue queue analysis** - `include_issues` parameter fetches recent issues for qualitative insights:
    - Migration patterns (e.g., "Migration from simpleSAMLphp Authentication")
    - Common technical problems (Symfony, dependencies, error handling)
    - Maintainer responsiveness and activity
    - Setup complexity discussions
    - Community health indicators
  - 🆕 **Issue search tool** - `search_module_issues` finds solutions to your specific problems:
    - Keyword-based search across issue queue
    - Relevance scoring for best matches
    - Automatic Drupal version filtering (shows only compatible issues)
    - Direct links to solutions, patches, and workarounds
    - Saves hours of manual issue queue browsing
- Installation script for easy setup
- Comprehensive test suite
- CI/CD with GitHub Actions

### Fixed
- **Critical:** Fixed drupal.org API parsing error that caused modules to be skipped silently
  - The `body` field can be a dict or a list; now handles both formats correctly
  - The `taxonomy_vocabulary_44` field can be a dict or a list; now handles both formats
  - Error was: `'list' object has no attribute 'get'` when parsing modules without descriptions
  - All drupal.org searches now work correctly (tested with simplesamlphp_sp, saml, webform, etc.)

### Improved
- Enhanced `describe_module` error messages to guide users to correct tool
- Module usage calculation now sums all version installations for accurate totals
- Better formatted output with clear sections and trust indicators
- Added disclaimer for "8.x" modules that may support Drupal 9/10/11 (API limitation)

## [0.1.0] - 2025-01-20

### Added
- Initial release
- Local module indexing for Drupal 9/10 sites
- Parse .info.yml, .services.yml, .routing.yml, and PHP files
- Six core MCP tools:
  - `search_functionality` - Search for functionality across modules
  - `list_modules` - List all modules with details
  - `describe_module` - Get detailed module information
  - `find_unused_contrib` - Find unused contrib modules
  - `check_redundancy` - Check if functionality exists before building
  - `reindex_modules` - Force re-indexing
- Support for custom and contrib modules
- Service dependency analysis
- Keyword-based search across all module components
- Structured result formatting
- Configuration via JSON file
- Works with Claude Desktop, Claude Code, and Cursor

### Documentation
- Comprehensive README with examples
- QUICKSTART guide for 5-minute setup
- DEMO script for presentations
- ARCHITECTURE documentation
- Sample queries collection
- Setup guides for Claude Desktop, Claude Code, and Cursor

[Unreleased]: https://github.com/davo20019/drupal-scout-mcp/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/davo20019/drupal-scout-mcp/compare/v0.1.0...v1.4.0
[0.1.0]: https://github.com/davo20019/drupal-scout-mcp/releases/tag/v0.1.0
