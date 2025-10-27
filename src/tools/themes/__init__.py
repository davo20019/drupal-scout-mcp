"""
Theme tools for Drupal Scout MCP.

This package provides theme analysis tools:
- info.py: Theme metadata, region layout, and active theme information
- blocks.py: Block placement analysis per region
- templates.py: Template file discovery and override analysis

All tools are registered with MCP and auto-discovered by the server.
"""

# Import all tools for MCP auto-discovery
from .info import describe_theme, get_active_themes, get_theme_regions
from .blocks import get_theme_blocks
from .templates import (
    find_theme_templates,
    get_theme_template_overrides,
    get_template_suggestions,
    get_view_template_info,
)

# Export for MCP auto-discovery
__all__ = [
    "describe_theme",
    "get_active_themes",
    "get_theme_regions",
    "get_theme_blocks",
    "find_theme_templates",
    "get_theme_template_overrides",
    "get_template_suggestions",
    "get_view_template_info",
]
