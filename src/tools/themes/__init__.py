"""
Theme tools for Drupal Scout MCP.

This package provides theme analysis and visualization tools:
- visualization.py: Visual region layout with HTML output
- info.py: Theme metadata and active theme information
- blocks.py: Block placement analysis per region

All tools are registered with MCP and auto-discovered by the server.
"""

# Import all tools for MCP auto-discovery
from .visualization import visualize_theme_regions
from .info import describe_theme, get_active_themes
from .blocks import get_theme_blocks

# Export for MCP auto-discovery
__all__ = [
    "visualize_theme_regions",
    "describe_theme",
    "get_active_themes",
    "get_theme_blocks",
]
