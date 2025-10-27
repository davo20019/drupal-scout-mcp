"""
Menu analysis tools for Drupal Scout MCP.

This package provides menu discovery and link analysis tools.
"""

# Import all tools for MCP auto-discovery
from .links import get_menu_link_info, list_menu_links

# Export for MCP auto-discovery
__all__ = [
    "get_menu_link_info",
    "list_menu_links",
]
