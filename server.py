#!/usr/bin/env python3
"""
Drupal Scout MCP Server

A Model Context Protocol server for discovering functionality in Drupal sites.
"""

import logging
import sys

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("Drupal Scout")

# CRITICAL FIX: When running as __main__, tool modules import from 'server'
# We need to ensure 'server' module points to __main__ to share the mcp instance
if __name__ == "__main__":
    sys.modules["server"] = sys.modules["__main__"]

# Import tool modules to register @mcp.tool() decorated functions
# IMPORTANT: Must import AFTER mcp instance is created (above)
import src.tools.exports  # noqa: E402, F401
import src.tools.drupal_org  # noqa: E402, F401
import src.tools.system  # noqa: E402, F401
import src.tools.entities  # noqa: E402, F401
import src.tools.taxonomy  # noqa: E402, F401
import src.tools.views  # noqa: E402, F401
import src.tools.modules  # noqa: E402, F401

# Note: All tool implementations moved to src/tools/ modules
# This keeps server.py focused on MCP server setup and initialization


def main():
    """Main entry point for the MCP server."""
    # Note: Pre-indexing and drush testing moved to lazy initialization
    # to avoid delaying MCP server startup which can cause connection issues
    logger.info("🚀 Starting Drupal Scout MCP Server...")
    logger.info(f"   📦 {len(mcp._tool_manager._tools)} tools registered")
    logger.info("   (Modules will be indexed on first request)")

    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()
