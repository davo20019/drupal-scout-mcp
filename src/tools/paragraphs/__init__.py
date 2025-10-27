"""
Paragraphs analysis tools for Drupal Scout MCP.

This package provides paragraph type discovery, analysis, and audit tools:
- info.py: Paragraph type listing and detailed information
- templates.py: Template and preprocess hook discovery
- usage.py: Usage tracking and reference analysis
- analysis.py: Duplicate detection and field comparison
- exports.py: CSV export for audits and planning

All tools are registered with MCP and auto-discovered by the server.
"""

# Import all tools for MCP auto-discovery
from .info import list_paragraph_types, describe_paragraph_type
from .templates import find_paragraph_templates
from .usage import get_paragraph_usage, check_paragraph_existence, get_paragraph_references
from .analysis import find_duplicate_paragraphs
from .exports import export_paragraphs_to_csv

# Export for MCP auto-discovery
__all__ = [
    "list_paragraph_types",
    "describe_paragraph_type",
    "find_paragraph_templates",
    "get_paragraph_usage",
    "check_paragraph_existence",
    "get_paragraph_references",
    "find_duplicate_paragraphs",
    "export_paragraphs_to_csv",
]
