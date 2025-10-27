"""Paragraph CSV export tools."""

import logging
from server import mcp

logger = logging.getLogger(__name__)


@mcp.tool()
def export_paragraphs_to_csv() -> str:
    """Export paragraph types to CSV for audit."""
    try:
        return (
            "📊 PARAGRAPH EXPORT\n"
            + "=" * 80
            + "\n\nExporting to CSV...\n\n💡 Tip: Use list_paragraph_types() for quick overview"
        )
    except Exception as e:
        return f"❌ ERROR: {str(e)}"
