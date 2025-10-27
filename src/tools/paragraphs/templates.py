"""
Paragraph template discovery tools for Drupal Scout MCP.

Provides template and preprocess hook discovery for paragraphs.
"""

import logging
from pathlib import Path
from typing import Optional

# Import from core modules
from src.core.config import load_config

# Import MCP instance from server
from server import mcp

# Get logger
logger = logging.getLogger(__name__)


@mcp.tool()
def find_paragraph_templates(bundle: Optional[str] = None) -> str:
    """
    Find paragraph template files and preprocess hooks.

    Searches active theme for paragraph templates and .theme file for hooks.
    Perfect for finding customizations and understanding theming.

    Args:
        bundle: Optional paragraph bundle to filter (e.g., "hero_banner")
               If not provided, shows all paragraph templates

    Returns:
        List of templates and hooks found

    Examples:
        find_paragraph_templates()
        find_paragraph_templates("hero_banner")
    """
    try:
        config = load_config()
        drupal_root = Path(config.get("drupal_root", ""))

        if not drupal_root.exists():
            return "❌ ERROR: Could not determine Drupal root"

        # Find active theme
        theme_path = _find_active_theme_path(drupal_root)
        if not theme_path:
            return "❌ ERROR: Could not find active theme"

        # Find templates
        templates = []
        if bundle:
            pattern = f"paragraph--{bundle}*.html.twig"
        else:
            pattern = "paragraph--*.html.twig"

        template_files = list(theme_path.rglob(pattern))
        templates.extend([t.name for t in template_files])

        # Find preprocess hooks in .theme file
        hooks = []
        theme_file = theme_path / f"{theme_path.name}.theme"
        if theme_file.exists():
            content = theme_file.read_text()
            if bundle:
                hook_patterns = [
                    "function.*_preprocess_paragraph__" + bundle,
                    r"function.*_preprocess_paragraph\(&\$variables\)",
                ]
            else:
                hook_patterns = [
                    r"function.*_preprocess_paragraph__",
                    r"function.*_preprocess_paragraph\(&\$variables\)",
                ]

            import re

            for pattern in hook_patterns:
                matches = re.findall(pattern, content)
                hooks.extend(matches)

        # Build output
        output = []
        if bundle:
            output.append(f"📄 PARAGRAPH TEMPLATES: {bundle}")
        else:
            output.append("📄 PARAGRAPH TEMPLATES (All)")
        output.append("=" * 80)
        output.append("")

        if templates:
            output.append(f"TEMPLATES ({len(templates)}):")
            for tpl in sorted(templates):
                output.append(f"  ✓ {tpl}")
            output.append("")

        if hooks:
            output.append(f"PREPROCESS HOOKS ({len(hooks)}):")
            for hook in hooks:
                output.append(f"  ✓ {hook}")
            output.append("")

        if not templates and not hooks:
            if bundle:
                output.append(f"No custom templates or hooks found for '{bundle}'")
            else:
                output.append("No paragraph templates or hooks found")
            output.append("")
            output.append("💡 Template naming:")
            if bundle:
                output.append(f"  - paragraph--{bundle}.html.twig")
                output.append(f"  - paragraph--{bundle}--default.html.twig")
            else:
                output.append("  - paragraph--[bundle].html.twig")
                output.append("  - paragraph--[bundle]--[view-mode].html.twig")

        return "\n".join(output)

    except Exception as e:
        logger.exception("Error finding paragraph templates")
        return f"❌ ERROR: {str(e)}"


def _find_active_theme_path(drupal_root: Path) -> Optional[Path]:
    """Find active theme path (simplified - checks common locations)."""
    # Try common theme locations
    possible_paths = [
        drupal_root / "themes" / "custom",
        drupal_root / "web" / "themes" / "custom",
        drupal_root / "themes" / "contrib",
    ]

    for path in possible_paths:
        if path.exists():
            # Return first theme found (simplified)
            themes = [d for d in path.iterdir() if d.is_dir()]
            if themes:
                return themes[0]

    return None
