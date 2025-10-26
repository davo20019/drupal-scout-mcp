"""
Module code analysis tools for Drupal Scout MCP server.

Provides tools for reading and analyzing Drupal module code:
- read_module_file: Read files from modules with smart chunking
- list_module_files: List files in a module with size information
- get_module_directory_tree: Show module directory structure
- read_module_function: Extract specific PHP functions from files

These tools enable deep code analysis for learning, reviewing, and contributing.
"""

import logging
import re
from pathlib import Path
from typing import Optional, List, Dict, Any

# Import from core modules
from src.core.config import ensure_indexed, get_config
from src.core.drush import run_drush_command

# Import MCP instance from server
from server import mcp

logger = logging.getLogger(__name__)

# Token limits for MCP responses
MAX_RESPONSE_TOKENS = 20000  # ~20K tokens max per response
CHARS_PER_TOKEN = 4  # Approximate conversion
MAX_RESPONSE_CHARS = MAX_RESPONSE_TOKENS * CHARS_PER_TOKEN  # ~80KB

# File size thresholds
SMALL_FILE_THRESHOLD = 50000  # 50KB
MEDIUM_FILE_THRESHOLD = 200000  # 200KB

# Module-level cache for module paths
_module_path_cache: Dict[str, Path] = {}
_cache_initialized = False


def _is_php_file(file_path: str) -> bool:
    """Check if file is a PHP file (including Drupal extensions)."""
    php_extensions = {".php", ".module", ".install", ".theme", ".inc", ".profile"}
    return any(file_path.endswith(ext) for ext in php_extensions)


def _build_module_path_cache() -> Dict[str, Path]:
    """
    Build module/theme path cache using Drupal's registry (drush) + filesystem fallback.

    This follows Drupal best practices by using the official Extension List API
    via drush, which knows about symlinks, custom structures, Platform.sh, etc.

    Three-tier approach:
    1. Drush pm:list - Most reliable (90% of cases)
    2. Drush theme:list - For themes
    3. Filesystem scan - Fallback for custom modules if drush fails

    Returns:
        Dictionary mapping module/theme names to their paths
    """
    cache = {}

    # Method 1: Use Drush to get module paths (most reliable)
    # This uses Drupal's own Extension List API - the official way
    try:
        logger.info("Building module index via drush...")

        # Get modules
        modules = run_drush_command(["pm:list", "--format=json", "--fields=name,path"], timeout=30)

        if modules:
            for name, info in modules.items():
                if "path" in info and info["path"]:
                    # Path from drush is relative to Drupal webroot (where index.php lives)
                    config = get_config()
                    drupal_root = Path(config.get("drupal_root"))

                    # Handle both relative and absolute paths
                    module_path = Path(info["path"])
                    if not module_path.is_absolute():
                        # Try direct path first
                        candidate = drupal_root / module_path

                        # If not found, try with web/ prefix (composer structure)
                        if not candidate.exists():
                            candidate = drupal_root / "web" / module_path

                        module_path = candidate

                    if module_path.exists():
                        cache[name] = module_path

            logger.info(f"Found {len(cache)} modules via drush")

        # Get themes (theme:list may not exist in older drush versions)
        try:
            themes = run_drush_command(
                ["theme:list", "--format=json", "--fields=name,path"], timeout=30
            )

            if themes:
                for name, info in themes.items():
                    if "path" in info and info["path"] and name not in cache:
                        config = get_config()
                        drupal_root = Path(config.get("drupal_root"))

                        theme_path = Path(info["path"])
                        if not theme_path.is_absolute():
                            # Try direct path first
                            candidate = drupal_root / theme_path

                            # If not found, try with web/ prefix (composer structure)
                            if not candidate.exists():
                                candidate = drupal_root / "web" / theme_path

                            theme_path = candidate

                        if theme_path.exists():
                            cache[name] = theme_path

                logger.info(f"Total modules+themes via drush: {len(cache)}")
        except Exception:
            # theme:list not available in this drush version
            # Themes will be found via filesystem scan if needed
            logger.info(f"theme:list not available, skipping theme discovery via drush")

    except Exception as e:
        logger.warning(f"Drush failed, using filesystem fallback: {e}")

    # Method 2: Filesystem fallback (for custom modules or if drush fails)
    # Only scan custom locations - drush already got core/contrib
    try:
        config = get_config()
        drupal_root = Path(config.get("drupal_root"))

        # Check for web/ subdirectory (Composer projects)
        if (drupal_root / "web").exists():
            scan_root = drupal_root / "web"
        else:
            scan_root = drupal_root

        # Only scan custom directories (drush already got core/contrib)
        custom_locations = [
            scan_root / "modules" / "custom",
            scan_root / "themes" / "custom",
        ]

        for location in custom_locations:
            if location.exists() and location.is_dir():
                for item in location.iterdir():
                    if item.is_dir() and item.name not in cache:
                        # Verify it's actually a module/theme (has .info.yml)
                        info_files = list(item.glob("*.info.yml"))
                        if info_files:
                            cache[item.name] = item
                            logger.debug(f"Found custom module via filesystem: {item.name}")

        logger.info(f"Total after filesystem scan: {len(cache)}")

    except Exception as e:
        logger.error(f"Filesystem scan failed: {e}")

    return cache


def _get_module_path_cache() -> Dict[str, Path]:
    """
    Get module path cache, building it if necessary.

    Auto-builds on first use, cached for subsequent calls.

    Returns:
        Dictionary mapping module names to paths
    """
    global _module_path_cache, _cache_initialized

    if _cache_initialized:
        return _module_path_cache

    _module_path_cache = _build_module_path_cache()
    _cache_initialized = True

    return _module_path_cache


def _find_module_path(module_name: str, explicit_path: Optional[str] = None) -> Optional[Path]:
    """
    Find path to a module using Drupal's registry (drush) with filesystem fallback.

    This uses Drupal's official Extension List API via drush - the same way Drupal
    itself finds modules. Works with symlinks, custom structures, Platform.sh, etc.

    Three-tier approach:
    1. User-provided explicit path (if specified)
    2. Drush-based cache (most reliable, auto-built)
    3. Not found (returns None)

    Args:
        module_name: Machine name of module/theme
        explicit_path: Optional user-provided path override (relative to drupal_root)
                      Example: "web/modules/custom/my_module"

    Returns:
        Path to module directory or None if not found
    """
    ensure_indexed()
    config = get_config()
    drupal_root = Path(config.get("drupal_root"))

    # Option 1: User explicitly provided path
    if explicit_path:
        full_path = drupal_root / explicit_path
        if full_path.exists() and full_path.is_dir():
            logger.info(f"Using explicit path for {module_name}: {explicit_path}")
            return full_path
        else:
            logger.warning(f"Explicit path does not exist or is not a directory: {explicit_path}")
            # Don't return None yet - try cache as fallback

    # Option 2: Use cached index (drush + filesystem)
    cache = _get_module_path_cache()

    if module_name in cache:
        return cache[module_name]

    # Not found
    logger.warning(f"Module '{module_name}' not found in index")
    return None


def _format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}MB"


def _count_lines(file_path: Path) -> int:
    """Count lines in a file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _extract_php_functions(content: str) -> List[Dict[str, Any]]:
    """
    Extract PHP function definitions from content.

    Returns list of dicts with function name, start line, signature.
    """
    functions = []
    lines = content.split("\n")

    # Pattern to match function definitions
    # Matches: function name(...) { or public function name(...) {
    pattern = re.compile(
        r"^\s*(public|private|protected|static)?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\("
    )

    for i, line in enumerate(lines, 1):
        match = pattern.search(line)
        if match:
            visibility = match.group(1) or "public"
            func_name = match.group(2)
            functions.append(
                {"name": func_name, "line": i, "signature": line.strip(), "visibility": visibility}
            )

    return functions


@mcp.tool()
def read_module_file(
    module_name: str,
    file_path: str,
    module_path: Optional[str] = None,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    mode: str = "auto",
) -> str:
    """
    Read files from a Drupal module with smart chunking for large files.

    This tool enables deep code analysis for modules, themes, and core.
    Automatically handles large files to stay within token limits.

    Uses Drupal's official registry (drush) to find modules - works with symlinks,
    custom structures, Platform.sh, Acquia, Pantheon, and all Drupal setups.

    Modes:
    - auto: Smart decision based on file size (recommended)
    - full: Return entire file (may fail for large files)
    - summary: Return file structure and metadata only
    - functions: List PHP functions (for .php files)

    For large files (>50KB), use offset/limit parameters for manual chunking.

    Args:
        module_name: Module/theme machine name (e.g., "views", "node", "olivero")
        file_path: Relative path to file within module (e.g., "views.module", "src/Controller/NodeController.php")
        module_path: Optional explicit module path override (relative to drupal_root)
                    Example: "web/modules/custom/my_module"
                    If not provided, Scout auto-detects using drush
        offset: Line number to start reading from (0-indexed)
        limit: Number of lines to read
        mode: Reading mode - "auto", "full", "summary", "functions"

    Returns:
        File content or summary with metadata and chunking information

    Examples:
        read_module_file("node", "node.module")  # Auto mode for small files
        read_module_file("views", "views.module", mode="summary")  # Large file summary
        read_module_file("views", "views.module", offset=0, limit=500)  # First 500 lines
        read_module_file("node", "src/Entity/Node.php", mode="functions")  # List functions
        read_module_file("my_module", "my_module.module", module_path="web/modules/custom/my_module")  # Explicit path
    """
    ensure_indexed()

    # Find module path
    module_dir = _find_module_path(module_name, explicit_path=module_path)
    if not module_dir:
        return (
            f"❌ ERROR: Module '{module_name}' not found\n\n"
            "Scout uses Drupal's registry (drush) to find modules.\n\n"
            "Try:\n"
            "  • Use get_all_module_paths() to see available modules\n"
            "  • Use list_modules() to see all installed modules\n"
            "  • Provide explicit path: module_path='web/modules/custom/my_module'\n"
            "  • Run refresh_module_index() if you just installed a module"
        )

    # Build full file path
    full_file_path = module_dir / file_path

    if not full_file_path.exists():
        return (
            f"❌ ERROR: File not found\n\n"
            f"Module: {module_name}\n"
            f"Path: {file_path}\n"
            f"Full path: {full_file_path}\n\n"
            f"Use list_module_files('{module_name}') to see available files."
        )

    if not full_file_path.is_file():
        return f"❌ ERROR: Path is a directory, not a file: {file_path}\n\nUse list_module_files('{module_name}') to browse directory contents."

    # Get file info
    file_size = full_file_path.stat().st_size
    total_lines = _count_lines(full_file_path)

    output = []
    output.append(f"📄 FILE: {module_name}/{file_path}\n")
    output.append("=" * 80)
    output.append("")

    # Determine mode based on file size if auto
    if mode == "auto":
        if file_size < SMALL_FILE_THRESHOLD:
            mode = "full"
        elif file_size < MEDIUM_FILE_THRESHOLD:
            mode = "summary"
        else:
            mode = "summary"

    # MODE: Summary
    if mode == "summary":
        output.append("📊 FILE SUMMARY")
        output.append("")
        output.append(f"Size: {_format_file_size(file_size)}")
        output.append(f"Lines: {total_lines:,}")
        output.append(f"Location: {full_file_path}")
        output.append("")

        # For PHP files, extract function list
        if _is_php_file(file_path):
            try:
                with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    functions = _extract_php_functions(content)

                if functions:
                    output.append(f"Functions: {len(functions)}")
                    output.append("")
                    output.append("Function List:")
                    for func in functions[:20]:  # First 20 functions
                        output.append(
                            f"  • {func['name']}() - line {func['line']} ({func['visibility']})"
                        )
                    if len(functions) > 20:
                        output.append(f"  ... and {len(functions) - 20} more functions")
                    output.append("")
            except Exception as e:
                logger.error(f"Error parsing PHP file: {e}")

        # Provide chunking recommendations
        if file_size > SMALL_FILE_THRESHOLD:
            output.append("⚠️  FILE IS LARGE")
            output.append("")
            if _is_php_file(file_path):
                output.append(
                    f"Use read_module_function('{module_name}', '{file_path}', 'function_name')"
                )
                output.append("to read specific functions.")
            output.append("")
            output.append("Or use chunking:")
            chunk_size = 500
            output.append(
                f"  read_module_file('{module_name}', '{file_path}', offset=0, limit={chunk_size})"
            )
            output.append(
                f"  read_module_file('{module_name}', '{file_path}', offset={chunk_size}, limit={chunk_size})"
            )
            output.append("  ...")

        return "\n".join(output)

    # MODE: Functions (PHP only)
    if mode == "functions":
        if not _is_php_file(file_path):
            return f"❌ ERROR: 'functions' mode only works with PHP files\n\nFile: {file_path}\n\nSupported extensions: .php, .module, .install, .theme, .inc, .profile"

        try:
            with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                functions = _extract_php_functions(content)

            if not functions:
                return f"No functions found in {file_path}"

            output.append(f"📋 FUNCTIONS IN {file_path}")
            output.append("")
            output.append(f"Total: {len(functions)} functions")
            output.append("")

            for func in functions:
                output.append(f"Line {func['line']}: {func['signature']}")

            output.append("")
            output.append("To read a specific function:")
            output.append(
                f"  read_module_function('{module_name}', '{file_path}', 'function_name')"
            )

            return "\n".join(output)

        except Exception as e:
            return f"❌ ERROR: Could not parse PHP file\n\n{str(e)}"

    # MODE: Full or chunked reading
    try:
        with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Determine slice
        if offset is not None or limit is not None:
            start = offset or 0
            end = start + (limit or len(lines))
            selected_lines = lines[start:end]
            is_chunked = True
        else:
            selected_lines = lines
            is_chunked = False

        content = "".join(selected_lines)

        # Check if response will be too large
        if len(content) > MAX_RESPONSE_CHARS:
            return (
                f"⚠️  ERROR: Content too large for single response\n\n"
                f"File size: {_format_file_size(len(content))}\n"
                f"Max size: {_format_file_size(MAX_RESPONSE_CHARS)}\n\n"
                f"Use chunking:\n"
                f"  offset: Starting line (default 0)\n"
                f"  limit: Number of lines to read (recommend 500)\n\n"
                f"Example:\n"
                f"  read_module_file('{module_name}', '{file_path}', offset=0, limit=500)"
            )

        # Output metadata
        output.append(f"Size: {_format_file_size(file_size)}")
        output.append(f"Lines: {len(selected_lines):,} of {total_lines:,}")

        if is_chunked:
            output.append(f"Range: {offset or 0} to {(offset or 0) + len(selected_lines)}")
            has_more = (offset or 0) + len(selected_lines) < total_lines
            if has_more:
                next_offset = (offset or 0) + len(selected_lines)
                output.append(f"More content available: offset={next_offset}")

        output.append("")
        output.append("─" * 80)
        output.append("")

        # Add line numbers
        start_line = (offset or 0) + 1
        numbered_lines = []
        for i, line in enumerate(selected_lines, start=start_line):
            numbered_lines.append(f"{i:5d} │ {line.rstrip()}")

        output.append("\n".join(numbered_lines))

        return "\n".join(output)

    except UnicodeDecodeError:
        return f"❌ ERROR: File contains binary data or unsupported encoding\n\nFile: {file_path}"
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return f"❌ ERROR: Could not read file\n\n{str(e)}"


@mcp.tool()
def list_module_files(
    module_name: str,
    pattern: Optional[str] = None,
    module_path: Optional[str] = None,
    show_sizes: bool = True,
    offset: int = 0,
    limit: int = 100,
) -> str:
    """
    List files in a Drupal module with size information.

    Helps identify which files to read and provides chunking recommendations.

    Args:
        module_name: Module/theme machine name (e.g., "views", "node", "olivero")
        pattern: Optional glob pattern to filter files (e.g., "*.php", "src/**/*.php", "templates/*.twig")
        module_path: Optional explicit module path override (relative to drupal_root)
        show_sizes: Include file sizes and chunking recommendations (default: True)
        offset: Starting file index for pagination (default: 0)
        limit: Maximum number of files to return (default: 100)

    Returns:
        Formatted list of files with paths, sizes, and reading recommendations

    Examples:
        list_module_files("node")  # First 100 files
        list_module_files("webform", offset=100, limit=100)  # Next 100 files
        list_module_files("views", "*.module")  # Just .module files
        list_module_files("views", "src/**/*.php")  # All PHP in src/
        list_module_files("olivero", "templates/*.twig")  # Twig templates
    """
    ensure_indexed()

    # Find module path
    module_dir = _find_module_path(module_name, explicit_path=module_path)
    if not module_dir:
        return (
            f"❌ ERROR: Module '{module_name}' not found\n\n"
            "Use list_modules() to see available modules."
        )

    output = []
    output.append(f"📁 FILES IN: {module_name}\n")
    output.append("=" * 80)
    output.append("")

    # Get files
    if pattern:
        files = list(module_dir.glob(pattern))
    else:
        files = list(module_dir.rglob("*"))

    # Filter out directories
    files = [f for f in files if f.is_file()]

    if not files:
        return f"No files found in {module_name}" + (f" matching '{pattern}'" if pattern else "")

    # Sort by path
    files.sort()

    total_files = len(files)

    # Group by type for better organization
    file_types = {}
    for file in files:
        ext = file.suffix or "(no extension)"
        if ext not in file_types:
            file_types[ext] = []
        file_types[ext].append(file)

    output.append(f"Total files: {total_files}")
    output.append(f"File types: {len(file_types)}")

    # Apply pagination
    paginated_files = files[offset : offset + limit]
    showing_count = len(paginated_files)

    if offset > 0 or showing_count < total_files:
        output.append(f"Showing: {offset + 1}-{offset + showing_count} of {total_files}")
        output.append("")
        if offset + showing_count < total_files:
            next_offset = offset + limit
            output.append(
                f"💡 More files available. Use: list_module_files('{module_name}', offset={next_offset}, limit={limit})"
            )

    output.append("")

    # Show by type (full counts)
    for ext in sorted(file_types.keys()):
        type_files = file_types[ext]
        output.append(f"{ext}: {len(type_files)} files")

    output.append("")
    output.append("─" * 80)
    output.append("")

    # List files with details (paginated)
    for file in paginated_files:
        rel_path = file.relative_to(module_dir)
        size = file.stat().st_size

        if show_sizes:
            size_str = _format_file_size(size)
            output.append(f"{rel_path}")
            output.append(f"  Size: {size_str}")

            # Add reading recommendation
            if size < SMALL_FILE_THRESHOLD:
                output.append(f"  ✅ Small - use: read_module_file('{module_name}', '{rel_path}')")
            elif size < MEDIUM_FILE_THRESHOLD:
                output.append(
                    f"  ⚠️  Medium - use summary: read_module_file('{module_name}', '{rel_path}', mode='summary')"
                )
            else:
                output.append(
                    f"  ❌ Large - use chunking: read_module_file('{module_name}', '{rel_path}', offset=0, limit=500)"
                )

            output.append("")
        else:
            output.append(f"  {rel_path}")

    # Summary recommendations (only for displayed files)
    large_files = [f for f in paginated_files if f.stat().st_size > MEDIUM_FILE_THRESHOLD]
    if large_files:
        output.append("")
        output.append("⚠️  LARGE FILES IN THIS PAGE:")
        output.append("")
        for file in large_files[:5]:  # First 5
            rel_path = file.relative_to(module_dir)
            output.append(
                f"  • {rel_path} ({_format_file_size(file.stat().st_size)}) - requires chunking"
            )

    # Pagination reminder
    if offset + showing_count < total_files:
        output.append("")
        output.append("─" * 80)
        output.append("")
        remaining = total_files - (offset + showing_count)
        output.append(f"📄 {remaining} more files available")
        next_offset = offset + limit
        output.append(
            f"   Use: list_module_files('{module_name}', offset={next_offset}, limit={limit})"
        )

    return "\n".join(output)


@mcp.tool()
def get_module_directory_tree(
    module_name: str, module_path: Optional[str] = None, max_depth: int = 3, max_items: int = 300
) -> str:
    """
    Show module directory structure as a tree.

    Helps understand module organization and architecture.

    Args:
        module_name: Module/theme machine name
        module_path: Optional explicit module path override
        max_depth: Maximum depth to show (default: 3)
        max_items: Maximum number of items to display (default: 300, prevents token overflow)

    Returns:
        Directory tree visualization

    Examples:
        get_module_directory_tree("node")
        get_module_directory_tree("views", max_depth=2)
        get_module_directory_tree("webform", max_items=200)
    """
    ensure_indexed()

    # Find module path
    module_dir = _find_module_path(module_name, explicit_path=module_path)
    if not module_dir:
        return (
            f"❌ ERROR: Module '{module_name}' not found\n\n"
            "Use list_modules() to see available modules."
        )

    output = []
    output.append(f"📁 DIRECTORY TREE: {module_name}\n")
    output.append("=" * 80)
    output.append("")
    output.append(f"{module_name}/")

    items_shown = [0]  # Use list to allow mutation in nested function
    truncated = [False]

    def _build_tree(path: Path, prefix: str = "", depth: int = 0):
        """Recursively build directory tree."""
        if depth >= max_depth or items_shown[0] >= max_items:
            if items_shown[0] >= max_items and not truncated[0]:
                truncated[0] = True
                output.append(f"{prefix}... (truncated - max {max_items} items)")
            return

        try:
            entries = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        except PermissionError:
            return

        # Filter out common ignores
        ignore_patterns = {".git", "node_modules", "vendor", ".idea", "__pycache__"}
        entries = [e for e in entries if e.name not in ignore_patterns]

        for i, entry in enumerate(entries):
            if items_shown[0] >= max_items:
                if not truncated[0]:
                    truncated[0] = True
                    output.append(f"{prefix}... (truncated - max {max_items} items)")
                return

            is_last = i == len(entries) - 1
            current_prefix = "└── " if is_last else "├── "
            next_prefix = "    " if is_last else "│   "

            if entry.is_dir():
                output.append(f"{prefix}{current_prefix}{entry.name}/")
                items_shown[0] += 1
                _build_tree(entry, prefix + next_prefix, depth + 1)
            else:
                # Add file with size
                size = entry.stat().st_size
                size_str = _format_file_size(size)
                output.append(f"{prefix}{current_prefix}{entry.name} ({size_str})")
                items_shown[0] += 1

    _build_tree(module_dir)

    output.append("")
    if truncated[0]:
        output.append(f"⚠️  Output truncated at {max_items} items to prevent token overflow")
        output.append("")
        output.append(f"To see more structure:")
        output.append(f"  • Reduce depth: get_module_directory_tree('{module_name}', max_depth=2)")
        output.append(
            f"  • Increase limit: get_module_directory_tree('{module_name}', max_items=500)"
        )
        output.append(
            f"  • Use list_module_files('{module_name}', pattern='src/**/*.php') for targeted browsing"
        )
    elif max_depth < 5:
        output.append(f"Showing depth: {max_depth}, items: {items_shown[0]}")
        output.append(
            f"Use get_module_directory_tree('{module_name}', max_depth=5) for deeper view"
        )

    return "\n".join(output)


@mcp.tool()
def read_module_function(
    module_name: str, file_path: str, function_name: str, module_path: Optional[str] = None
) -> str:
    """
    Read a specific PHP function from a module file.

    Extracts just the requested function with its docblock and context.
    Perfect for large files where you only need one function.

    Args:
        module_name: Module machine name
        file_path: Relative path to PHP file
        function_name: Name of function to extract

    Returns:
        Function code with docblock and metadata

    Examples:
        read_module_function("node", "node.module", "node_save")
        read_module_function("views", "views.module", "views_init")
        read_module_function("user", "src/UserStorage.php", "loadByProperties")
    """
    ensure_indexed()

    # Find module path
    module_dir = _find_module_path(module_name, explicit_path=module_path)
    if not module_dir:
        return f"❌ ERROR: Module '{module_name}' not found"

    # Build full file path
    full_file_path = module_dir / file_path

    if not full_file_path.exists():
        return f"❌ ERROR: File not found: {file_path}"

    if not _is_php_file(file_path):
        return f"❌ ERROR: Only works with PHP files, got: {file_path}\n\nSupported extensions: .php, .module, .install, .theme, .inc, .profile"

    try:
        with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Find function
        pattern = re.compile(
            rf"^\s*(public|private|protected|static)?\s*function\s+{re.escape(function_name)}\s*\("
        )

        func_start = None
        for i, line in enumerate(lines):
            if pattern.search(line):
                func_start = i
                break

        if func_start is None:
            # Try to list available functions
            content = "".join(lines)
            functions = _extract_php_functions(content)
            func_names = [f["name"] for f in functions]

            return (
                f"❌ ERROR: Function '{function_name}' not found in {file_path}\n\n"
                f"Available functions ({len(func_names)}):\n"
                + "\n".join(f"  • {name}" for name in func_names[:20])
                + (f"\n  ... and {len(func_names) - 20} more" if len(func_names) > 20 else "")
            )

        # Find function end (closing brace)
        brace_count = 0
        func_end = func_start
        started = False

        for i in range(func_start, len(lines)):
            line = lines[i]
            if "{" in line:
                started = True
                brace_count += line.count("{")
            if "}" in line:
                brace_count -= line.count("}")

            if started and brace_count == 0:
                func_end = i
                break

        # Look for docblock before function
        docblock_start = func_start
        for i in range(func_start - 1, max(0, func_start - 30), -1):
            line = lines[i].strip()
            if line.startswith("/**"):
                docblock_start = i
                break
            elif line and not line.startswith("*") and not line.startswith("*/"):
                break

        # Extract function with docblock
        func_lines = lines[docblock_start : func_end + 1]
        func_code = "".join(func_lines)

        output = []
        output.append(f"🔍 FUNCTION: {function_name}()")
        output.append("")
        output.append(f"File: {module_name}/{file_path}")
        output.append(f"Lines: {docblock_start + 1} - {func_end + 1}")
        output.append(f"Length: {len(func_lines)} lines")
        output.append("")
        output.append("─" * 80)
        output.append("")

        # Add line numbers
        for i, line in enumerate(func_lines, start=docblock_start + 1):
            output.append(f"{i:5d} │ {line.rstrip()}")

        return "\n".join(output)

    except Exception as e:
        logger.error(f"Error reading function: {e}")
        return f"❌ ERROR: Could not extract function\n\n{str(e)}"


@mcp.tool()
def get_all_module_paths() -> str:
    """
    List all discovered modules and themes with their filesystem paths.

    This tool helps you understand the site structure and verify that
    Scout can find all modules. Useful for:
    - Understanding site layout
    - Debugging path finding issues
    - Finding the correct module_path value to pass to other tools

    Uses drush pm:list and theme:list to discover modules, with
    filesystem scan fallback for custom modules.

    Returns:
        Formatted list of all modules with their paths, grouped by type

    Example output:
        DRUPAL MODULES & THEMES

        Core Modules (186):
          node → /app/web/core/modules/node
          user → /app/web/core/modules/user
          ...

        Contrib Modules (24):
          views → /app/web/modules/contrib/views
          pathauto → /app/web/modules/contrib/pathauto
          ...

        Custom Modules (3):
          my_module → /app/web/modules/custom/my_module
          ...

        Themes (5):
          olivero → /app/web/core/themes/olivero
          ...
    """
    # Ensure cache is built
    cache = _get_module_path_cache()

    if not cache:
        return (
            "❌ ERROR: No modules found\n\n"
            "Possible causes:\n"
            "1. Drupal root not configured correctly in config.json\n"
            "2. Drush not available or not working\n"
            "3. No modules installed\n\n"
            "Run check_scout_health() to diagnose issues."
        )

    output = []
    output.append("📦 DRUPAL MODULES & THEMES")
    output.append("")
    output.append("=" * 80)
    output.append("")

    # Group by type (core, contrib, custom, themes)
    core_modules = {}
    contrib_modules = {}
    custom_modules = {}
    core_themes = {}
    contrib_themes = {}
    custom_themes = {}

    for name, path in cache.items():
        path_str = str(path)

        # Classify by path
        if "/core/modules/" in path_str:
            core_modules[name] = path
        elif "/core/themes/" in path_str:
            core_themes[name] = path
        elif "/modules/contrib/" in path_str or "/contrib/" in path_str:
            contrib_modules[name] = path
        elif "/modules/custom/" in path_str or "/custom/" in path_str:
            custom_modules[name] = path
        elif "/themes/" in path_str:
            # Themes outside core
            if "/contrib/" in path_str:
                contrib_themes[name] = path
            elif "/custom/" in path_str:
                custom_themes[name] = path
            else:
                contrib_themes[name] = path  # Default to contrib
        else:
            # Unclassified - put in custom
            custom_modules[name] = path

    # Display each category
    categories = [
        ("Core Modules", core_modules),
        ("Contrib Modules", contrib_modules),
        ("Custom Modules", custom_modules),
        ("Core Themes", core_themes),
        ("Contrib Themes", contrib_themes),
        ("Custom Themes", custom_themes),
    ]

    total_count = 0
    for category_name, items in categories:
        if not items:
            continue

        total_count += len(items)
        output.append(f"## {category_name} ({len(items)})")
        output.append("")

        # Sort alphabetically
        for name in sorted(items.keys()):
            path = items[name]
            output.append(f"  {name:30s} → {path}")

        output.append("")

    # Summary
    output.append("─" * 80)
    output.append("")
    output.append(f"Total: {total_count} modules and themes discovered")
    output.append("")
    output.append("💡 TIP: Use the module_path parameter in code analysis tools if a module")
    output.append("   is not auto-discovered or you want to analyze a specific path:")
    output.append(
        "   read_module_file('my_module', 'my_module.module', module_path='/custom/path')"
    )

    return "\n".join(output)


@mcp.tool()
def refresh_module_index() -> str:
    """
    Force refresh of the module path cache.

    Call this tool when:
    - You've enabled/disabled modules via drush or UI
    - You've installed new contrib modules via composer
    - You've created new custom modules
    - Module paths seem out of date or incorrect

    This will rebuild the cache using drush pm:list and theme:list,
    ensuring all code analysis tools have up-to-date module locations.

    Returns:
        Summary of reindexed modules

    Example:
        # After installing a new module:
        refresh_module_index()
        # Now code analysis tools will find the new module
    """
    global _module_path_cache, _cache_initialized

    # Clear existing cache
    _module_path_cache = {}
    _cache_initialized = False

    # Rebuild cache
    cache = _get_module_path_cache()

    if not cache:
        return (
            "⚠️  WARNING: Module cache refresh completed but no modules found\n\n"
            "Possible causes:\n"
            "1. Drupal root not configured in config.json\n"
            "2. Drush not available\n"
            "3. No modules installed\n\n"
            "Run check_scout_health() to diagnose."
        )

    # Count by type
    core_count = sum(
        1 for p in cache.values() if "/core/modules/" in str(p) or "/core/themes/" in str(p)
    )
    contrib_count = sum(1 for p in cache.values() if "/contrib/" in str(p))
    custom_count = sum(1 for p in cache.values() if "/custom/" in str(p))
    other_count = len(cache) - core_count - contrib_count - custom_count

    output = []
    output.append("✅ Module index refreshed successfully")
    output.append("")
    output.append(f"Total: {len(cache)} modules and themes")
    output.append(f"  • Core: {core_count}")
    output.append(f"  • Contrib: {contrib_count}")
    output.append(f"  • Custom: {custom_count}")
    if other_count > 0:
        output.append(f"  • Other: {other_count}")
    output.append("")
    output.append("All code analysis tools now have updated module paths.")
    output.append("")
    output.append("Use get_all_module_paths() to see the full list.")

    return "\n".join(output)
