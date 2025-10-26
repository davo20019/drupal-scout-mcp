"""Configuration and state management for Drupal Scout."""

import json
import logging
from pathlib import Path
from typing import Optional

from src.indexer import ModuleIndexer
from src.search import ModuleSearch
from src.prioritizer import ResultPrioritizer
from src.drupal_org import DrupalOrgAPI

logger = logging.getLogger(__name__)

# Module-level state
_config: dict = {}
_indexer: Optional[ModuleIndexer] = None
_searcher: Optional[ModuleSearch] = None
_prioritizer = ResultPrioritizer()
_drupal_org_api = DrupalOrgAPI()


def get_config() -> dict:
    """Get config, loading if needed."""
    global _config
    if not _config:
        _config = load_config()
    return _config


def get_indexer() -> Optional[ModuleIndexer]:
    """Get indexer, initializing if needed."""
    ensure_indexed()
    return _indexer


def get_searcher() -> Optional[ModuleSearch]:
    """Get searcher, initializing if needed."""
    ensure_indexed()
    return _searcher


def get_prioritizer() -> ResultPrioritizer:
    """Get prioritizer instance."""
    return _prioritizer


def get_drupal_org_api() -> DrupalOrgAPI:
    """Get Drupal.org API instance."""
    return _drupal_org_api


def load_config() -> dict:
    """Load configuration from config.json or environment."""
    config_path = Path.home() / ".config" / "drupal-scout" / "config.json"

    if config_path.exists():
        with open(config_path, "r") as f:
            return json.load(f)

    # Try local config
    local_config = Path("config.json")
    if local_config.exists():
        with open(local_config, "r") as f:
            return json.load(f)

    # No default - user must configure
    raise ValueError(
        "Configuration not found. Please create config.json with:\n"
        "{\n"
        '  "drupal_root": "/path/to/your/drupal",\n'
        '  "modules_path": "modules"\n'
        "}"
    )


def reset_index():
    """Reset the module index to force re-indexing."""
    global _indexer, _searcher
    _indexer = None
    _searcher = None


def ensure_indexed():
    """Ensure modules are indexed before operations."""
    global _indexer, _searcher, _config

    if _indexer is None:
        _config = load_config()
        drupal_root = Path(_config["drupal_root"])

        if not drupal_root.exists():
            raise ValueError(
                f"Drupal root not found: {drupal_root}\n"
                f"Please configure drupal_root in config.json"
            )

        logger.info(f"Indexing modules from: {drupal_root}")
        _indexer = ModuleIndexer(drupal_root, _config)
        _indexer.index_all()

        _searcher = ModuleSearch(_indexer)
        logger.info(f"Indexed {_indexer.modules.get('total', 0)} modules")
